"""Reject an oversized body at the edge, before it is read into memory.

A 300 MB BOM that is parsed and *then* rejected has already cost 300 MB of RSS
and however long the transfer took. Worse, the same request from twenty
suppliers at once takes the process down — so this is an availability control,
not a tidiness one.

Two layers, because either alone has a hole:

* **Content-Length**, checked before the body is touched at all. Handles every
  well-behaved client, and costs nothing.
* **A streaming byte count**, because `Content-Length` is a claim by the client.
  A chunked upload omits it entirely, and a hostile one can simply lie. The
  stream is aborted the moment the running total crosses the cap.
"""

from __future__ import annotations

from starlette.datastructures import Headers
from starlette.types import ASGIApp, Message, Receive, Scope, Send

from app.utils.logger import get_logger

logger = get_logger(__name__)


class BodyTooLarge(Exception):
    """The request body exceeded the configured cap."""


def _too_large_response(limit: int) -> dict:
    return {
        "detail": (
            f"request body exceeds the {limit} byte limit (MAX_BOM_MB). "
            "Split the submission or raise the cap."
        )
    }


class BodySizeLimitMiddleware:
    """Pure ASGI middleware — deliberately not `BaseHTTPMiddleware`.

    `BaseHTTPMiddleware` materialises the request body to hand it to the next
    app, which is exactly the cost this class exists to avoid.
    """

    def __init__(self, app: ASGIApp, *, max_bytes: int) -> None:
        self.app = app
        self.max_bytes = max_bytes

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http" or scope["method"] in ("GET", "HEAD", "DELETE", "OPTIONS"):
            await self.app(scope, receive, send)
            return

        headers = Headers(scope=scope)
        declared = headers.get("content-length")
        if declared is not None and declared.isdigit() and int(declared) > self.max_bytes:
            logger.warning(
                "body_rejected_at_edge",
                reason="content-length",
                declared=int(declared),
                limit=self.max_bytes,
                path=scope.get("path"),
            )
            await self._reject(send)
            return

        received = 0
        exceeded = False

        async def counting_receive() -> Message:
            nonlocal received, exceeded
            message = await receive()
            if message["type"] == "http.request":
                received += len(message.get("body", b""))
                if received > self.max_bytes:
                    # The client under-declared or omitted Content-Length. Stop
                    # reading rather than finishing the transfer and then refusing.
                    exceeded = True
                    logger.warning(
                        "body_rejected_at_edge",
                        reason="stream-exceeded-cap",
                        received=received,
                        limit=self.max_bytes,
                        path=scope.get("path"),
                    )
                    raise BodyTooLarge(received)
            return message

        try:
            await self.app(scope, counting_receive, send)
        except BodyTooLarge:
            if not exceeded:  # pragma: no cover - defensive
                raise
            await self._reject(send)

    async def _reject(self, send: Send) -> None:
        import json

        body = json.dumps(_too_large_response(self.max_bytes)).encode()
        await send(
            {
                "type": "http.response.start",
                "status": 413,
                "headers": [
                    (b"content-type", b"application/json"),
                    (b"content-length", str(len(body)).encode()),
                ],
            }
        )
        await send({"type": "http.response.body", "body": body})
