"""Shared HTTP behaviour for the knowledge-base feeds.

Every feed here is somebody else's service, and all four have the same failure
modes: rate limits, transient 5xx, and occasional silence. Two rules follow.

**A feed that is down is a reported gap, not a crashed assessment.** The lanes
already fail independently; enrichment must too. A component whose CVE lookup
failed reports the field absent with the reason, which is honest — we do not know
— and is very different from reporting no vulnerabilities, which is a claim.

**Never retry into a rate limit.** NVD without an API key allows 5 requests per
30 seconds; hammering it earns a longer block and degrades the feed for everyone
using it, including the next assessment.
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass
from typing import Any

import httpx

from app.utils.logger import get_logger

logger = get_logger(__name__)

DEFAULT_TIMEOUT = 20.0
#: Retried once, with a pause. Anything else is reported rather than retried.
RETRYABLE_STATUS = frozenset({429, 500, 502, 503, 504})


class FeedUnavailable(RuntimeError):
    """The feed could not be reached or answered. Reported, never swallowed."""

    def __init__(self, feed: str, detail: str) -> None:
        self.feed = feed
        super().__init__(f"{feed} unavailable: {detail}")


@dataclass(frozen=True, slots=True)
class FeedResponse:
    payload: Any
    #: Recorded on every enriched value, so an assessment can say where a fact
    #: came from and a reviewer can see it was not supplier-declared.
    source: str
    url: str


async def fetch_json(
    *,
    feed: str,
    url: str,
    params: dict[str, Any] | None = None,
    headers: dict[str, str] | None = None,
    # ruff ASYNC109 suggests asyncio.timeout for a `timeout` parameter. That rule
    # targets hand-rolled timeout handling; here the value is handed to httpx,
    # which applies it per-phase (connect, read, write, pool). Wrapping the call
    # in asyncio.timeout instead would give a single coarse deadline and lose the
    # distinction between a slow feed and an unreachable one.
    timeout: float = DEFAULT_TIMEOUT,  # noqa: ASYNC109
    client: httpx.AsyncClient | None = None,
) -> FeedResponse:
    """GET JSON, with one bounded retry."""
    owned = client is None
    session = client or httpx.AsyncClient(timeout=timeout, follow_redirects=True)

    try:
        for attempt in (1, 2):
            try:
                response = await session.get(url, params=params, headers=headers)
            except (httpx.TimeoutException, httpx.TransportError) as error:
                if attempt == 2:
                    raise FeedUnavailable(feed, f"{type(error).__name__}: {error}") from None
                await asyncio.sleep(2.0)
                continue

            if response.status_code in RETRYABLE_STATUS and attempt == 1:
                # One pause, then one more try. Not a loop: retrying into a rate
                # limit earns a longer block.
                logger.warning("feed_retry", feed=feed, status=response.status_code)
                await asyncio.sleep(3.0 if response.status_code == 429 else 1.5)
                continue

            if response.status_code >= 400:
                raise FeedUnavailable(feed, f"HTTP {response.status_code}")

            try:
                return FeedResponse(payload=response.json(), source=feed, url=str(response.url))
            except ValueError as error:
                raise FeedUnavailable(feed, f"response was not JSON: {error}") from None

        raise FeedUnavailable(feed, "exhausted retries")  # pragma: no cover
    finally:
        if owned:
            await session.aclose()
