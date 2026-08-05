"""Outbound webhooks, signed so a consumer can trust them.

**The timestamp is inside the signed payload, not beside it.** A signature over
the body alone is replayable: an attacker who captures one delivery can resend it
indefinitely and the signature still verifies. Signing `timestamp.body` and
rejecting old timestamps closes that, and it is the difference between a
signature that proves authenticity and one that proves only that the message was
authentic *once*.

**The raw body is signed, not the parsed object.** JSON round-tripping reorders
keys and changes whitespace, so a consumer who re-serialises before verifying
gets a different string and a failed check. Sign the bytes that go on the wire.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import time
from dataclasses import dataclass
from typing import Any

import httpx

from app.utils.logger import get_logger

logger = get_logger(__name__)

SIGNATURE_HEADER = "X-BOM-Signature"
TIMESTAMP_HEADER = "X-BOM-Timestamp"
SIGNATURE_VERSION = "v1"

#: How old a delivery may be and still verify. Five minutes is enough for a slow
#: consumer and short enough that a captured delivery is not a lasting key.
MAX_SKEW_SECONDS = 300

#: Attempt delays. Bounded: a consumer that is down for an hour is down, and
#: retrying forever turns their outage into our queue backlog.
BACKOFF_SECONDS = (1, 5, 30)


class SignatureInvalid(ValueError):
    """The delivery did not verify."""


@dataclass(frozen=True, slots=True)
class Delivery:
    url: str
    attempt: int
    status_code: int | None
    signature: str
    error: str | None = None

    @property
    def succeeded(self) -> bool:
        return self.status_code is not None and 200 <= self.status_code < 300


def sign(body: bytes, secret: str, *, timestamp: int | None = None) -> tuple[str, str]:
    """Return (signature, timestamp). The timestamp is part of what is signed."""
    stamp = str(timestamp if timestamp is not None else int(time.time()))
    material = f"{stamp}.".encode() + body
    digest = hmac.new(secret.encode(), material, hashlib.sha256).hexdigest()
    return f"{SIGNATURE_VERSION}={digest}", stamp


def verify(
    body: bytes,
    signature: str,
    timestamp: str,
    secret: str,
    *,
    max_skew: int = MAX_SKEW_SECONDS,
    now: int | None = None,
) -> None:
    """Raise unless the delivery is authentic and recent.

    Written to be handed to consumers verbatim — the reference implementation
    they check against is the one we use.
    """
    try:
        stamp = int(timestamp)
    except (TypeError, ValueError):
        raise SignatureInvalid("timestamp is not an integer") from None

    current = now if now is not None else int(time.time())
    if abs(current - stamp) > max_skew:
        raise SignatureInvalid(
            f"delivery is {abs(current - stamp)}s old, beyond the {max_skew}s window; "
            "a signature without a freshness check is replayable"
        )

    expected, _ = sign(body, secret, timestamp=stamp)
    # Constant-time: a timing side channel here leaks the signature byte by byte.
    if not hmac.compare_digest(expected, signature):
        raise SignatureInvalid("signature does not match the body")


async def deliver(
    url: str,
    payload: dict[str, Any],
    secret: str,
    *,
    client: httpx.AsyncClient | None = None,
    max_attempts: int = 3,
) -> list[Delivery]:
    """POST a signed payload, retrying with backoff. One row per attempt."""
    # Serialised once: the bytes signed must be the bytes sent.
    body = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
    signature, timestamp = sign(body, secret)
    headers = {
        "Content-Type": "application/json",
        SIGNATURE_HEADER: signature,
        TIMESTAMP_HEADER: timestamp,
    }

    owned = client is None
    session = client or httpx.AsyncClient(timeout=15.0)
    deliveries: list[Delivery] = []

    try:
        for attempt in range(1, max_attempts + 1):
            try:
                response = await session.post(url, content=body, headers=headers)
                delivery = Delivery(
                    url=url,
                    attempt=attempt,
                    status_code=response.status_code,
                    signature=signature,
                )
            except (httpx.TimeoutException, httpx.TransportError) as error:
                delivery = Delivery(
                    url=url,
                    attempt=attempt,
                    status_code=None,
                    signature=signature,
                    error=f"{type(error).__name__}: {error}",
                )

            deliveries.append(delivery)
            if delivery.succeeded:
                logger.info("webhook_delivered", attempt=attempt, status=delivery.status_code)
                return deliveries

            if attempt < max_attempts:
                import asyncio

                await asyncio.sleep(BACKOFF_SECONDS[min(attempt - 1, len(BACKOFF_SECONDS) - 1)])

        logger.warning("webhook_failed", attempts=len(deliveries))
        return deliveries
    finally:
        if owned:
            await session.aclose()


def reference_implementation() -> str:
    """Verification code to hand a consumer.

    Published rather than described: a consumer who has to infer the scheme from
    prose will get the timestamp handling wrong, and a wrongly-implemented
    verifier that accepts everything is worse than none.
    """
    return '''
import hashlib, hmac, time

def verify(body: bytes, signature: str, timestamp: str, secret: str) -> bool:
    if abs(int(time.time()) - int(timestamp)) > 300:
        return False                      # replay window
    material = f"{timestamp}.".encode() + body
    expected = "v1=" + hmac.new(secret.encode(), material, hashlib.sha256).hexdigest()
    return hmac.compare_digest(expected, signature)
'''.strip()
