"""CERT-In vulnerability notes and advisories, per rec. 7.1.7.

CERT-In publishes advisories as HTML pages with no documented JSON API and no
stable machine-readable feed. That is a real constraint, not an oversight, and it
shapes what this client can honestly claim:

* **A configured feed URL is fetched and parsed.** Deployments that have an
  agreed feed — a mirror, an internal cache, or a future published API — get
  deterministic enrichment.
* **With no feed configured this returns nothing and says so.** It does not
  scrape the public site: a layout change would silently turn advisories into an
  empty list, and an empty advisory list reads as "no advisories apply", which is
  a claim we would not be entitled to make.

The absence is reported as a gap in the assessment rather than hidden.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

import httpx

from app.services.kb.base import fetch_json
from app.utils.logger import get_logger

logger = get_logger(__name__)

FEED = "certin"


def parse_advisory(item: dict[str, Any]) -> dict[str, Any]:
    return {
        "source": FEED,
        "ref": str(item.get("ref") or item.get("id") or ""),
        "title": item.get("title"),
        "url": item.get("url"),
        "published": item.get("published") or item.get("date"),
        "cve_ids": item.get("cve_ids") or item.get("cves"),
        "synced_at": datetime.now(UTC).isoformat(),
    }


async def fetch_advisories(
    *, feed_url: str | None = None, client: httpx.AsyncClient | None = None
) -> list[dict[str, Any]]:
    """Advisories from a configured feed.

    Returns an empty list when no feed is configured — and the caller records
    that as an unavailable source, not as "no advisories".
    """
    if not feed_url:
        logger.info(
            "certin_feed_unconfigured",
            detail=(
                "no CERT-In advisory feed configured; advisory enrichment is "
                "reported as unavailable rather than empty"
            ),
        )
        return []

    response = await fetch_json(feed=FEED, url=feed_url, client=client, timeout=45.0)
    payload = response.payload
    items = payload if isinstance(payload, list) else (payload or {}).get("advisories") or []
    advisories = [parse_advisory(item) for item in items if isinstance(item, dict)]
    logger.info("certin_fetched", count=len(advisories))
    return [advisory for advisory in advisories if advisory["ref"]]


def is_configured(feed_url: str | None) -> bool:
    return bool(feed_url)
