"""CISA Known Exploited Vulnerabilities.

One JSON document, refreshed daily, small enough to fetch whole — so unlike NVD
there is no per-component lookup and no rate limit to respect. KEV membership is
a stronger claim than "a CVE exists": it means exploitation has been observed,
which is why a KEV-listed CVE with no VEX statement is a critical finding under
rec. 7.1.6 rather than an advisory one.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

import httpx

from app.services.kb.base import fetch_json
from app.utils.logger import get_logger

logger = get_logger(__name__)

FEED = "cisa-kev"
CATALOG_URL = (
    "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
)


def parse_entry(item: dict[str, Any]) -> dict[str, Any]:
    return {
        "cve_id": item.get("cveID"),
        "vendor_project": item.get("vendorProject"),
        "product": item.get("product"),
        "added_on": item.get("dateAdded"),
        "due_date": item.get("dueDate"),
        "known_ransomware": item.get("knownRansomwareCampaignUse"),
        "synced_at": datetime.now(UTC).isoformat(),
    }


#: Process-level cache. The catalogue is ~1,600 entries refreshed once a day, so
#: fetching it per assessment is pure waste — twenty concurrent submissions would
#: download it twenty times and hold a database transaction open across every one
#: of those downloads. `sync_kb` (workers/tasks.py) refreshes it on a schedule;
#: this cache is what keeps the assessment path off the network in between.
_CACHE: dict[str, Any] = {"entries": None, "fetched_at": None}
CACHE_TTL_SECONDS = 3600


def cached_catalog() -> list[dict[str, Any]] | None:
    """The cached catalogue, or None when absent or stale."""
    fetched_at = _CACHE.get("fetched_at")
    if _CACHE.get("entries") is None or fetched_at is None:
        return None
    age = (datetime.now(UTC) - fetched_at).total_seconds()
    return _CACHE["entries"] if age < CACHE_TTL_SECONDS else None


def prime_cache(entries: list[dict[str, Any]]) -> None:
    """Populate the cache. Called by `sync_kb`, and by tests."""
    _CACHE["entries"] = entries
    _CACHE["fetched_at"] = datetime.now(UTC)


def clear_cache() -> None:
    _CACHE["entries"] = None
    _CACHE["fetched_at"] = None


async def fetch_catalog(*, client: httpx.AsyncClient | None = None) -> list[dict[str, Any]]:
    """The whole catalogue. ~1,600 entries; fetched entire and diffed locally."""
    if (cached := cached_catalog()) is not None:
        return cached

    response = await fetch_json(feed=FEED, url=CATALOG_URL, client=client, timeout=60.0)
    payload = response.payload or {}
    entries = [parse_entry(item) for item in payload.get("vulnerabilities") or []]
    prime_cache(entries)
    logger.info("kev_fetched", count=len(entries), released=payload.get("catalogVersion"))
    return entries


def index_by_cve(entries: list[dict[str, Any]]) -> dict[str, dict[str, Any]]:
    return {entry["cve_id"]: entry for entry in entries if entry.get("cve_id")}
