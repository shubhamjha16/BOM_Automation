"""NVD CVE lookup.

Queried by CPE where a component has one and by keyword otherwise, because the
NVD's own matching is CPE-based and a keyword search is a guess. The distinction
is recorded: a keyword-matched CVE is lower confidence than a CPE match and the
assessment says which it was.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

import httpx

from app.configs.envConfig import settings
from app.services.kb.base import FeedResponse, fetch_json
from app.utils.logger import get_logger

logger = get_logger(__name__)

FEED = "nvd"
BASE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"


def _headers() -> dict[str, str]:
    # An API key raises the rate limit from 5 to 50 requests per 30 seconds.
    # Without one the sync is slow but correct, so the key is optional.
    return {"apiKey": settings.NVD_API_KEY} if settings.NVD_API_KEY else {}


def parse_cve(item: dict[str, Any]) -> dict[str, Any]:
    """One NVD record → the row shape `cves` stores."""
    cve = item.get("cve", item)
    descriptions = cve.get("descriptions") or []
    english = next(
        (entry.get("value") for entry in descriptions if entry.get("lang") == "en"),
        None,
    )

    metrics = (cve.get("metrics") or {}).get("cvssMetricV31") or []
    primary = next(
        (metric for metric in metrics if metric.get("type") == "Primary"),
        metrics[0] if metrics else None,
    )
    cvss = (primary or {}).get("cvssData") or {}

    weaknesses = []
    for weakness in cve.get("weaknesses") or []:
        for description in weakness.get("description") or []:
            value = description.get("value")
            if value and value.startswith("CWE-"):
                weaknesses.append(value)

    return {
        "cve_id": cve.get("id"),
        "published": cve.get("published"),
        "modified": cve.get("lastModified"),
        "description": english,
        "cvss_v31_vector": cvss.get("vectorString"),
        "cvss_v31_score": cvss.get("baseScore"),
        "cwe_ids": sorted(set(weaknesses)) or None,
        "synced_at": datetime.now(UTC).isoformat(),
    }


async def by_cve_id(
    cve_id: str, *, client: httpx.AsyncClient | None = None
) -> dict[str, Any] | None:
    response: FeedResponse = await fetch_json(
        feed=FEED, url=BASE_URL, params={"cveId": cve_id}, headers=_headers(), client=client
    )
    items = (response.payload or {}).get("vulnerabilities") or []
    return parse_cve(items[0]) if items else None


async def by_cpe(
    cpe: str, *, limit: int = 20, client: httpx.AsyncClient | None = None
) -> list[dict[str, Any]]:
    """CPE match — the NVD's own matching, and the higher-confidence path."""
    response = await fetch_json(
        feed=FEED,
        url=BASE_URL,
        params={"cpeName": cpe, "resultsPerPage": limit},
        headers=_headers(),
        client=client,
    )
    items = (response.payload or {}).get("vulnerabilities") or []
    return [parse_cve(item) for item in items[:limit]]


async def by_keyword(
    keyword: str, *, limit: int = 20, client: httpx.AsyncClient | None = None
) -> list[dict[str, Any]]:
    """Keyword search — a guess, and recorded as the lower-confidence path."""
    response = await fetch_json(
        feed=FEED,
        url=BASE_URL,
        params={"keywordSearch": keyword, "resultsPerPage": limit},
        headers=_headers(),
        client=client,
    )
    items = (response.payload or {}).get("vulnerabilities") or []
    return [parse_cve(item) for item in items[:limit]]
