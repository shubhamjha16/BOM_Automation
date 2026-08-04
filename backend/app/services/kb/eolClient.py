"""Lifecycle data for 4.2(11) End-of-Life and 4.2(10) Release Date.

endoflife.date keys on a product slug, not a package name, and the two rarely
match — `pkg:pypi/django` is `django`, but `pkg:maven/org.springframework/spring-core`
is `spring-framework`. That gap is precisely where the S10 agent earns its place:
the deterministic feed answers the products it knows, and only the unmatched
remainder is worth a retrieval loop.

The client itself never guesses a slug. A wrong slug returns a real, confident,
wrong EOL date, which is worse than no answer.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

import httpx

from app.services.kb.base import FeedUnavailable, fetch_json
from app.utils.logger import get_logger

logger = get_logger(__name__)

FEED = "endoflife.date"
BASE_URL = "https://endoflife.date/api"

#: Package name → endoflife.date slug, where they differ and the mapping is
#: unambiguous. Curated, deliberately small, and extended only by a human — the
#: same discipline as the supplier registry (S11). A guessed entry here produces
#: a confident wrong date on every future assessment.
SLUG_OVERRIDES: dict[str, str] = {
    "spring-core": "spring-framework",
    "spring-boot-starter": "spring-boot",
    "tomcat-catalina": "tomcat",
    "tomcat-embed-core": "tomcat",
    "openssl": "openssl",
    "log4j-core": "log4j",
    "jackson-databind": "jackson",
    "postgresql": "postgresql",
    "mysql-connector-java": "mysql",
}


def slug_for(name: str) -> str | None:
    """The endoflife.date slug for a package, or None.

    Returns None rather than a guess. An unmatched product becomes an agent
    batch (S10), not a fabricated lookup.
    """
    if not name:
        return None
    normalised = name.strip().lower()
    if normalised in SLUG_OVERRIDES:
        return SLUG_OVERRIDES[normalised]
    # Only the trivially safe transformation: a slug is lowercase and hyphenated.
    if normalised.replace("-", "").replace(".", "").isalnum():
        return normalised
    return None


def parse_cycle(product_key: str, item: dict[str, Any]) -> dict[str, Any]:
    def _date(value: Any) -> Any:
        # endoflife.date uses `true`/`false` for "still supported"/"unsupported"
        # as well as dates. A boolean is not a date and must not become one.
        return value if isinstance(value, str) else None

    return {
        "product_key": product_key,
        "cycle": str(item.get("cycle")),
        "eol_date": _date(item.get("eol")),
        "support_end": _date(item.get("support")),
        "latest_version": item.get("latest"),
        "release_date": _date(item.get("releaseDate")),
        "source": FEED,
        "synced_at": datetime.now(UTC).isoformat(),
    }


async def cycles_for(
    product_key: str, *, client: httpx.AsyncClient | None = None
) -> list[dict[str, Any]]:
    """Every release cycle for a product, or an empty list when unknown.

    A 404 means endoflife.date does not track this product — a real answer, not
    a failure, and the trigger for an agent batch.
    """
    try:
        response = await fetch_json(
            feed=FEED, url=f"{BASE_URL}/{product_key}.json", client=client
        )
    except FeedUnavailable as error:
        if "404" in str(error):
            logger.info("eol_unknown_product", product=product_key)
            return []
        raise

    payload = response.payload
    if not isinstance(payload, list):
        return []
    return [parse_cycle(product_key, item) for item in payload if isinstance(item, dict)]


def match_cycle(cycles: list[dict[str, Any]], version: str | None) -> dict[str, Any] | None:
    """The cycle a version belongs to.

    Longest-prefix match, because cycles are major or major.minor ("3", "3.11")
    and a version is full ("3.11.7"). Longest wins so "3.11" beats "3".
    """
    if not version or not cycles:
        return None
    candidates = [
        cycle
        for cycle in cycles
        if cycle.get("cycle") and str(version).startswith(str(cycle["cycle"]))
    ]
    if not candidates:
        return None
    return max(candidates, key=lambda cycle: len(str(cycle["cycle"])))
