"""Turn feed data into the four ENRICH fields, recording where each came from.

**Provenance is the point.** 4.2(8)–4.2(11) are minimum elements the supplier was
required to declare. When we fill one from NVD or endoflife.date, the assessment
must say so — otherwise a reader sees a populated Vulnerabilities field and
concludes the supplier declared it, when in fact we went and looked. That
misreads the supplier's conformance in their favour, which is the same class of
error as scoring a `not_determinable` field as compliant.

So every enriched value carries `source`, and the field verdict says
"enriched from NVD" rather than "present".
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import date
from typing import Any

from app.services.kb import eolClient
from app.utils.logger import get_logger

logger = get_logger(__name__)

#: Deterministic feeds. An agent-sourced value is marked separately and reviewed.
DETERMINISTIC_SOURCES = frozenset({"nvd", "cisa-kev", "endoflife.date", "certin"})


@dataclass(frozen=True, slots=True)
class EnrichedValue:
    """One field filled from outside the BOM."""

    value: Any
    source: str
    detail: str = ""

    @property
    def is_deterministic(self) -> bool:
        return self.source in DETERMINISTIC_SOURCES


@dataclass(slots=True)
class EnrichmentOutcome:
    """What enrichment did to one entity set."""

    enriched: int = 0
    unresolved: list[str] = field(default_factory=list)
    #: Distinct products the deterministic feeds could not answer. This is the
    #: agent's batch list — per product, never per component (§11).
    agent_batch: set[str] = field(default_factory=set)
    sources_used: set[str] = field(default_factory=set)
    #: Feeds that were unavailable, so their absence is a reported gap rather
    #: than an implied "nothing found".
    unavailable: dict[str, str] = field(default_factory=dict)


def _as_date(value: Any) -> date | None:
    if isinstance(value, date):
        return value
    if isinstance(value, str):
        try:
            return date.fromisoformat(value[:10])
        except ValueError:
            return None
    return None


def apply_vulnerabilities(
    entity: dict[str, Any], cves: list[dict[str, Any]], *, kev_index: dict[str, Any]
) -> EnrichedValue | None:
    """4.2(8) Vulnerabilities, and the KEV flag that drives `vexCoverage`."""
    if not cves:
        return None

    identifiers = [cve["cve_id"] for cve in cves if cve.get("cve_id")]
    kev_hits = [cve_id for cve_id in identifiers if cve_id in kev_index]

    entity["vulnerabilities"] = identifiers
    entity["vulnerability_source"] = "nvd"
    if kev_hits:
        # Read by the S9 vexCoverage rule once VEX authoring lands (S12).
        entity["kev_cves"] = kev_hits

    return EnrichedValue(
        value=identifiers,
        source="nvd",
        detail=(
            f"{len(identifiers)} CVE(s) from NVD"
            + (f", {len(kev_hits)} KEV-listed" if kev_hits else "")
        ),
    )


def apply_lifecycle(
    entity: dict[str, Any], cycles: list[dict[str, Any]]
) -> dict[str, EnrichedValue]:
    """4.2(10) Release Date and 4.2(11) End-of-Life, from the matched cycle."""
    matched = eolClient.match_cycle(cycles, entity.get("version"))
    if matched is None:
        return {}

    applied: dict[str, EnrichedValue] = {}

    if eol := _as_date(matched.get("eol_date")):
        entity["eol_date"] = eol.isoformat()
        entity["eol_source"] = matched.get("source", "endoflife.date")
        applied["end_of_life"] = EnrichedValue(
            value=eol.isoformat(),
            source=str(matched.get("source", "endoflife.date")),
            detail=f"cycle {matched.get('cycle')} reaches end-of-life {eol.isoformat()}",
        )

    if released := _as_date(matched.get("release_date")):
        entity["release_date"] = released.isoformat()
        entity["release_source"] = matched.get("source", "endoflife.date")
        applied["release_date"] = EnrichedValue(
            value=released.isoformat(),
            source=str(matched.get("source", "endoflife.date")),
            detail=f"cycle {matched.get('cycle')} released {released.isoformat()}",
        )

    # 4.2(9) Patch Status: derivable only where the feed states a latest version.
    latest = matched.get("latest_version")
    if latest and entity.get("version"):
        current = str(entity["version"]) == str(latest)
        entity["patch_status"] = "current" if current else f"behind (latest {latest})"
        entity["patch_source"] = matched.get("source", "endoflife.date")
        applied["patch_status"] = EnrichedValue(
            value=entity["patch_status"],
            source=str(matched.get("source", "endoflife.date")),
            detail=f"declared {entity['version']}, latest in cycle is {latest}",
        )

    return applied


def batch_key_for(entity: dict[str, Any]) -> str:
    """The distinct product an entity belongs to.

    **This is what makes agentic enrichment affordable.** A 50,000-component SBOM
    has perhaps forty unknown *products*; batching per product turns forty
    thousand potential retrieval loops into forty. Per-component retrieval is a
    cost failure, not a design choice (§11).
    """
    purl = str(entity.get("purl") or "")
    if purl.startswith("pkg:"):
        # pkg:maven/org.apache.tomcat/tomcat-catalina@9.0.71 -> the name, not the
        # version: two versions of one product are one research question.
        body = purl[4:].split("?")[0].split("@")[0]
        return body.lower()
    return str(entity.get("name") or "").strip().lower()


def summarise(outcome: EnrichmentOutcome) -> dict[str, Any]:
    """The deterministic-versus-agentic split the sprint exits on."""
    return {
        "enriched": outcome.enriched,
        "unresolved": len(outcome.unresolved),
        "agent_batches": len(outcome.agent_batch),
        "sources_used": sorted(outcome.sources_used),
        "feeds_unavailable": outcome.unavailable,
    }
