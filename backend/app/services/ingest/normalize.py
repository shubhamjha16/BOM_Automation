"""One entry point for ingestion: detect, dispatch, parse.

Every caller goes through `ingest_document`. Keeping the dispatch in one place is
what lets the "never silently empty" rule be checked once rather than in each
lane — there is exactly one function that can return entities, and it either
returns a conserved `ParseResult` or raises.
"""

from __future__ import annotations

from typing import Any

from app.services.ingest.detect import Format, detect
from app.services.ingest.parsers import assetRegister, cyclonedx, spdxJson, spdxTagValue
from app.services.ingest.result import ParseResult
from app.utils.logger import get_logger

logger = get_logger(__name__)


def ingest_document(
    payload: Any, *, lane: str = "sbom", declared_format: str | None = None
) -> ParseResult:
    """Detect the format, parse it, and return a conserved result.

    Raises on anything it cannot read. It never returns an empty result for an
    unreadable document, because an empty component list renders as a clean
    assessment of a supplier who submitted nothing wrong.
    """
    # An asset register is not a BOM format and has no self-identifying field —
    # it is a spreadsheet. The caller declares it, which is why detection is
    # explicit and caller-overridable in the first place.
    if lane == "hbom" or (declared_format or "").lower().startswith("assetregister"):
        result = assetRegister.parse(payload, lane=lane)
        logger.info(
            "document_ingested",
            format=result.format,
            spec_version=result.spec_version,
            lane=lane,
            parsed=result.parsed_count,
            rejected=result.rejected_count,
        )
        return result

    detection = detect(payload, declared=declared_format)

    if detection.format is Format.CYCLONEDX_JSON:
        result = cyclonedx.parse(payload, lane=lane)
    elif detection.format is Format.SPDX_JSON:
        result = spdxJson.parse(payload, lane=lane)
    else:
        result = spdxTagValue.parse(payload, lane=lane)

    logger.info(
        "document_ingested",
        format=str(detection.format),
        spec_version=result.spec_version,
        lane=lane,
        parsed=result.parsed_count,
        rejected=result.rejected_count,
    )
    return result


def supported_formats() -> dict[str, list[str]]:
    """What this engine can read, for the API and for rejection messages."""
    return {
        "CycloneDX": sorted(cyclonedx.SUPPORTED_SPEC_VERSIONS),
        "SPDX": sorted(spdxJson.SUPPORTED_SPEC_VERSIONS),
    }
