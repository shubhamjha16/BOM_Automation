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


def is_asset_register(
    payload: Any, *, lane: str, declared_format: str | None = None
) -> bool:
    """True for a spreadsheet export rather than a BOM document.

    An asset register has no self-identifying field — it is a spreadsheet — so it
    is recognised by being *text or bytes* in the HBOM lane, or by the caller
    saying so outright. A mapping that identifies itself as CycloneDX or SPDX is
    never one, whatever lane it arrived in.
    """
    if (declared_format or "").lower().startswith("assetregister"):
        return True
    return lane == "hbom" and isinstance(payload, (str, bytes, bytearray))


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
    # A text document stored in a JSON payload column arrives wrapped. That is a
    # storage detail of the interim `bom_documents.payload` column, and it
    # disappears when documents move to object storage.
    if isinstance(payload, dict) and set(payload) == {"__text__"}:
        payload = payload["__text__"]

    # **Routed on the payload's shape, not on the lane alone.** HBOM data is
    # usually procurement data — a CSV or XLSX export from ServiceNow, SAP or a
    # spreadsheet — which is why the lane implies the asset-register parser. But
    # CycloneDX 1.6 carries hardware as `type: device`, and s.10.2.4 makes the
    # HBOM-with-SBOM pairing explicit, so a CycloneDX HBOM is a legitimate
    # submission. Routing every hbom document to the register parser refused those
    # with "an asset register must be CSV text or XLSX bytes, got dict" — an
    # internal message about our own dispatcher, raised at a supplier who sent a
    # valid document. Found by the S21 scale measurement, whose HBOM lane was
    # quietly timing the exception path.
    if is_asset_register(payload, lane=lane, declared_format=declared_format):
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
