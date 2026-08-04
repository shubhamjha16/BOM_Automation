"""AIBOM lane — CERT-In s.9.3.

Structurally identical to the SBOM lane, over a different catalogue and a
different entity set. That symmetry is the point: adding a sixth BOM type when
CERT-In publishes v3.0 is one lane module plus one catalogue file.
"""

from __future__ import annotations

from app.configs.scoringConfig import ENGINE_VERSION
from app.services.catalogue.loader import catalogue_checksum, get_catalogue
from app.services.graph.laneRunner import run_lane
from app.services.graph.state import GraphState, LaneResult, SubmissionDocument
from app.services.ingest.normalize import ingest_document
from app.services.score.documentChecks import check_all, document_metadata
from app.services.score.fieldCheck import FieldResult
from app.services.score.verdict import lane_verdict
from app.services.score.weighting import lane_score


def _as_row(result: FieldResult) -> dict:
    """Flatten a FieldResult for persistence and for the API."""
    return {
        "element_key": result.element_key,
        "label": result.label,
        "clause": result.clause,
        "tier": str(result.tier),
        "determinability": str(result.determinability),
        "verdict": str(result.verdict),
        "populated": result.coverage.populated,
        "total": result.coverage.total,
        "coverage": round(result.coverage.ratio, 4),
        "weight": result.weight,
        "detail": result.detail,
        "consumer_action": result.consumer_action or None,
    }


def score_aibom(documents: list[SubmissionDocument]) -> LaneResult:
    catalogue = get_catalogue("aibom")
    entities: list[dict] = []
    document_meta: list[dict] = []
    rejected = 0

    for document in documents:
        # The dispatcher detects, validates and conserves; a lane never picks
        # a parser, so a new format is one dispatcher branch and no lane edits.
        parsed = ingest_document(
            document.payload, lane="aibom", declared_format=document.format
        )
        entities.extend(parsed.entities)
        document_meta.append(
            document_metadata(
                author=parsed.doc_author,
                timestamp=parsed.doc_timestamp,
                spec_version=parsed.spec_version,
            )
        )
        rejected += len(parsed.rejected)

    # Elements are routed by scope: per-component fields over the entity set,
    # document fields (author, timestamp) over the documents themselves.
    results = check_all(catalogue, entities, document_meta)
    score = lane_score(results)
    verdict, detail = lane_verdict(score, results)
    if rejected:
        detail = f"{detail}; {rejected} non-model entry/entries not scored by this lane"

    return LaneResult(
        lane="aibom",
        verdict=verdict,
        score=score,
        entity_count=len(entities),
        detail=detail,
        engine_version=ENGINE_VERSION,
        inputs_hash=catalogue_checksum("aibom"),
        field_results=[_as_row(item) for item in results],
        entities=entities,
        rejected_count=rejected,
    )


async def aibom_lane(state: GraphState) -> GraphState:
    return await run_lane(state, "aibom", score_aibom)
