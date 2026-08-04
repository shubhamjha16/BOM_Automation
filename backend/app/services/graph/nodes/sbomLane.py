"""SBOM lane — CERT-In s.4.2, the 21 minimum elements.

The lane body is synchronous and pure: parse, score, verdict. No I/O, no clock,
no model. The runner wraps it with timing, timeout and isolation.
"""

from __future__ import annotations

from app.configs.scoringConfig import ENGINE_VERSION
from app.services.catalogue.loader import catalogue_checksum, get_catalogue
from app.services.graph.laneRunner import run_lane
from app.services.graph.state import GraphState, LaneResult, SubmissionDocument
from app.services.ingest.parsers import cyclonedx
from app.services.score.documentChecks import check_all, document_metadata
from app.services.score.verdict import lane_verdict
from app.services.score.weighting import lane_score


def score_sbom(documents: list[SubmissionDocument]) -> LaneResult:
    catalogue = get_catalogue("sbom")
    entities: list[dict] = []
    document_meta: list[dict] = []
    rejected = 0

    for document in documents:
        parsed = cyclonedx.parse(document.payload, lane="sbom")
        parsed.assert_conserved(len(document.payload.get("components", []) or []))
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
        detail = f"{detail}; {rejected} entry/entries rejected, see the rejected list"

    return LaneResult(
        lane="sbom",
        verdict=verdict,
        score=score,
        entity_count=len(entities),
        detail=detail,
        engine_version=ENGINE_VERSION,
        inputs_hash=catalogue_checksum("sbom"),
    )


async def sbom_lane(state: GraphState) -> GraphState:
    return await run_lane(state, "sbom", score_sbom)
