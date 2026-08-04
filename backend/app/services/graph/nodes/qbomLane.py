"""QBOM lane — CERT-In s.8.5.

Ships beside CBOM because Table 8 embeds Cryptographic Asset, pointing at the
Table 9 model the CBOM lane already builds. This lane adds only what is
QBOM-specific: the quantum system itself, and the migration posture of the
classical cryptography it threatens.
"""

from __future__ import annotations

from app.configs.scoringConfig import ENGINE_VERSION
from app.services.catalogue.loader import catalogue_checksum, get_catalogue
from app.services.graph.laneRunner import run_lane
from app.services.graph.nodes.sbomLane import _as_row
from app.services.graph.state import GraphState, LaneResult, SubmissionDocument
from app.services.ingest.normalize import ingest_document
from app.services.score.documentChecks import check_all, document_metadata
from app.services.score.verdict import lane_verdict
from app.services.score.weighting import lane_score


def score_qbom(documents: list[SubmissionDocument]) -> LaneResult:
    catalogue = get_catalogue("qbom")
    entities: list[dict] = []
    document_meta: list[dict] = []
    rejected = 0

    for document in documents:
        parsed = ingest_document(document.payload, lane="qbom", declared_format=document.format)
        entities.extend(parsed.entities)
        document_meta.append(
            document_metadata(
                author=parsed.doc_author,
                timestamp=parsed.doc_timestamp,
                spec_version=parsed.spec_version,
            )
        )
        rejected += len(parsed.rejected)

    results = check_all(catalogue, entities, document_meta)
    score = lane_score(results)
    verdict, detail = lane_verdict(score, results)

    if rejected:
        detail = f"{detail}; {rejected} entry/entries not scored by this lane"

    return LaneResult(
        lane="qbom",
        verdict=verdict,
        score=score,
        entity_count=len(entities),
        detail=detail,
        engine_version=ENGINE_VERSION,
        inputs_hash=catalogue_checksum("qbom"),
        field_results=[_as_row(item) for item in results],
        rejected_count=rejected,
        entities=entities,
    )


async def qbom_lane(state: GraphState) -> GraphState:
    return await run_lane(state, "qbom", score_qbom)
