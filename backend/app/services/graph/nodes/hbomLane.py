"""HBOM lane — CERT-In s.10.2, Table 11.

Lands here rather than beside the artifact-scanning lanes because its data is
procurement data: asset registers, purchase records and delivery documentation,
not scanner output. Every result carries `SOURCE_NOTE` so a reader can tell which
claims rest on a scan and which on a purchase order.
"""

from __future__ import annotations

from app.configs.scoringConfig import ENGINE_VERSION
from app.services.catalogue.hbom import SOURCE_NOTE
from app.services.catalogue.loader import catalogue_checksum, get_catalogue
from app.services.graph.laneRunner import run_lane
from app.services.graph.nodes.sbomLane import _as_row
from app.services.graph.state import GraphState, LaneResult, SubmissionDocument
from app.services.ingest.normalize import ingest_document
from app.services.score.documentChecks import check_all, document_metadata
from app.services.score.verdict import lane_verdict
from app.services.score.weighting import lane_score


def score_hbom(documents: list[SubmissionDocument]) -> LaneResult:
    catalogue = get_catalogue("hbom")
    entities: list[dict] = []
    document_meta: list[dict] = []
    rejected = 0

    for document in documents:
        parsed = ingest_document(
            document.payload, lane="hbom", declared_format=document.format
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

    results = check_all(catalogue, entities, document_meta)
    score = lane_score(results)
    verdict, detail = lane_verdict(score, results)

    # Stated on every HBOM result, not only in the narrative: a reader must be
    # able to tell a missing purchase record from a missing scan.
    detail = f"{detail}. {SOURCE_NOTE}"
    if rejected:
        detail = f"{detail} {rejected} register row(s) could not be read."

    return LaneResult(
        lane="hbom",
        verdict=verdict,
        score=score,
        entity_count=len(entities),
        detail=detail,
        engine_version=ENGINE_VERSION,
        inputs_hash=catalogue_checksum("hbom"),
        field_results=[_as_row(item) for item in results],
        rejected_count=rejected,
        entities=entities,
    )


async def hbom_lane(state: GraphState) -> GraphState:
    return await run_lane(state, "hbom", score_hbom)
