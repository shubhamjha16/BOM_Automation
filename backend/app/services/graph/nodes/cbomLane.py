"""CBOM lane — CERT-In s.8.4.

Scores the four Table 9 asset types. Each element declares which asset
types it applies to, and coverage excludes the rest from the denominator:
reporting a certificate as missing its cipher mode is a category error, not a
gap.

Document-level checks sit alongside the field verdicts. Coverage answers "was it
declared?"; those answer "is what was declared wrong?" — and a fully-declared
expired certificate scores full marks on every field.
"""

from __future__ import annotations

from app.configs.scoringConfig import ENGINE_VERSION
from app.services.catalogue.loader import catalogue_checksum, get_catalogue
from app.services.graph.laneRunner import run_lane
from app.services.graph.nodes.sbomLane import _as_row
from app.services.graph.state import GraphState, LaneResult, SubmissionDocument
from app.services.ingest.normalize import ingest_document
from app.services.score.cryptoChecks import run_all
from app.services.score.documentChecks import check_all, document_metadata
from app.services.score.verdict import lane_verdict
from app.services.score.weighting import lane_score


def score_cbom(documents: list[SubmissionDocument]) -> LaneResult:
    catalogue = get_catalogue("cbom")
    entities: list[dict] = []
    document_meta: list[dict] = []
    rejected = 0

    for document in documents:
        parsed = ingest_document(document.payload, lane="cbom", declared_format=document.format)
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

    # Document-level checks: coverage answers "was it declared?", these answer
    # "is what was declared wrong?". A fully-declared expired certificate scores
    # full marks on every field and is still a finding.
    findings = run_all(entities)
    verdict, detail = lane_verdict(score, results, configuration_findings=findings)
    if findings:
        detail = f"{detail}; {len(findings)} configuration finding(s): " + "; ".join(
            f"s.{item.clause} {item.check_key}" for item in findings[:3]
        )

    if rejected:
        detail = f"{detail}; {rejected} entry/entries not scored by this lane"

    return LaneResult(
        lane="cbom",
        verdict=verdict,
        score=score,
        entity_count=len(entities),
        detail=detail,
        engine_version=ENGINE_VERSION,
        inputs_hash=catalogue_checksum("cbom"),
        field_results=[_as_row(item) for item in results],
        rejected_count=rejected,
        entities=entities,
    )


async def cbom_lane(state: GraphState) -> GraphState:
    return await run_lane(state, "cbom", score_cbom)
