"""The blocking gate. Runs before anything renders. **No bypass flag.**

A job that fails here terminates as ``blocked_conformance`` naming the field, and
nothing renders. That is not a job failure to be retried — retrying will
correctly refuse again. It is a refusal to issue an assessment that could not be
traced to the guideline.

Three checks, all of them refusals rather than warnings:

1. **Every clause resolves** in the pinned guideline version — field verdicts and
   correlation findings alike.
2. **No `not_determinable` field reached the supplier score.** Scoring one as a
   defect blames a supplier for something they could not have supplied; scoring
   it as compliant puts a green tick on a field nobody checked. Both end with a
   client failing a real audit while holding this assessment.
3. **No consumer-determined field was given a supplier verdict.** This is the
   direction a probe bug takes: a `present` on Criticality would silently mark a
   consumer determination as met.
"""

from __future__ import annotations

from datetime import UTC, datetime

from app.configs.jobTypes import JobStatus
from app.services.graph.state import GraphState, NodeRun
from app.utils.logger import get_logger
from app.validators.conformanceValidator import (
    ClauseNotTraceable,
    assert_all_traceable,
    citations_from,
)
from app.validators.determinabilityValidator import (
    DeterminabilityViolation,
    assert_rows_not_scored,
)

logger = get_logger(__name__)


async def conformance_gate(state: GraphState) -> GraphState:
    started_at = datetime.now(UTC)
    lane_results = state.get("lane_results", [])
    findings = state.get("correlation_findings", [])

    citations = citations_from(lane_results, findings)
    rows = [field for result in lane_results for field in (result.field_results or [])]

    try:
        assert_all_traceable(citations)
        assert_rows_not_scored(rows)
    except (ClauseNotTraceable, DeterminabilityViolation) as error:
        logger.error(
            "conformance_gate_blocked",
            reason=str(error),
            job_id=state.get("job_id"),
            citations_checked=len(citations),
        )
        return GraphState(
            status=JobStatus.BLOCKED_CONFORMANCE,
            gate_verdict="blocked",
            gate_reason=str(error),
            node_runs=[
                NodeRun(
                    node="conformanceGate",
                    status="failed",
                    started_at=started_at,
                    finished_at=datetime.now(UTC),
                    error=str(error),
                )
            ],
        )

    logger.info(
        "conformance_gate_passed",
        citations_checked=len(citations),
        fields_checked=len(rows),
        findings_checked=len(findings),
    )
    return GraphState(
        gate_verdict="passed",
        gate_reason=None,
        node_runs=[
            NodeRun(
                node="conformanceGate",
                status="succeeded",
                started_at=started_at,
                finished_at=datetime.now(UTC),
            )
        ],
    )
