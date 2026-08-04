"""The blocking gate. Runs before anything renders.

A job that fails here terminates as ``blocked_conformance`` naming the field, and
nothing renders. That is not a job failure to be retried — it is a refusal to
issue an assessment that could not be traced to the guideline.

S8 extends this with the figure-provenance check (S11) once the narrative path
produces prose. The clause and determinability checks are enforced from S1.
"""

from __future__ import annotations

from datetime import UTC, datetime

from app.configs.jobTypes import JobStatus
from app.services.graph.state import GraphState, NodeRun
from app.utils.logger import get_logger
from app.validators.conformanceValidator import ClauseNotTraceable, assert_all_traceable
from app.validators.determinabilityValidator import DeterminabilityViolation

logger = get_logger(__name__)


async def conformance_gate(state: GraphState) -> GraphState:
    started_at = datetime.now(UTC)
    citations = [
        (finding.clause, "sbom") for finding in state.get("correlation_findings", [])
    ]

    try:
        assert_all_traceable(citations)  # type: ignore[arg-type]
    except (ClauseNotTraceable, DeterminabilityViolation) as error:
        logger.error("conformance_gate_blocked", reason=str(error))
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

    logger.info("conformance_gate_passed", citations_checked=len(citations))
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
