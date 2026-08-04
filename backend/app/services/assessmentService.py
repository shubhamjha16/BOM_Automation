"""Run an assessment through the graph and summarise the result.

The service owns the graph invocation; controllers own HTTP. S2 persists the
lane results and node runs, S4 moves the invocation onto arq — the shape here
does not change when they do.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from typing import Any

from app.configs.envConfig import Lane
from app.configs.jobTypes import JobStatus, LaneVerdict
from app.services.graph.builder import compile_assessment_graph
from app.services.graph.state import (
    CorrelationFinding,
    GraphState,
    LaneResult,
    NodeRun,
    SubmissionDocument,
)
from app.services.score.weighting import overall_score
from app.utils.logger import get_logger

logger = get_logger(__name__)

_graph = None


def _get_graph() -> Any:
    """Compiled once. Compilation is pure wiring, so a module-level cache is safe."""
    global _graph
    if _graph is None:
        _graph = compile_assessment_graph()
    return _graph


@dataclass(frozen=True, slots=True)
class AssessmentSummary:
    job_id: str
    submission_id: str
    status: JobStatus
    overall_score: float | None
    lane_results: list[LaneResult]
    node_runs: list[NodeRun]
    errors: list[str]
    correlation_findings: list[CorrelationFinding] = field(default_factory=list)
    gate_reason: str | None = None

    @property
    def parallelism_proven(self) -> bool:
        """True when at least two lane runs overlap in wall-clock time.

        The S1 exit proof. Sequential lanes would produce disjoint intervals, and
        an assessment that claims a parallel graph while running five lanes in
        series has a design that only reads as concurrent.
        """
        lane_runs = [run for run in self.node_runs if run.lane is not None]
        return any(
            left.overlaps(right)
            for index, left in enumerate(lane_runs)
            for right in lane_runs[index + 1 :]
        )


def _summarise(state: GraphState, job_id: str, submission_id: str) -> AssessmentSummary:
    results = state.get("lane_results", [])
    scores: dict[str, float | None] = {
        result.lane: (result.score if result.counts_toward_overall else None)
        for result in results
    }
    status = state.get("status", JobStatus.SUCCEEDED)
    if status is JobStatus.RUNNING:
        status = JobStatus.SUCCEEDED

    return AssessmentSummary(
        job_id=job_id,
        submission_id=submission_id,
        status=status,
        overall_score=overall_score(scores),
        lane_results=sorted(results, key=lambda result: result.lane),
        node_runs=state.get("node_runs", []),
        errors=state.get("errors", []),
        correlation_findings=state.get("correlation_findings", []),
        gate_reason=state.get("gate_reason"),
    )


async def run_assessment(
    *,
    org_id: str,
    submission_id: str,
    documents: list[SubmissionDocument],
    requested_lanes: list[Lane] | None = None,
    job_id: str | None = None,
) -> AssessmentSummary:
    """Assess one submission across every enabled lane."""
    job_id = job_id or str(uuid.uuid4())
    initial = GraphState(
        job_id=job_id,
        org_id=org_id,
        submission_id=submission_id,
        status=JobStatus.RUNNING,
        documents=documents,
        requested_lanes=list(requested_lanes or []),
        lane_results=[],
        node_runs=[],
        errors=[],
        correlation_findings=[],
        heal_attempts=0,
    )

    logger.info("assessment_started", job_id=job_id, documents=len(documents))
    final: GraphState = await _get_graph().ainvoke(initial)
    summary = _summarise(final, job_id, submission_id)

    logger.info(
        "assessment_complete",
        job_id=job_id,
        status=str(summary.status),
        overall_score=summary.overall_score,
        parallelism_proven=summary.parallelism_proven,
        verdicts={result.lane: str(result.verdict) for result in summary.lane_results},
    )
    return summary


def lane_rollup(summary: AssessmentSummary) -> dict[Lane, dict[str, Any]]:
    """Per-lane view for the console. Five tracks, not one spinner."""
    return {
        result.lane: {
            "verdict": str(result.verdict),
            "score": result.score,
            "entity_count": result.entity_count,
            "detail": result.detail,
            "counts_toward_overall": result.counts_toward_overall,
            "is_finding": result.verdict is LaneVerdict.LANE_ABSENT,
        }
        for result in summary.lane_results
    }
