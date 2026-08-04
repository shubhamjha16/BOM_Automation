"""Persisting an assessment run: the graph's in-memory result becomes rows.

This is the seam between the graph (which knows nothing about databases) and the
job table. Keeping it here means `run_assessment` stays testable without a
session, and the persistence rules stay in one place rather than being spread
across nodes.
"""

from __future__ import annotations

import uuid

from app.configs.jobTypes import JobStatus
from app.repositories.jobRepository import JobRepository
from app.services.assessmentService import AssessmentSummary
from app.utils.logger import get_logger

logger = get_logger(__name__)


def _node_run_rows(summary: AssessmentSummary) -> list[dict]:
    return [
        {
            "lane": run.lane,
            "node": run.node,
            "attempt": run.attempt,
            "status": run.status,
            "started_at": run.started_at,
            "finished_at": run.finished_at,
            "latency_ms": run.latency_ms,
            "error": run.error,
        }
        for run in summary.node_runs
    ]


async def persist_summary(
    repository: JobRepository, job_id: uuid.UUID, summary: AssessmentSummary
) -> None:
    """Write the run log, then close the job.

    **Order matters.** Node runs are written first: they are the audit trail and
    the evidence of parallelism, and once `mark_terminal` succeeds the job is
    settled. Writing history after the close would leave a window where a job
    reads as finished with nothing behind it.

    A lane that failed does not fail the job. Lanes fail independently — an
    absent or timed-out lane is a reported finding, and the assessment that
    reports it succeeded at its own task.
    """
    await repository.record_node_runs(job_id, _node_run_rows(summary))

    status = (
        JobStatus.BLOCKED_CONFORMANCE
        if summary.status is JobStatus.BLOCKED_CONFORMANCE
        else JobStatus.SUCCEEDED
    )
    error = summary.gate_reason if status is JobStatus.BLOCKED_CONFORMANCE else None

    await repository.mark_terminal(job_id, status, error=error)
    logger.info(
        "assessment_persisted",
        job_id=str(job_id),
        status=str(status),
        node_runs=len(summary.node_runs),
        lane_errors=len(summary.errors),
    )
