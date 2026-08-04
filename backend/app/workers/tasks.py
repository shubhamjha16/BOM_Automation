"""Worker tasks.

Every task is a plain async function that takes its own session and does its own
org scoping. They are called directly in tests — no Redis, no worker — which is
what keeps the queue an execution detail rather than a testing obstacle.

**A task never raises for a lane failure.** Lanes fail independently: an absent,
crashed or timed-out lane is a reported finding, and raising would make arq retry
a job whose assessment already succeeded at its own task.
"""

from __future__ import annotations

import uuid
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from typing import Any

from sqlalchemy.ext.asyncio import AsyncSession

from app.configs.dbConfig import get_sessionmaker
from app.configs.jobTypes import JobStatus
from app.models.enums import SubmissionStatus
from app.repositories.jobRepository import JobRepository, TerminalJobWriteRejected
from app.repositories.submissionRepository import SubmissionRepository
from app.services.assessmentService import run_assessment
from app.services.graph.state import SubmissionDocument
from app.services.jobService import persist_summary
from app.utils.logger import get_logger

logger = get_logger(__name__)


@asynccontextmanager
async def _session_for(ctx: dict[str, Any]) -> AsyncIterator[AsyncSession]:
    """The session this task should use.

    Three cases, deliberately explicit:

    * ``ctx["session"]`` — an already-open session, handed in by an inline caller.
      **Reused, not replaced, and never closed here.** Opening a second session
      would put the task on a different connection that cannot see the caller's
      uncommitted work, and committing it would settle a transaction the caller
      still owns.
    * ``ctx["session_factory"]`` — a factory supplied by tests or by worker
      startup.
    * Neither — the process-wide factory, which is the real worker path.
    """
    existing = ctx.get("session")
    if existing is not None:
        yield existing
        return

    factory = ctx.get("session_factory") or get_sessionmaker()
    async with factory() as session:
        yield session


async def run_assessment_task(
    ctx: dict[str, Any], org_id: str, submission_id: str, job_id: str
) -> dict[str, Any]:
    """Assess one submission. The unit of work the queue schedules.

    The whole fan-out runs inside this single task rather than one task per lane.
    Five tasks would need a barrier to know when to join, and a barrier over a
    queue is a distributed lock — where the graph already gives an in-process
    join for free. Concurrency across *submissions* is what the queue provides,
    and that is where it is actually needed.
    """
    scoped_org = uuid.UUID(org_id)
    borrowed = ctx.get("session") is not None

    async with _session_for(ctx) as session:
        jobs = JobRepository(session, scoped_org)
        submissions = SubmissionRepository(session, scoped_org)

        job = await jobs.get(uuid.UUID(job_id))
        if job is None:
            # Not an error worth retrying: the job was deleted or belongs to
            # another tenant. Retrying cannot make it exist.
            logger.warning("task_job_missing", job_id=job_id, org_id=org_id)
            return {"status": "job_missing", "job_id": job_id}
        if job.is_terminal:
            # A redelivery after the job already settled. arq guarantees
            # at-least-once, so this is expected traffic, not an anomaly.
            logger.info("task_already_terminal", job_id=job_id, status=str(job.status))
            return {"status": str(job.status), "job_id": job_id, "redelivered": True}

        try:
            await jobs.mark_running(job.id)
        except TerminalJobWriteRejected:
            return {"status": "already_terminal", "job_id": job_id}

        submission = await submissions.get_with_documents(uuid.UUID(submission_id))
        if submission is None:
            await jobs.mark_terminal(
                job.id, JobStatus.FAILED, error="submission not found for this job"
            )
            if not borrowed:
                await session.commit()
            return {"status": "failed", "job_id": job_id}

        documents = [
            SubmissionDocument(
                lane=document.lane,  # type: ignore[arg-type]
                format=document.format.value,
                payload=document.payload,
                spec_version=document.spec_version,
                filename=document.filename,
            )
            for document in submission.documents
            if document.payload is not None
        ]

        summary = await run_assessment(
            org_id=org_id,
            submission_id=submission_id,
            documents=documents,
            job_id=job_id,
        )
        await persist_summary(jobs, job.id, summary)
        await submissions.set_status(
            submission.id, SubmissionStatus.SCORED, overall_score=summary.overall_score
        )
        # A borrowed session belongs to the caller's transaction; committing it
        # here would settle work the caller has not finished.
        if not borrowed:
            await session.commit()

    return {
        "status": str(summary.status),
        "job_id": job_id,
        "overall_score": summary.overall_score,
        "lanes": {result.lane: str(result.verdict) for result in summary.lane_results},
    }


async def reconcile_stale_jobs(
    ctx: dict[str, Any], org_id: str, older_than_seconds: int = 900
) -> int:
    """Fail jobs left running by a worker that died.

    Scheduled rather than triggered: the whole point is that nothing is alive to
    trigger it. Marks orphans failed rather than requeueing, because whether a
    re-run is safe depends on what the job already wrote.
    """
    from datetime import UTC, datetime, timedelta

    cutoff = datetime.now(UTC) - timedelta(seconds=older_than_seconds)
    borrowed = ctx.get("session") is not None

    async with _session_for(ctx) as session:
        jobs = JobRepository(session, uuid.UUID(org_id))
        reconciled = await jobs.reconcile_stale(
            older_than=cutoff, reason=f"no worker heartbeat for {older_than_seconds}s"
        )
        if not borrowed:
            await session.commit()
    return len(reconciled)
