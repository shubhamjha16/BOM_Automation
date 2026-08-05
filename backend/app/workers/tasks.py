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
from app.repositories.corpusRepository import CorpusRepository
from app.repositories.jobRepository import JobRepository, TerminalJobWriteRejected
from app.repositories.laneRepository import LaneRepository
from app.repositories.submissionRepository import SubmissionRepository
from app.services.assessmentService import run_assessment
from app.services.catalogue.seeder import get_active_version
from app.services.graph.state import SubmissionDocument
from app.services.ingest.normalize import ingest_document
from app.services.jobService import persist_lane_results, persist_summary
from app.services.llm.anthropicClient import active_generator
from app.services.narrative.drafter import UnsupportedFigure, draft_section
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

        # The engagement's lanes reach the fan-out here. Without this they only
        # ever reached the idempotency key, and every lane ran on every
        # submission — making lane_not_applicable unreachable in practice.
        summary = await run_assessment(
            org_id=org_id,
            submission_id=submission_id,
            documents=documents,
            requested_lanes=await submissions.enabled_lanes_for(submission.id),
            job_id=job_id,
        )
        # Pin this assessment to the catalogue version it was scored under.
        # Read only: seeding is a deployment step (`make seed-catalogue`), and a
        # task that wrote the schema row would put twenty concurrent assessments
        # into a race over it. A missing pin is reported, not manufactured.
        version = await get_active_version(session)
        if version is None:
            logger.warning(
                "guideline_version_unseeded",
                submission_id=submission_id,
                detail="lane results will not be pinned; run `make seed-catalogue`",
            )
        lanes = LaneRepository(session, scoped_org)
        await persist_lane_results(
            lanes,
            submission.id,
            summary,
            guideline_version_id=version.id if version else None,
        )

        # Cross-BOM findings, cited and gated exactly as field verdicts are.
        await lanes.record_findings(
            submission_id=submission.id, findings=summary.correlation_findings
        )

        # Every entry the parsers refused, kept with its reason so
        # GET /submissions/{id}/rejected can answer "why 380 and not 400?".
        for document in submission.documents:
            if document.payload is None:
                continue
            try:
                parsed = ingest_document(
                    document.payload,
                    lane=document.lane,
                    declared_format=document.format.value,
                )
            except Exception:  # noqa: BLE001 - the lane already reported this
                continue
            document.parsed_count = parsed.parsed_count
            document.rejected_count = parsed.rejected_count
            document.entry_count = parsed.entry_count
            await lanes.record_rejections(
                bom_document_id=document.id, rejections=parsed.rejected
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


async def sync_kb(ctx: dict[str, Any], older_than_seconds: int = 0) -> dict[str, int]:
    """Refresh the knowledge base. Scheduled, never on the assessment path.

    **Why this is a task and not a lazy fetch.** The CISA KEV catalogue is ~1,600
    entries refreshed once a day. Fetching it inside an assessment meant twenty
    concurrent submissions downloaded it twenty times, each holding a database
    transaction open across seconds of network I/O. The same lesson as catalogue
    seeding: work that is shared, slow and infrequent belongs on a schedule.
    """
    from app.services.kb import kevClient

    entries = await kevClient.fetch_catalog()
    kevClient.prime_cache(entries)
    logger.info("kb_synced", kev_entries=len(entries))
    return {"kev_entries": len(entries)}


async def draft_narrative_task(
    ctx: dict[str, Any],
    org_id: str,
    job_id: str,
    section: str,
    facts: str,
    engagement_id: str | None = None,
) -> dict[str, Any]:
    """Draft one assessment section from the engine's facts and house wording.

    **The three `narrative_*` job types were declared in `JobType` and wired to
    nothing.** An enum value with no handler is worse than an absent one: it reads
    as a supported operation, and the first caller to enqueue it gets a job that
    sits queued forever.

    Runs as a job rather than inline for the same reason assessment does — a
    provider call is seconds of latency that must not be attached to an HTTP
    request. The section still carries its findings when no provider is
    configured, because `NullGenerator` restates them rather than returning
    nothing (§11: a client reading flat facts is better served than one reading
    fluent prose that might be wrong).
    """
    scoped_org = uuid.UUID(org_id)

    async with _session_for(ctx) as session:
        jobs = JobRepository(session, scoped_org)
        job = await jobs.get(uuid.UUID(job_id))
        if job is None:
            logger.warning("narrative_job_missing", job_id=job_id)
            return {"status": "missing"}

        await jobs.mark_running(job.id)
        try:
            drafted = await draft_section(
                CorpusRepository(session, scoped_org),
                section=section,
                facts=facts,
                engagement_id=uuid.UUID(engagement_id) if engagement_id else None,
                generator=ctx.get("generator") or active_generator(),
            )
        except UnsupportedFigure as error:
            # A draft asserting an unsupplied figure is a refusal, not a retry.
            # Re-running the same prompt against the same model produces the same
            # class of fabrication, and a queue that retries it burns the budget
            # and eventually ships one.
            logger.error("narrative_refused", section=section, error=str(error))
            await jobs.mark_terminal(
                job.id, status=JobStatus.BLOCKED_CONFORMANCE, error=str(error)
            )
            return {"status": str(JobStatus.BLOCKED_CONFORMANCE), "reason": str(error)}

        await jobs.mark_terminal(job.id, status=JobStatus.SUCCEEDED)
        return {"status": str(JobStatus.SUCCEEDED), **drafted.as_row()}
