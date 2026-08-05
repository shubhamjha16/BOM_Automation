"""Enqueueing, with idempotency, and a synchronous fallback.

`enqueue_assessment` is the only place that decides whether work runs on the
queue or inline. Two reasons that decision lives here rather than in the
controller:

* **The idempotency check and the enqueue must not drift apart.** They are one
  operation — find or create — and splitting them across layers invites a second
  caller that creates without checking.
* **Tests and single-process development need inline execution**, and that must
  not mean a different code path for the actual assessment. Both branches call
  the same task function.
"""

from __future__ import annotations

import uuid
from collections.abc import Sequence
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any

from arq import create_pool
from arq.connections import RedisSettings

from app.configs.envConfig import settings
from app.configs.jobTypes import JobType
from app.models.job import Job
from app.repositories.jobRepository import JobRepository
from app.utils.idempotency import DEFAULT_WINDOW_SECONDS, idempotency_key
from app.utils.logger import get_logger

logger = get_logger(__name__)


@dataclass(frozen=True, slots=True)
class EnqueueResult:
    job: Job
    #: False when an existing job inside the idempotency window was returned.
    #: The caller reports the same job_id either way — that is the contract.
    created: bool
    queued: bool


async def find_or_create_job(
    jobs: JobRepository,
    *,
    submission_id: uuid.UUID,
    engagement_id: uuid.UUID,
    document_checksums: list[str],
    enabled_lanes: Sequence[str],
    user_id: uuid.UUID | None = None,
    window_seconds: int = DEFAULT_WINDOW_SECONDS,
) -> tuple[Job, bool]:
    """Return the existing job for this document set, or create one."""
    key = idempotency_key(
        org_id=str(jobs.org_id),
        document_checksums=document_checksums,
        enabled_lanes=enabled_lanes,
    )

    existing = await jobs.find_by_idempotency_key(key)
    if existing is not None:
        age = datetime.now(UTC) - existing.created_at.replace(tzinfo=UTC)
        if age < timedelta(seconds=window_seconds):
            logger.info(
                "idempotent_hit",
                job_id=str(existing.id),
                age_seconds=int(age.total_seconds()),
            )
            return existing, False
        # Outside the window the same documents are a deliberate re-assessment.
        # The key is unique, so the old job's key is released to let it through.
        existing.idempotency_key = None
        await jobs.session.flush()

    job = await jobs.create(
        job_type=JobType.ASSESS_SUBMISSION,
        engagement_id=engagement_id,
        submission_id=submission_id,
        user_id=user_id,
        idempotency_key=key,
    )
    return job, True


async def enqueue_assessment(
    jobs: JobRepository,
    *,
    submission_id: uuid.UUID,
    engagement_id: uuid.UUID,
    document_checksums: list[str],
    enabled_lanes: Sequence[str],
    user_id: uuid.UUID | None = None,
    inline: bool | None = None,
) -> EnqueueResult:
    """Find or create the job, then hand it to the queue.

    `inline=True` runs the task in-process. The task function is identical, so
    inline execution is not a second implementation that can drift.
    """
    job, created = await find_or_create_job(
        jobs,
        submission_id=submission_id,
        engagement_id=engagement_id,
        document_checksums=document_checksums,
        enabled_lanes=enabled_lanes,
        user_id=user_id,
    )
    if not created:
        # One job_id, one execution. Do not enqueue a second time.
        return EnqueueResult(job=job, created=False, queued=False)

    if inline:
        return EnqueueResult(job=job, created=True, queued=False)

    try:
        pool = await create_pool(RedisSettings.from_dsn(settings.REDIS_URL))
    except Exception as error:  # noqa: BLE001 - the queue being down is reportable
        logger.error("enqueue_failed", job_id=str(job.id), error=str(error))
        raise

    try:
        # `_job_id` makes arq itself reject a duplicate delivery of the same job,
        # so idempotency holds even if this function is called twice.
        await pool.enqueue_job(
            "run_assessment_task",
            str(jobs.org_id),
            str(submission_id),
            str(job.id),
            _job_id=str(job.id),
        )
    finally:
        await pool.aclose()

    logger.info("assessment_enqueued", job_id=str(job.id), submission_id=str(submission_id))
    return EnqueueResult(job=job, created=True, queued=True)


async def run_inline(
    session: Any, org_id: uuid.UUID, submission_id: uuid.UUID, job_id: uuid.UUID
) -> Any:
    """Execute the task in-process, through the same function the worker calls.

    The caller's session is passed through rather than a new one being opened:
    inline execution happens inside the request's transaction, and a second
    session would be a second connection that cannot see the job just written.
    """
    from app.workers.tasks import run_assessment_task

    return await run_assessment_task(
        {"session": session}, str(org_id), str(submission_id), str(job_id)
    )
