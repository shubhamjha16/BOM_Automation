"""Job read models."""

from __future__ import annotations

import uuid
from collections.abc import AsyncIterator

from sqlalchemy import select

from app.models.job import NodeRun
from app.repositories.jobRepository import JobRepository
from app.schemas.response.job import JobDetailOut, JobOut, NodeRunOut


async def list_jobs(
    jobs: JobRepository, *, limit: int = 50, offset: int = 0
) -> list[JobOut]:
    rows = await jobs.list(limit=limit, offset=offset)
    return [JobOut.model_validate(row) for row in rows]


async def get_job(jobs: JobRepository, job_id: uuid.UUID) -> JobDetailOut | None:
    job = await jobs.get(job_id)
    if job is None:
        return None
    # Reads through the repository's session; the org check already happened on
    # the parent job, and node_runs are reachable only through it.
    result = await jobs.session.execute(
        select(NodeRun).where(NodeRun.job_id == job.id).order_by(NodeRun.started_at)
    )
    detail = JobDetailOut.model_validate(job)
    detail.node_runs = [NodeRunOut.model_validate(row) for row in result.scalars().all()]
    return detail


async def progress_stream(
    jobs: JobRepository, job_id: uuid.UUID
) -> AsyncIterator[str] | None:
    """SSE frames for one job, replayed from its persisted node runs."""
    from app.services.progressStream import stream

    job = await jobs.get(job_id)
    if job is None:
        return None
    result = await jobs.session.execute(
        select(NodeRun).where(NodeRun.job_id == job.id).order_by(NodeRun.started_at)
    )
    return stream(job, list(result.scalars().all()))
