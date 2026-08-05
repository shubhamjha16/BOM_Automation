"""Job endpoints.

`/jobs/{id}` exists so a killed worker's job is visible rather than vanished, and
`node_runs` is exposed because overlapping lane intervals are the evidence the
fan-out ran concurrently. S18 adds the SSE event stream on top.
"""

from __future__ import annotations

from uuid import UUID

from fastapi import APIRouter, HTTPException
from fastapi.responses import StreamingResponse

from app.controllers import jobController as controller
from app.routers.deps import JobRepoDep
from app.schemas.response.job import JobDetailOut, JobOut

router = APIRouter(prefix="/jobs", tags=["jobs"])


@router.get("", response_model=list[JobOut])
async def list_jobs(jobs: JobRepoDep, limit: int = 50, offset: int = 0) -> list[JobOut]:
    return await controller.list_jobs(jobs, limit=limit, offset=offset)


@router.get("/{job_id}", response_model=JobDetailOut)
async def get_job(job_id: UUID, jobs: JobRepoDep) -> JobDetailOut:
    detail = await controller.get_job(jobs, job_id)
    if detail is None:
        raise HTTPException(404, "job not found")
    return detail


@router.get("/{job_id}/events")
async def job_events(job_id: UUID, jobs: JobRepoDep) -> StreamingResponse:
    """Per-lane progress as SSE. Five tracks, not one spinner."""
    stream = await controller.progress_stream(jobs, job_id)
    if stream is None:
        raise HTTPException(404, "job not found")
    return StreamingResponse(stream, media_type="text/event-stream")
