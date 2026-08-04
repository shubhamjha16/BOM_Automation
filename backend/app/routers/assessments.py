"""Assessment rendering and export endpoints."""

from __future__ import annotations

from uuid import UUID

from fastapi import APIRouter, HTTPException, Query
from fastapi.responses import Response

from app.controllers import assessmentController as controller
from app.routers.deps import LaneRepoDep, SubmissionRepoDep

router = APIRouter(prefix="/assessments", tags=["assessments"])


@router.get("/{submission_id}")
async def render(
    submission_id: UUID, submissions: SubmissionRepoDep, lanes: LaneRepoDep
) -> dict:
    """The assessment's sections, each carrying what it was written from."""
    if await submissions.get(submission_id) is None:
        raise HTTPException(404, "submission not found")
    return await controller.render(lanes, submission_id)


@router.get("/{submission_id}/export")
async def export(
    submission_id: UUID,
    submissions: SubmissionRepoDep,
    lanes: LaneRepoDep,
    format: str = Query("json", pattern="^(json|xlsx|docx|pdf)$"),
) -> Response:
    if await submissions.get(submission_id) is None:
        raise HTTPException(404, "submission not found")
    body, media_type, filename = await controller.export(lanes, submission_id, fmt=format)
    return Response(
        content=body,
        media_type=media_type,
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )
