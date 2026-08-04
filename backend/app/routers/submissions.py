"""Submission endpoints. Handlers do HTTP and nothing else — no SQL, no rules."""

from __future__ import annotations

from uuid import UUID

from fastapi import APIRouter, HTTPException, status

from app.configs.envConfig import settings
from app.controllers import submissionController as controller
from app.routers.deps import JobRepoDep, LaneRepoDep, SubmissionRepoDep
from app.schemas.request.submission import SubmissionCreate
from app.schemas.response.submission import SubmissionDetailOut, SubmissionOut

router = APIRouter(prefix="/submissions", tags=["submissions"])


@router.post("", response_model=SubmissionOut, status_code=status.HTTP_201_CREATED)
async def create(body: SubmissionCreate, submissions: SubmissionRepoDep) -> SubmissionOut:
    submission = await controller.create_submission(
        submissions,
        engagement_id=body.engagement_id,
        documents=[document.model_dump() for document in body.documents],
    )
    return SubmissionOut.model_validate(submission)


@router.get("/{submission_id}", response_model=SubmissionDetailOut)
async def get(submission_id: UUID, submissions: SubmissionRepoDep) -> SubmissionDetailOut:
    submission = await submissions.get_with_documents(submission_id)
    if submission is None:
        raise HTTPException(404, "submission not found")
    return SubmissionDetailOut.model_validate(submission)


@router.post("/{submission_id}/commit")
async def commit(
    submission_id: UUID, submissions: SubmissionRepoDep, jobs: JobRepoDep
) -> dict:
    result = await controller.commit_submission(
        submissions, jobs, submission_id=submission_id, inline=settings.JOBS_INLINE
    )
    if result is None:
        raise HTTPException(404, "submission not found")
    return {
        "job_id": str(result.job_id),
        "status": result.status,
        "created": result.created,
        "queued": result.queued,
    }


@router.get("/{submission_id}/rejected")
async def rejected(
    submission_id: UUID, submissions: SubmissionRepoDep, lanes: LaneRepoDep
) -> dict:
    """Every entry the parsers refused, with an actionable reason.

    Nothing is dropped silently: this is the answer to "why does your report say
    380 components when I sent 400?".
    """
    if await submissions.get(submission_id) is None:
        raise HTTPException(404, "submission not found")
    return await controller.rejected_report(submissions, lanes, submission_id)


@router.get("/{submission_id}/lanes")
async def lanes_for(
    submission_id: UUID, submissions: SubmissionRepoDep, lanes: LaneRepoDep
) -> dict:
    """Five lane results side by side."""
    if await submissions.get(submission_id) is None:
        raise HTTPException(404, "submission not found")
    return await controller.lane_report(lanes, submission_id)


@router.get("/{submission_id}/lanes/{lane}/fields")
async def fields_for(
    submission_id: UUID, lane: str, submissions: SubmissionRepoDep, lanes: LaneRepoDep
) -> dict:
    """Field verdicts with their clause references, and the consumer
    determinations in their own section."""
    if await submissions.get(submission_id) is None:
        raise HTTPException(404, "submission not found")
    report = await controller.field_report(lanes, submission_id, lane)
    if report is None:
        raise HTTPException(404, f"no {lane} result for this submission")
    return report


@router.get("/{submission_id}/correlations")
async def correlations(
    submission_id: UUID, submissions: SubmissionRepoDep, lanes: LaneRepoDep
) -> dict:
    """Cross-BOM findings — the class of result no single-lane tool can produce.

    Also reports which rules ran and which could not, because "found nothing" and
    "did not run" are different answers.
    """
    if await submissions.get(submission_id) is None:
        raise HTTPException(404, "submission not found")
    return await controller.correlation_report(lanes, submission_id)
