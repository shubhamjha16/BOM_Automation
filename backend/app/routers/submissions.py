"""Submission endpoints. Handlers do HTTP and nothing else — no SQL, no rules."""

from __future__ import annotations

from uuid import UUID

from fastapi import APIRouter, HTTPException, status

from app.controllers import submissionController as controller
from app.routers.deps import JobRepoDep, SubmissionRepoDep
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
    summary = await controller.commit_submission(
        submissions, jobs, submission_id=submission_id
    )
    if summary is None:
        raise HTTPException(404, "submission not found")
    return {
        "job_id": summary.job_id,
        "status": str(summary.status),
        "overall_score": summary.overall_score,
        "lanes": controller.rollup_response(summary),
    }
