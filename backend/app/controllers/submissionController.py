"""Submission orchestration: validate → persist → (commit) assess.

The layering rule this sprint establishes: **routers do HTTP, controllers do
orchestration, services do work, repositories do SQL.** A controller never
touches a `select()` and a router never touches a controller's internals, so
adding an endpoint cannot accidentally add a query that forgets its org scope.
"""

from __future__ import annotations

import hashlib
import json
import uuid
from typing import Any

from app.configs.jobTypes import JobType
from app.models.enums import BomFormat, SubmissionStatus
from app.repositories.jobRepository import JobRepository
from app.repositories.submissionRepository import SubmissionRepository
from app.services.assessmentService import lane_rollup, run_assessment
from app.services.graph.state import SubmissionDocument
from app.services.jobService import persist_summary
from app.utils.logger import get_logger
from app.validators.submissionValidator import validate_submission

logger = get_logger(__name__)


def checksum_of(payload: dict[str, Any]) -> str:
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canonical.encode()).hexdigest()


def _sizeof(payload: dict[str, Any]) -> int:
    return len(json.dumps(payload, separators=(",", ":")).encode())


def _entry_count(payload: dict[str, Any]) -> int:
    """Declared entries in the document, before any parsing.

    Recorded at receipt so the S6 contract — parsed + rejected == entry_count —
    has a number to reconcile against that the parser did not itself produce.
    """
    for key in ("components", "packages"):
        if isinstance(entries := payload.get(key), list):
            return len(entries)
    return 0


async def create_submission(
    submissions: SubmissionRepository,
    *,
    engagement_id: uuid.UUID,
    documents: list[dict[str, Any]],
    submitted_by: uuid.UUID | None = None,
) -> Any:
    """Validate and persist. Raises `SubmissionInvalid`, mapped to 422 upstream."""
    enriched = [
        {
            **document,
            "checksum": checksum_of(document["payload"]),
            "size_bytes": _sizeof(document["payload"]),
        }
        for document in documents
    ]
    validate_submission(engagement_id=str(engagement_id), documents=enriched)

    submission = await submissions.create(
        engagement_id=engagement_id, submitted_by=submitted_by
    )
    for document in enriched:
        await submissions.add_document(
            submission,
            lane=document["lane"],
            format=BomFormat(document["format"]),
            checksum=document["checksum"],
            size_bytes=document["size_bytes"],
            spec_version=document.get("spec_version"),
            filename=document.get("filename"),
            entry_count=_entry_count(document["payload"]),
            payload=document["payload"],
        )

    logger.info(
        "submission_created",
        submission_id=str(submission.id),
        documents=len(enriched),
        lanes=sorted({document["lane"] for document in enriched}),
    )
    return submission


async def commit_submission(
    submissions: SubmissionRepository,
    jobs: JobRepository,
    *,
    submission_id: uuid.UUID,
) -> Any:
    """Finalise a submission and run its assessment.

    S4 moves the execution onto arq; the job row is already created first here,
    so that change is a swap of one call rather than a restructure — and a crash
    mid-assessment already leaves a reconcilable row today.
    """
    submission = await submissions.get_with_documents(submission_id)
    if submission is None:
        return None

    job = await jobs.create(
        job_type=JobType.ASSESS_SUBMISSION,
        engagement_id=submission.engagement_id,
        submission_id=submission.id,
    )
    await jobs.mark_running(job.id)

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
        org_id=str(submissions.org_id),
        submission_id=str(submission.id),
        documents=documents,
        job_id=str(job.id),
    )
    await persist_summary(jobs, job.id, summary)
    await submissions.set_status(
        submission.id,
        SubmissionStatus.SCORED,
        overall_score=summary.overall_score,
    )
    return summary


def rollup_response(summary: Any) -> list[dict[str, Any]]:
    return [
        {"lane": lane, **detail} for lane, detail in sorted(lane_rollup(summary).items())
    ]
