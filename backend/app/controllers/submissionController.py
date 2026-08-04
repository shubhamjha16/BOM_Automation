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
from dataclasses import dataclass
from typing import Any

from app.configs.laneConfig import resolve_lanes
from app.models.enums import BomFormat
from app.repositories.jobRepository import JobRepository
from app.repositories.submissionRepository import SubmissionRepository
from app.services.assessmentService import lane_rollup
from app.services.queueService import enqueue_assessment, run_inline
from app.utils.logger import get_logger
from app.validators.submissionValidator import validate_submission

logger = get_logger(__name__)


@dataclass(frozen=True, slots=True)
class CommitResult:
    job_id: uuid.UUID
    status: str
    #: False when an identical document set was already submitted inside the
    #: idempotency window. The same job_id is returned either way.
    created: bool
    queued: bool

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
    enabled_lanes: list[str] | None = None,
    user_id: uuid.UUID | None = None,
    inline: bool = False,
) -> CommitResult | None:
    """Finalise a submission and enqueue its assessment.

    Returns the job, never the assessment: the work is asynchronous, and a
    handler that waited for it would tie a 50,000-component scoring run to an
    HTTP timeout. Callers poll `GET /jobs/{id}`.

    `inline=True` runs the same task function in-process — for single-process
    development and tests, not a second code path.
    """
    submission = await submissions.get_with_documents(submission_id)
    if submission is None:
        return None

    lanes = enabled_lanes or list(resolve_lanes())
    result = await enqueue_assessment(
        jobs,
        submission_id=submission.id,
        engagement_id=submission.engagement_id,
        document_checksums=[document.checksum for document in submission.documents],
        enabled_lanes=lanes,
        user_id=user_id,
        inline=inline,
    )

    if inline and result.created:
        await run_inline(
            submissions.session, submissions.org_id, submission.id, result.job.id
        )

    return CommitResult(
        job_id=result.job.id,
        status=str(result.job.status),
        created=result.created,
        queued=result.queued,
    )


def rollup_response(summary: Any) -> list[dict[str, Any]]:
    return [
        {"lane": lane, **detail} for lane, detail in sorted(lane_rollup(summary).items())
    ]
