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
from collections.abc import Sequence
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
    enabled_lanes: Sequence[str] | None = None,
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

    # The engagement narrows the deployment default; it never widens it. Reading
    # it here is what makes lane_not_applicable reachable at all.
    engagement_lanes = enabled_lanes or await submissions.enabled_lanes_for(submission_id)
    lanes = list(resolve_lanes(engagement_lanes))
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


# --- read models -------------------------------------------------------------


async def list_submissions(
    submissions: SubmissionRepository, *, limit: int = 50, offset: int = 0
) -> list[Any]:
    """Newest first, with documents eager-loaded for the list view."""
    from app.schemas.response.submission import SubmissionOut

    rows = await submissions.list_recent(limit=limit, offset=offset)
    return [SubmissionOut.model_validate(row) for row in rows]


async def rejected_report(
    submissions: SubmissionRepository, lanes: Any, submission_id: uuid.UUID
) -> dict[str, Any]:
    """Every dropped entry, plus the counts that must reconcile.

    The counts are returned alongside the list so a reader can check the
    arithmetic themselves rather than taking parsed + rejected == received on
    trust.
    """
    documents = await submissions.documents_for(submission_id)
    entries = await lanes.rejected_for_submission(submission_id)
    return {
        "submission_id": str(submission_id),
        "totals": {
            "received": sum(document.entry_count for document in documents),
            "parsed": sum(document.parsed_count for document in documents),
            "rejected": sum(document.rejected_count for document in documents),
        },
        "documents": [
            {
                "id": str(document.id),
                "lane": document.lane,
                "filename": document.filename,
                "entry_count": document.entry_count,
                "parsed_count": document.parsed_count,
                "rejected_count": document.rejected_count,
                "counts_reconcile": document.counts_reconcile,
            }
            for document in documents
        ],
        "rejected": entries,
    }


async def lane_report(lanes: Any, submission_id: uuid.UUID) -> dict[str, Any]:
    results = await lanes.for_submission(submission_id)
    return {
        "submission_id": str(submission_id),
        "lanes": [
            {
                "lane": result.lane,
                "verdict": str(result.verdict),
                "score": float(result.score) if result.score is not None else None,
                "entity_count": result.entity_count,
                "detail": result.detail,
                "engine_version": result.engine_version,
                # lane_not_applicable is excluded from the overall score;
                # lane_absent is a finding. Never rendered the same way.
                "counts_toward_overall": str(result.verdict)
                not in ("lane_not_applicable", "lane_timeout"),
                "is_finding": str(result.verdict) == "lane_absent",
            }
            for result in results
        ],
    }


async def field_report(
    lanes: Any, submission_id: uuid.UUID, lane: str
) -> dict[str, Any] | None:
    results = await lanes.for_submission(submission_id)
    match = next((item for item in results if item.lane == lane), None)
    if match is None:
        return None

    verdicts = await lanes.verdicts_for(match.id)
    scored = [row for row in verdicts if str(row.verdict) != "not_determinable"]
    determined = [row for row in verdicts if str(row.verdict) == "not_determinable"]

    def shape(row: Any) -> dict[str, Any]:
        return {
            "element_key": row.element_key,
            "clause": row.clause,
            "verdict": str(row.verdict),
            "populated": row.populated,
            "total": row.total,
            "coverage": float(row.coverage) if row.coverage is not None else None,
            "detail": row.detail,
            "consumer_action": row.consumer_action,
        }

    return {
        "submission_id": str(submission_id),
        "lane": lane,
        "score": float(match.score) if match.score is not None else None,
        "verdict": str(match.verdict),
        "fields": [shape(row) for row in scored],
        # not_determinable renders in its own section, never as compliant and
        # never as a supplier defect.
        "consumer_determinations": [shape(row) for row in determined],
    }


async def correlation_report(lanes: Any, submission_id: uuid.UUID) -> dict[str, Any]:
    """Findings, plus the rule catalogue so a reader can see what was checked."""
    from app.services.correlate.engine import rule_catalogue

    findings = await lanes.findings_for(submission_id)
    return {
        "submission_id": str(submission_id),
        "findings": [
            {
                "rule_key": row.rule_key,
                "severity": row.severity,
                "clause": row.clause,
                "detail": row.detail,
                "left_ref": row.left_ref,
                "right_ref": row.right_ref,
            }
            for row in findings
        ],
        # Inspectable, as the minimum elements are: a reader can see which rules
        # exist, which are implemented, and what each one is for.
        "rules": rule_catalogue(),
    }
