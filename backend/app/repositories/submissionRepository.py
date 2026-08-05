"""Submission and BOM document persistence, org-scoped like everything else."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime

from sqlalchemy import select
from sqlalchemy.orm import selectinload

from app.models.bomDocument import BomDocument
from app.models.engagement import Engagement
from app.models.enums import BomFormat, DocumentStatus, SubmissionStatus
from app.models.submission import Submission
from app.repositories.base import TenantScopedRepository


class SubmissionRepository(TenantScopedRepository[Submission]):
    model = Submission

    async def create(
        self,
        *,
        engagement_id: uuid.UUID,
        submitted_by: uuid.UUID | None = None,
    ) -> Submission:
        return await self.add(
            Submission(
                org_id=self.org_id,
                engagement_id=engagement_id,
                submitted_by=submitted_by,
                received_on=datetime.now(UTC),
                status=SubmissionStatus.RECEIVED,
                # Initialise the collection explicitly. Without it the flush below
                # makes the row persistent with `documents` unloaded, and the first
                # append would emit a lazy SELECT from sync context.
                documents=[],
            )
        )

    async def add_document(
        self,
        submission: Submission,
        *,
        lane: str,
        format: BomFormat,
        checksum: str,
        size_bytes: int,
        spec_version: str | None = None,
        filename: str | None = None,
        entry_count: int = 0,
        payload: dict | None = None,
    ) -> BomDocument:
        document = BomDocument(
            org_id=self.org_id,
            submission_id=submission.id,
            lane=lane,
            format=format,
            spec_version=spec_version,
            checksum=checksum,
            filename=filename,
            size_bytes=size_bytes,
            entry_count=entry_count,
            payload=payload,
            status=DocumentStatus.RECEIVED,
        )
        # Append through the relationship rather than session.add(): writing only
        # the foreign key leaves the parent's in-memory collection empty, and
        # serialising the submission then triggers a lazy load from sync context
        # (MissingGreenlet). Appending keeps both sides in agreement.
        submission.documents.append(document)
        await self.session.flush()
        return document

    async def list_recent(self, *, limit: int = 50, offset: int = 0) -> list[Submission]:
        """Newest first. Documents come along via the selectin relationship, so
        the list view does not fan out one query per row."""
        result = await self.session.execute(
            self.scoped()
            .order_by(Submission.created_at.desc())
            .limit(limit)
            .offset(offset)
        )
        return list(result.scalars().all())

    async def get_with_documents(self, submission_id: uuid.UUID) -> Submission | None:
        """Eager-loads documents: the detail view always renders them, and a lazy
        load here would be an N+1 across a five-document submission."""
        result = await self.session.execute(
            self.scoped()
            .where(Submission.id == submission_id)
            .options(selectinload(Submission.documents))
        )
        return result.scalar_one_or_none()

    async def documents_for(self, submission_id: uuid.UUID) -> list[BomDocument]:
        result = await self.session.execute(
            select(BomDocument)
            .where(BomDocument.org_id == self.org_id)
            .where(BomDocument.submission_id == submission_id)
            .order_by(BomDocument.created_at)
        )
        return list(result.scalars().all())

    async def enabled_lanes_for(self, submission_id: uuid.UUID) -> list[str] | None:
        """The engagement's enabled lanes, or None when it names none.

        This is what makes `lane_not_applicable` reachable. Without it the
        engagement's own column is decoration: every lane runs on every
        submission and a client with no quantum hardware sees a zero-scoring
        empty QBOM lane, which §11 is explicit is the wrong answer.
        """
        result = await self.session.execute(
            select(Engagement.enabled_lanes)
            .join(Submission, Submission.engagement_id == Engagement.id)
            .where(Submission.id == submission_id)
            .where(Submission.org_id == self.org_id)
        )
        lanes = result.scalar_one_or_none()
        return list(lanes) if lanes else None

    async def find_by_checksum(self, checksum: str) -> BomDocument | None:
        """Backed by `uq_bom_documents_org_id_checksum`.

        Identical bytes within one org is the same document — a supplier
        re-sending an unchanged BOM should not create a second one that scores
        separately and appears as a distinct submission in the estate view.
        """
        result = await self.session.execute(
            select(BomDocument)
            .where(BomDocument.org_id == self.org_id)
            .where(BomDocument.checksum == checksum)
        )
        return result.scalars().first()

    async def set_status(
        self,
        submission_id: uuid.UUID,
        status: SubmissionStatus,
        *,
        overall_score: float | None = None,
        overall_verdict: str | None = None,
    ) -> Submission | None:
        submission = await self.get(submission_id)
        if submission is None:
            return None
        submission.status = status
        if overall_score is not None:
            submission.overall_score = overall_score
        if overall_verdict is not None:
            submission.overall_verdict = overall_verdict
        await self.session.flush()
        return submission
