"""Assessments, their versions and their sections.

**`assessment_sections` is the provenance chain.** Each section records the field
verdicts and correlation findings it was written from, so
`GET /assessments/{id}/provenance` can answer "what is this sentence based on?"
with rows rather than an assurance. That is the claim the product rests on: every
statement traces to a verdict, and every verdict to the BOM entry behind it.

`status` gates issuance. An assessment reaches `issued` only through the review
gate in `services/access/authz.py`, and the assessor who ran it cannot be the
approver however senior they are.
"""

from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import DateTime, ForeignKey, Index, Integer, String, Text, Uuid
from sqlalchemy.orm import Mapped, mapped_column

from app.models.base import Base, Timestamped, UuidPrimaryKey, text_array


class Assessment(UuidPrimaryKey, Timestamped, Base):
    __tablename__ = "assessments"
    __table_args__ = (Index("ix_assessments_org_id_status", "org_id", "status"),)

    org_id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True), ForeignKey("orgs.id", ondelete="CASCADE"), nullable=False, index=True
    )
    submission_id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True),
        ForeignKey("submissions.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    title: Mapped[str] = mapped_column(String(255), nullable=False)
    #: draft | in_review | approved | issued
    status: Mapped[str] = mapped_column(String(16), nullable=False, default="draft")
    #: The assessor who ran it. Recorded so the approver can be checked against it.
    authored_by: Mapped[uuid.UUID | None] = mapped_column(
        Uuid(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL")
    )
    reviewed_by: Mapped[uuid.UUID | None] = mapped_column(
        Uuid(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL")
    )
    approved_by: Mapped[uuid.UUID | None] = mapped_column(
        Uuid(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL")
    )
    s3_key: Mapped[str | None] = mapped_column(String(512))
    current_version: Mapped[int] = mapped_column(Integer, nullable=False, default=1)
    issued_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


class AssessmentSection(UuidPrimaryKey, Timestamped, Base):
    """One section, and the verdicts it was written from."""

    __tablename__ = "assessment_sections"
    __table_args__ = (Index("ix_assessment_sections_assessment_id_ord", "assessment_id", "ord"),)

    org_id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True), ForeignKey("orgs.id", ondelete="CASCADE"), nullable=False, index=True
    )
    assessment_id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True),
        ForeignKey("assessments.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    ord: Mapped[int] = mapped_column(Integer, nullable=False)
    section_type: Mapped[str] = mapped_column(String(48), nullable=False)
    content: Mapped[str | None] = mapped_column(Text)
    #: The provenance chain. A section citing neither is a section nobody can check.
    field_verdict_ids: Mapped[list[str] | None] = mapped_column(text_array())
    correlation_finding_ids: Mapped[list[str] | None] = mapped_column(text_array())
