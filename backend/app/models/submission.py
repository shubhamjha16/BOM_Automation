"""A submission: one artifact with up to five BOM facets, not five jobs.

`overall_score` is nullable and stays null until the engine computes one. A
default of zero would render as "assessed, scored nothing" — indistinguishable
from a genuine total failure.
"""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import TYPE_CHECKING

from sqlalchemy import DateTime, Enum, ForeignKey, Index, Numeric, String, Uuid
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.models.base import Base, Timestamped, UuidPrimaryKey
from app.models.enums import SubmissionStatus

if TYPE_CHECKING:
    from app.models.bomDocument import BomDocument


class Submission(UuidPrimaryKey, Timestamped, Base):
    __tablename__ = "submissions"
    __table_args__ = (
        Index("ix_submissions_org_id_status", "org_id", "status"),
        Index("ix_submissions_engagement_id_created_at", "engagement_id", "created_at"),
    )

    org_id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True), ForeignKey("orgs.id", ondelete="CASCADE"), nullable=False, index=True
    )
    engagement_id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True),
        ForeignKey("engagements.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    submitted_by: Mapped[uuid.UUID | None] = mapped_column(
        Uuid(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL")
    )
    received_on: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    status: Mapped[SubmissionStatus] = mapped_column(
        Enum(
            SubmissionStatus,
            name="submission_status",
            values_callable=lambda e: [i.value for i in e],
        ),
        nullable=False,
        default=SubmissionStatus.RECEIVED,
    )
    #: Null until scored. Never defaulted to zero — see the module docstring.
    overall_score: Mapped[float | None] = mapped_column(Numeric(5, 2))
    overall_verdict: Mapped[str | None] = mapped_column(String(30))
    terminal_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))

    documents: Mapped[list[BomDocument]] = relationship(
        back_populates="submission",
        cascade="all, delete-orphan",
        # A submission carries at most five documents, so eager-loading the
        # collection on the detail view is one extra query, never a fan-out.
        lazy="selectin",
    )
