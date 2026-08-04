"""Persisted cross-BOM findings.

Stored beside field verdicts because they reach the reader the same way: a clause
reference, a severity and a sentence. The assessment does not distinguish "a
field was absent" from "two documents disagree" in how it must be traced — both
pass the conformance gate, both cite the guideline.
"""

from __future__ import annotations

import uuid

from sqlalchemy import ForeignKey, Index, String, Text, Uuid
from sqlalchemy.orm import Mapped, mapped_column

from app.models.base import Base, Timestamped, UuidPrimaryKey


class CorrelationFindingRow(UuidPrimaryKey, Timestamped, Base):
    __tablename__ = "correlation_findings"
    __table_args__ = (
        Index("ix_correlation_findings_submission_id_rule", "submission_id", "rule_key"),
    )

    org_id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True), ForeignKey("orgs.id", ondelete="CASCADE"), nullable=False, index=True
    )
    submission_id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True),
        ForeignKey("submissions.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    rule_key: Mapped[str] = mapped_column(String(64), nullable=False)
    severity: Mapped[str] = mapped_column(String(10), nullable=False)
    #: Cited exactly as a field verdict cites one, and gated the same way.
    clause: Mapped[str] = mapped_column(String(32), nullable=False)
    detail: Mapped[str] = mapped_column(Text, nullable=False)
    left_ref: Mapped[str | None] = mapped_column(String(255))
    right_ref: Mapped[str | None] = mapped_column(String(255))
