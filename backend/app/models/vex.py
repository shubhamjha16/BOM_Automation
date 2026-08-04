"""VEX statements and their CSAF exports.

`status` is a plain string column with the four values enforced in
`services/vex/authoring.py` rather than a database enum, deliberately: rec. 7.1.6
could gain a status in a future revision, and a schema migration is a worse place
to discover that than a validator. The validator is the authority and it refuses
anything outside the four.

`authored_by` and `reviewed_by` are separate columns because nothing is issued on
one person's judgement (§11) — the same rule the assessment review gate enforces.
"""

from __future__ import annotations

import uuid

from sqlalchemy import DateTime, ForeignKey, Index, String, Text, Uuid
from sqlalchemy.orm import Mapped, mapped_column

from app.models.base import Base, Timestamped, UuidPrimaryKey, jsonb, text_array


class VexStatement(UuidPrimaryKey, Timestamped, Base):
    __tablename__ = "vex_statements"
    __table_args__ = (
        Index("ix_vex_statements_submission_id_cve", "submission_id", "cve_id"),
    )

    org_id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True), ForeignKey("orgs.id", ondelete="CASCADE"), nullable=False, index=True
    )
    submission_id: Mapped[uuid.UUID | None] = mapped_column(
        Uuid(as_uuid=True), ForeignKey("submissions.id", ondelete="CASCADE"), index=True
    )
    component_ref: Mapped[str | None] = mapped_column(String(255))
    cve_id: Mapped[str] = mapped_column(String(32), nullable=False, index=True)
    #: One of the four of rec. 7.1.6, enforced by the authoring validator.
    status: Mapped[str] = mapped_column(String(24), nullable=False)
    #: Mandatory for not_affected and fixed. Never written by an agent.
    justification: Mapped[str | None] = mapped_column(Text)
    #: The analyst who made the determination. An agent never appears here.
    authored_by: Mapped[str | None] = mapped_column(String(255))
    reviewed_by: Mapped[str | None] = mapped_column(String(255))
    #: Source URLs the evidence agent assembled. Advisory, never authority.
    evidence_refs: Mapped[list[str] | None] = mapped_column(text_array())


class CsafAdvisory(UuidPrimaryKey, Timestamped, Base):
    __tablename__ = "csaf_advisories"

    org_id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True), ForeignKey("orgs.id", ondelete="CASCADE"), nullable=False, index=True
    )
    vex_statement_id: Mapped[uuid.UUID | None] = mapped_column(
        Uuid(as_uuid=True), ForeignKey("vex_statements.id", ondelete="CASCADE"), index=True
    )
    tracking_id: Mapped[str] = mapped_column(String(128), nullable=False)
    doc: Mapped[dict] = mapped_column(jsonb(), nullable=False)
    published_at: Mapped[DateTime | None] = mapped_column(DateTime(timezone=True))
