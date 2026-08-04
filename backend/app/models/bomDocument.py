"""One BOM document within a submission.

**The count contract lives here.** `entry_count`, `parsed_count` and
`rejected_count` must satisfy parsed + rejected == entry_count for every
document — S6 asserts it across every fixture. Nothing is dropped silently, and
these three columns are how that claim is checked after the fact rather than
merely made at parse time.
"""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import TYPE_CHECKING

from sqlalchemy import (
    DateTime,
    Enum,
    ForeignKey,
    Integer,
    String,
    UniqueConstraint,
    Uuid,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.models.base import Base, Timestamped, UuidPrimaryKey, jsonb
from app.models.enums import BomFormat, DocumentStatus

if TYPE_CHECKING:
    from app.models.submission import Submission


class BomDocument(UuidPrimaryKey, Timestamped, Base):
    __tablename__ = "bom_documents"
    __table_args__ = (
        # Dedupes resubmissions: the same bytes submitted twice within an org is
        # the same document. Hand-added — autogenerate would not infer it (§5).
        UniqueConstraint("org_id", "checksum", name="uq_bom_documents_org_id_checksum"),
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
    lane: Mapped[str] = mapped_column(String(10), nullable=False)
    format: Mapped[BomFormat] = mapped_column(
        Enum(BomFormat, name="bom_format", values_callable=lambda e: [i.value for i in e]),
        nullable=False,
    )
    spec_version: Mapped[str | None] = mapped_column(String(20))
    #: SHA-256 over the canonicalised payload.
    checksum: Mapped[str] = mapped_column(String(64), nullable=False)
    filename: Mapped[str | None] = mapped_column(String(255))
    size_bytes: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    #: Object key once storage lands; null while documents are held inline.
    s3_key: Mapped[str | None] = mapped_column(String(512))
    #: **Interim home for the document itself.** The BOM belongs in S3 —
    #: presigned-only, SSE-KMS, per-client keys — because a BOM is an architecture
    #: disclosure and holding many suppliers' in one database column is the wrong
    #: blast radius. That move lands with the storage and encryption work in S13;
    #: until then the payload lives here so the assessment path is end-to-end real
    #: rather than stubbed. `s3_key` is the column it migrates to.
    payload: Mapped[dict | None] = mapped_column(jsonb())

    entry_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    parsed_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    rejected_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)

    doc_author: Mapped[str | None] = mapped_column(String(255))
    doc_timestamp: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    status: Mapped[DocumentStatus] = mapped_column(
        Enum(
            DocumentStatus,
            name="document_status",
            values_callable=lambda e: [i.value for i in e],
        ),
        nullable=False,
        default=DocumentStatus.RECEIVED,
    )

    submission: Mapped[Submission] = relationship(back_populates="documents")

    @property
    def counts_reconcile(self) -> bool:
        """parsed + rejected == entry_count. The S6 contract, checkable per row."""
        return self.parsed_count + self.rejected_count == self.entry_count
