"""Every input entry, kept.

`GET /submissions/{id}/rejected` reads this table. Persisting rejections rather
than only logging them is what makes "nothing is dropped silently" answerable
after the fact: a supplier asking "why does your report say 380 components when I
sent 400?" gets twenty rows with reasons, not a shrug.

Only rejected entries are stored. Parsed ones are already represented by the
scored entity, and duplicating a 50,000-component BOM into a second table would
double the storage for no additional answer.
"""

from __future__ import annotations

import uuid

from sqlalchemy import ForeignKey, Index, Integer, String, Text, Uuid
from sqlalchemy.orm import Mapped, mapped_column

from app.models.base import Base, Timestamped, UuidPrimaryKey, jsonb


class RawEntry(UuidPrimaryKey, Timestamped, Base):
    __tablename__ = "raw_entries"
    __table_args__ = (
        # The rejected list is always read per document, in document order.
        Index("ix_raw_entries_bom_document_id_ord", "bom_document_id", "ord"),
    )

    org_id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True), ForeignKey("orgs.id", ondelete="CASCADE"), nullable=False, index=True
    )
    bom_document_id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True),
        ForeignKey("bom_documents.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    #: Position in the source document, so a supplier can find the entry.
    ord: Mapped[int] = mapped_column(Integer, nullable=False)
    parse_status: Mapped[str] = mapped_column(String(20), nullable=False, default="rejected")
    #: Written for the supplier who has to fix it, not for us.
    reason: Mapped[str] = mapped_column(Text, nullable=False)
    #: bom-ref, SPDXID or purl where the entry had one.
    ref: Mapped[str | None] = mapped_column(String(255))
    payload: Mapped[dict | None] = mapped_column(jsonb())
