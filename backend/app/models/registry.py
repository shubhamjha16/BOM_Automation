"""The supplier registry — the curated asset, and a standing content cost (§12).

`minimum_elements` is pinned to a guideline version and changes when CERT-In
publishes. This table is different: it decays continuously as projects are
rebranded, acquired and abandoned, which is why Table 4's rationale calls for
successor links. It needs an owner and a review cadence, not a seeding task.

**The agent never writes here.** It writes `registry_proposals`, and a human
promotes one. That separation is the whole of "agents research; they never
decide" — an agent with write access to the curated asset would compound its own
mistakes into every future assessment.
"""

from __future__ import annotations

import uuid

from sqlalchemy import (
    DateTime,
    Float,
    ForeignKey,
    Index,
    String,
    Text,
    UniqueConstraint,
    Uuid,
)
from sqlalchemy.orm import Mapped, mapped_column

from app.models.base import Base, Timestamped, UuidPrimaryKey


class SupplierRegistryEntry(UuidPrimaryKey, Timestamped, Base):
    """One curated package-coordinates → supplying-organisation mapping."""

    __tablename__ = "supplier_registry_entries"
    __table_args__ = (
        # One entry per coordinate. A duplicate would make resolution
        # order-dependent, and two assessments of the same BOM could disagree.
        UniqueConstraint(
            "purl_type", "namespace_or_name", name="uq_supplier_registry_type_namespace"
        ),
        Index("ix_supplier_registry_namespace", "namespace_or_name"),
    )

    purl_type: Mapped[str] = mapped_column(String(32), nullable=False)
    #: The versionless coordinate: supplier identity belongs to the product, not
    #: the release.
    namespace_or_name: Mapped[str] = mapped_column(String(255), nullable=False)
    supplier_org: Mapped[str] = mapped_column(String(255), nullable=False)
    #: 'curated' — a human wrote it. Anything else is a proposal, not an entry.
    source: Mapped[str] = mapped_column(String(32), nullable=False, default="curated")
    confidence: Mapped[float] = mapped_column(Float, nullable=False, default=1.0)
    verified_by: Mapped[str | None] = mapped_column(String(255))
    verified_at: Mapped[DateTime | None] = mapped_column(DateTime(timezone=True))
    #: Table 4: the identifier must survive rebranding and acquisition.
    successor_id: Mapped[uuid.UUID | None] = mapped_column(
        Uuid(as_uuid=True), ForeignKey("supplier_registry_entries.id", ondelete="SET NULL")
    )
    note: Mapped[str | None] = mapped_column(Text)


class RegistryProposal(UuidPrimaryKey, Timestamped, Base):
    """An agent's proposed entry, awaiting human confirmation.

    Confirming one promotes it into `supplier_registry_entries` and permanently
    improves the curated asset for every future submission. That compounding is
    the point of the sprint.
    """

    __tablename__ = "registry_proposals"
    __table_args__ = (Index("ix_registry_proposals_status", "status"),)

    org_id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True), ForeignKey("orgs.id", ondelete="CASCADE"), nullable=False, index=True
    )
    agent_run_id: Mapped[uuid.UUID | None] = mapped_column(
        Uuid(as_uuid=True), ForeignKey("agent_runs.id", ondelete="SET NULL")
    )
    purl_type: Mapped[str] = mapped_column(String(32), nullable=False)
    namespace_or_name: Mapped[str] = mapped_column(String(255), nullable=False)
    proposed_supplier: Mapped[str] = mapped_column(String(255), nullable=False)
    confidence: Mapped[float] = mapped_column(Float, nullable=False, default=0.0)
    status: Mapped[str] = mapped_column(String(16), nullable=False, default="pending")
    reviewed_by: Mapped[str | None] = mapped_column(String(255))
    reviewed_at: Mapped[DateTime | None] = mapped_column(DateTime(timezone=True))
    reason: Mapped[str | None] = mapped_column(Text)


class IdentifierMapping(UuidPrimaryKey, Timestamped, Base):
    """One component's resolved CERT-In identifier, with how it was resolved.

    `source` is not decoration. A curated match and a namespace guess are
    different claims, and the assessment renders them differently — 4.2(21) is
    only *met* by a resolution the firm stands behind.
    """

    __tablename__ = "identifier_mappings"
    __table_args__ = (
        Index("ix_identifier_mappings_submission_id_source", "submission_id", "source"),
    )

    org_id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True), ForeignKey("orgs.id", ondelete="CASCADE"), nullable=False, index=True
    )
    submission_id: Mapped[uuid.UUID | None] = mapped_column(
        Uuid(as_uuid=True), ForeignKey("submissions.id", ondelete="CASCADE"), index=True
    )
    component_name: Mapped[str] = mapped_column(String(255), nullable=False)
    purl: Mapped[str | None] = mapped_column(String(512))
    certin_id: Mapped[str | None] = mapped_column(String(512))
    supplier_org: Mapped[str | None] = mapped_column(String(255))
    #: curated | declared_supplier | purl_namespace | proposed | unresolved
    source: Mapped[str] = mapped_column(String(24), nullable=False, default="unresolved")
    confidence: Mapped[float] = mapped_column(Float, nullable=False, default=0.0)
    reviewed_by: Mapped[str | None] = mapped_column(String(255))
