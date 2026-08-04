"""The vulnerability and lifecycle knowledge base.

**One KB, one owner** (§12). `cves`, `kev_entries` and the CERT-In advisories are
needed by both this product and `cybersecurity_factory`; two independently
maintained NVD syncs is the failure mode. These tables are the local cache of a
feed somebody else is authoritative for, which is why every row carries
`synced_at` and a `source` — a stale CVE record that cannot be dated is worse
than no record, because it reads as current.
"""

from __future__ import annotations

import uuid
from datetime import date, datetime

from sqlalchemy import (
    Date,
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

from app.models.base import Base, Timestamped, UuidPrimaryKey, text_array


class Cve(UuidPrimaryKey, Timestamped, Base):
    __tablename__ = "cves"
    __table_args__ = (UniqueConstraint("cve_id", name="uq_cves_cve_id"),)

    cve_id: Mapped[str] = mapped_column(String(32), nullable=False)
    published: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    modified: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    description: Mapped[str | None] = mapped_column(Text)
    cvss_v31_vector: Mapped[str | None] = mapped_column(String(128))
    cvss_v31_score: Mapped[float | None] = mapped_column(Float)
    cwe_ids: Mapped[list[str] | None] = mapped_column(text_array())
    #: When this row was last refreshed from NVD. Never null on a real row.
    synced_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


class KevEntry(UuidPrimaryKey, Timestamped, Base):
    """CISA Known Exploited Vulnerabilities.

    Separate from `cves` because KEV membership is a different claim from
    "a CVE exists": it means exploitation has been observed in the wild, which is
    what makes `vexCoverage` (rec. 7.1.6) a critical-severity finding.
    """

    __tablename__ = "kev_entries"
    __table_args__ = (UniqueConstraint("cve_id", name="uq_kev_entries_cve_id"),)

    cve_id: Mapped[str] = mapped_column(String(32), nullable=False, index=True)
    vendor_project: Mapped[str | None] = mapped_column(String(255))
    product: Mapped[str | None] = mapped_column(String(255))
    added_on: Mapped[date | None] = mapped_column(Date)
    due_date: Mapped[date | None] = mapped_column(Date)
    known_ransomware: Mapped[str | None] = mapped_column(String(32))
    synced_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


class EolRecord(UuidPrimaryKey, Timestamped, Base):
    """Lifecycle data for 4.2(11), keyed by product and release cycle."""

    __tablename__ = "eol_records"
    __table_args__ = (
        UniqueConstraint("product_key", "cycle", name="uq_eol_records_product_cycle"),
        Index("ix_eol_records_product_key", "product_key"),
    )

    product_key: Mapped[str] = mapped_column(String(128), nullable=False)
    cycle: Mapped[str] = mapped_column(String(64), nullable=False)
    eol_date: Mapped[date | None] = mapped_column(Date)
    support_end: Mapped[date | None] = mapped_column(Date)
    latest_version: Mapped[str | None] = mapped_column(String(64))
    release_date: Mapped[date | None] = mapped_column(Date)
    #: 'endoflife.date', or 'agent' where the S10 loop resolved it. The
    #: distinction is reported: an agent-sourced date is reviewed, not trusted.
    source: Mapped[str] = mapped_column(String(32), nullable=False, default="endoflife.date")
    synced_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


class Advisory(UuidPrimaryKey, Timestamped, Base):
    """CERT-In vulnerability notes and vendor advisories, per rec. 7.1.7."""

    __tablename__ = "advisories"
    __table_args__ = (UniqueConstraint("source", "ref", name="uq_advisories_source_ref"),)

    source: Mapped[str] = mapped_column(String(32), nullable=False)
    ref: Mapped[str] = mapped_column(String(128), nullable=False)
    title: Mapped[str | None] = mapped_column(Text)
    url: Mapped[str | None] = mapped_column(String(512))
    published: Mapped[date | None] = mapped_column(Date)
    cve_ids: Mapped[list[str] | None] = mapped_column(text_array())
    synced_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


class AgentRun(UuidPrimaryKey, Timestamped, Base):
    """One bounded agentic loop.

    Persisted so the cost and hop table the sprint exits on is a query rather
    than a claim, and so `hop_budget_exhausted` is visible as a distinct outcome
    from `insufficient` — the first is "we ran out of budget", the second is
    "what we found did not support a determination".
    """

    __tablename__ = "agent_runs"
    __table_args__ = (Index("ix_agent_runs_submission_id_kind", "submission_id", "kind"),)

    org_id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True), ForeignKey("orgs.id", ondelete="CASCADE"), nullable=False, index=True
    )
    submission_id: Mapped[uuid.UUID | None] = mapped_column(
        Uuid(as_uuid=True), ForeignKey("submissions.id", ondelete="CASCADE"), index=True
    )
    kind: Mapped[str] = mapped_column(String(24), nullable=False)
    #: The distinct product this run was batched under — never a component id.
    batch_key: Mapped[str] = mapped_column(String(255), nullable=False)
    hops: Mapped[int] = mapped_column(nullable=False, default=0)
    verdict: Mapped[str] = mapped_column(String(32), nullable=False)
    tokens: Mapped[int] = mapped_column(nullable=False, default=0)
    inr_cost: Mapped[float] = mapped_column(Float, nullable=False, default=0.0)


class AgentEvidence(UuidPrimaryKey, Timestamped, Base):
    """Every agentic output is evidenced or it does not ship (§11)."""

    __tablename__ = "agent_evidence"

    agent_run_id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True),
        ForeignKey("agent_runs.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    hop: Mapped[int] = mapped_column(nullable=False, default=0)
    query: Mapped[str | None] = mapped_column(Text)
    source_url: Mapped[str | None] = mapped_column(String(512))
    snippet: Mapped[str | None] = mapped_column(Text)
    supports: Mapped[bool] = mapped_column(nullable=False, default=False)
    confidence: Mapped[float | None] = mapped_column(Float)
