"""Jobs. There is no `jobs.json` and there will not be one.

The sibling factories keep job state in a file written by a `threading.Thread`.
That loses every job on restart, cannot be queried, cannot be scoped to a tenant,
and races itself under concurrency. A job here is a row.

**Terminal finality.** `terminal_at` is set exactly once, when the job reaches a
terminal status. After that, `status` is immutable — enforced in
`repositories/jobRepository.py` as a conditional UPDATE, and backed by the
partial index below so the reconciler's "what is still running?" query stays
cheap as the table grows.
"""

from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import DateTime, Enum, ForeignKey, Index, String, Text, Uuid, text
from sqlalchemy.orm import Mapped, mapped_column

from app.models.base import Base, Timestamped, UuidPrimaryKey, jsonb
from app.models.enums import JobStatus, JobType


class Job(UuidPrimaryKey, Timestamped, Base):
    __tablename__ = "jobs"
    __table_args__ = (
        # Composite, org first: every query is tenant-scoped, so a bare index on
        # status would be scanned across tenants and then filtered.
        Index("ix_jobs_org_id_status", "org_id", "status"),
        # Partial index over live jobs only. This is the reconciler's query after
        # a crash, and the table it runs against is mostly terminal rows forever.
        # Autogenerate will not produce this — it is hand-added, per §5.
        Index(
            "ix_jobs_live",
            "org_id",
            "created_at",
            postgresql_where=text("terminal_at IS NULL"),
            sqlite_where=text("terminal_at IS NULL"),
        ),
    )

    org_id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True), ForeignKey("orgs.id", ondelete="CASCADE"), nullable=False, index=True
    )
    user_id: Mapped[uuid.UUID | None] = mapped_column(
        Uuid(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL")
    )
    engagement_id: Mapped[uuid.UUID | None] = mapped_column(
        Uuid(as_uuid=True), ForeignKey("engagements.id", ondelete="CASCADE"), index=True
    )
    #: Set once the submission row exists (S3). Nullable because a job is created
    #: at enqueue time, which is before ingestion has produced anything.
    submission_id: Mapped[uuid.UUID | None] = mapped_column(Uuid(as_uuid=True), index=True)

    job_type: Mapped[JobType] = mapped_column(
        Enum(JobType, name="job_type", values_callable=lambda e: [i.value for i in e]),
        nullable=False,
    )
    status: Mapped[JobStatus] = mapped_column(
        Enum(JobStatus, name="job_status", values_callable=lambda e: [i.value for i in e]),
        nullable=False,
        default=JobStatus.QUEUED,
    )
    instructions: Mapped[dict | None] = mapped_column(jsonb())

    #: SHA-256 of document checksums + enabled lanes + org_id (S4). Unique, so a
    #: double-submitted document set returns one job_id and executes once.
    idempotency_key: Mapped[str | None] = mapped_column(String(64), unique=True)

    error: Mapped[str | None] = mapped_column(Text)
    #: Non-null exactly when the job has finished. The finality guard reads this.
    terminal_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))

    @property
    def is_terminal(self) -> bool:
        return self.terminal_at is not None


class NodeRun(UuidPrimaryKey, Timestamped, Base):
    """One node execution within a job.

    Persisting these is what makes the parallel fan-out auditable rather than
    merely claimed: overlapping `started_at`/`finished_at` across lanes of one job
    is the evidence the lanes ran concurrently, and it survives the process that
    produced it.
    """

    __tablename__ = "node_runs"
    __table_args__ = (Index("ix_node_runs_job_id_node", "job_id", "node"),)

    job_id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True), ForeignKey("jobs.id", ondelete="CASCADE"), nullable=False, index=True
    )
    lane: Mapped[str | None] = mapped_column(String(10))
    node: Mapped[str] = mapped_column(String(64), nullable=False)
    attempt: Mapped[int] = mapped_column(nullable=False, default=1)
    status: Mapped[str] = mapped_column(String(20), nullable=False)
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    latency_ms: Mapped[float | None] = mapped_column()
    error: Mapped[str | None] = mapped_column(Text)
