"""Submissions and BOM documents

Revision ID: 0002_submissions
Revises: 0001_foundation
Create Date: 2026-08-04

Hand-reviewed per §5. The two objects autogenerate would not have produced:

  * `uq_bom_documents_org_id_checksum` — dedupes resubmissions. The same bytes
    submitted twice within an org is the same document, and without this a
    supplier re-sending an unchanged BOM creates a second row that scores
    separately and shows as a distinct submission in the estate view.
  * `ix_submissions_engagement_id_created_at` — composite, because the estate
    dashboard reads a client's submissions in time order (S16), and an index on
    `engagement_id` alone would sort in memory.

`overall_score` is nullable with no default. A default of zero would render as
"assessed, scored nothing", which is indistinguishable from a genuine total
failure.
"""

from collections.abc import Sequence

import sqlalchemy as sa

from alembic import op

revision: str = "0002_submissions"
down_revision: str | None = "0001_foundation"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

SUBMISSION_STATUS = "submission_status"
BOM_FORMAT = "bom_format"
DOCUMENT_STATUS = "document_status"

SUBMISSION_STATUSES = ("received", "parsed", "scored", "assessed", "returned", "accepted")
BOM_FORMATS = ("CycloneDX", "SPDX")
DOCUMENT_STATUSES = ("received", "parsed", "rejected")


def upgrade() -> None:
    submission_status = sa.Enum(*SUBMISSION_STATUSES, name=SUBMISSION_STATUS)
    bom_format = sa.Enum(*BOM_FORMATS, name=BOM_FORMAT)
    document_status = sa.Enum(*DOCUMENT_STATUSES, name=DOCUMENT_STATUS)

    op.create_table(
        "submissions",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("org_id", sa.Uuid(), nullable=False),
        sa.Column("engagement_id", sa.Uuid(), nullable=False),
        sa.Column("submitted_by", sa.Uuid(), nullable=True),
        sa.Column("received_on", sa.DateTime(timezone=True), nullable=True),
        sa.Column("status", submission_status, nullable=False, server_default="received"),
        # Null until scored. Never defaulted to zero.
        sa.Column("overall_score", sa.Numeric(5, 2), nullable=True),
        sa.Column("overall_verdict", sa.String(30), nullable=True),
        sa.Column("terminal_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column(
            "created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
        sa.PrimaryKeyConstraint("id", name="pk_submissions"),
        sa.ForeignKeyConstraint(
            ["org_id"], ["orgs.id"], name="fk_submissions_org_id_orgs", ondelete="CASCADE"
        ),
        sa.ForeignKeyConstraint(
            ["engagement_id"],
            ["engagements.id"],
            name="fk_submissions_engagement_id_engagements",
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["submitted_by"],
            ["users.id"],
            name="fk_submissions_submitted_by_users",
            ondelete="SET NULL",
        ),
    )
    op.create_index("ix_submissions_org_id", "submissions", ["org_id"])
    op.create_index("ix_submissions_engagement_id", "submissions", ["engagement_id"])
    op.create_index("ix_submissions_org_id_status", "submissions", ["org_id", "status"])
    op.create_index(
        "ix_submissions_engagement_id_created_at",
        "submissions",
        ["engagement_id", "created_at"],
    )

    op.create_table(
        "bom_documents",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("org_id", sa.Uuid(), nullable=False),
        sa.Column("submission_id", sa.Uuid(), nullable=False),
        sa.Column("lane", sa.String(10), nullable=False),
        sa.Column("format", bom_format, nullable=False),
        sa.Column("spec_version", sa.String(20), nullable=True),
        sa.Column("checksum", sa.String(64), nullable=False),
        sa.Column("filename", sa.String(255), nullable=True),
        sa.Column("size_bytes", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("s3_key", sa.String(512), nullable=True),
        # Interim home for the document itself; migrates to S3 (presigned,
        # SSE-KMS, per-client keys) with the storage work in S13.
        sa.Column("payload", sa.dialects.postgresql.JSONB(), nullable=True),
        # parsed + rejected must equal entry_count. The S6 contract, checkable
        # per row after the fact rather than only asserted at parse time.
        sa.Column("entry_count", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("parsed_count", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("rejected_count", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("doc_author", sa.String(255), nullable=True),
        sa.Column("doc_timestamp", sa.DateTime(timezone=True), nullable=True),
        sa.Column("status", document_status, nullable=False, server_default="received"),
        sa.Column(
            "created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
        sa.PrimaryKeyConstraint("id", name="pk_bom_documents"),
        sa.ForeignKeyConstraint(
            ["org_id"], ["orgs.id"], name="fk_bom_documents_org_id_orgs", ondelete="CASCADE"
        ),
        sa.ForeignKeyConstraint(
            ["submission_id"],
            ["submissions.id"],
            name="fk_bom_documents_submission_id_submissions",
            ondelete="CASCADE",
        ),
        # Dedupes resubmissions of identical bytes within one org.
        sa.UniqueConstraint("org_id", "checksum", name="uq_bom_documents_org_id_checksum"),
    )
    op.create_index("ix_bom_documents_org_id", "bom_documents", ["org_id"])
    op.create_index("ix_bom_documents_submission_id", "bom_documents", ["submission_id"])


def downgrade() -> None:
    op.drop_index("ix_bom_documents_submission_id", table_name="bom_documents")
    op.drop_index("ix_bom_documents_org_id", table_name="bom_documents")
    op.drop_table("bom_documents")

    op.drop_index("ix_submissions_engagement_id_created_at", table_name="submissions")
    op.drop_index("ix_submissions_org_id_status", table_name="submissions")
    op.drop_index("ix_submissions_engagement_id", table_name="submissions")
    op.drop_index("ix_submissions_org_id", table_name="submissions")
    op.drop_table("submissions")

    bind = op.get_bind()
    for name in (DOCUMENT_STATUS, BOM_FORMAT, SUBMISSION_STATUS):
        sa.Enum(name=name).drop(bind, checkfirst=True)
