"""Cross-BOM correlation findings

Revision ID: 0005_correlation
Revises: 0004_ingestion_catalogue
Create Date: 2026-08-04

Hand-reviewed per §5. `ix_correlation_findings_submission_id_rule` is composite
because the assessment reads a submission's findings grouped by rule, and the
estate view (S16) asks "which submissions raised cryptoInSbom?" — an index on
`submission_id` alone would scan every finding of every rule to answer it.

No unique constraint on (submission_id, rule_key): one rule can legitimately
raise several findings for one submission, and forcing uniqueness would silently
discard all but the first.
"""

from collections.abc import Sequence

import sqlalchemy as sa

from alembic import op

revision: str = "0005_correlation"
down_revision: str | None = "0004_ingestion_catalogue"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "correlation_findings",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("org_id", sa.Uuid(), nullable=False),
        sa.Column("submission_id", sa.Uuid(), nullable=False),
        sa.Column("rule_key", sa.String(64), nullable=False),
        sa.Column("severity", sa.String(10), nullable=False),
        sa.Column("clause", sa.String(32), nullable=False),
        sa.Column("detail", sa.Text(), nullable=False),
        sa.Column("left_ref", sa.String(255), nullable=True),
        sa.Column("right_ref", sa.String(255), nullable=True),
        sa.Column(
            "created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
        sa.PrimaryKeyConstraint("id", name="pk_correlation_findings"),
        sa.ForeignKeyConstraint(
            ["org_id"], ["orgs.id"], name="fk_correlation_findings_org_id_orgs", ondelete="CASCADE"
        ),
        sa.ForeignKeyConstraint(
            ["submission_id"],
            ["submissions.id"],
            name="fk_correlation_findings_submission_id_submissions",
            ondelete="CASCADE",
        ),
    )
    op.create_index("ix_correlation_findings_org_id", "correlation_findings", ["org_id"])
    op.create_index(
        "ix_correlation_findings_submission_id", "correlation_findings", ["submission_id"]
    )
    op.create_index(
        "ix_correlation_findings_submission_id_rule",
        "correlation_findings",
        ["submission_id", "rule_key"],
    )


def downgrade() -> None:
    op.drop_index("ix_correlation_findings_submission_id_rule", table_name="correlation_findings")
    op.drop_index("ix_correlation_findings_submission_id", table_name="correlation_findings")
    op.drop_index("ix_correlation_findings_org_id", table_name="correlation_findings")
    op.drop_table("correlation_findings")
