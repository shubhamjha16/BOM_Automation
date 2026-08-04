"""VEX statements, CSAF advisories, assessments and their provenance chain

Revision ID: 0007_vex_assessments
Revises: 0006_enrichment_identifiers
Create Date: 2026-08-04

Hand-reviewed per §5.

`vex_statements.status` is a plain VARCHAR, not a database enum, and that is a
deliberate departure from every other status column here. Recommendation 7.1.6
could gain a status in a future revision, and a schema migration is a worse place
to discover that than a validator. `services/vex/authoring.py` is the authority
and refuses anything outside the four.

`assessment_sections.field_verdict_ids` and `correlation_finding_ids` are arrays
rather than a join table on purpose: they are read whole, always together with
the section, and never queried in the reverse direction. A join table would add a
second read to every provenance lookup to answer a question nobody asks.
"""

from collections.abc import Sequence

import sqlalchemy as sa

from alembic import op

revision: str = "0007_vex_assessments"
down_revision: str | None = "0006_enrichment_identifiers"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "vex_statements",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("org_id", sa.Uuid(), nullable=False),
        sa.Column("submission_id", sa.Uuid(), nullable=True),
        sa.Column("component_ref", sa.String(255), nullable=True),
        sa.Column("cve_id", sa.String(32), nullable=False),
        # One of the four of rec. 7.1.6; enforced by the authoring validator.
        sa.Column("status", sa.String(24), nullable=False),
        sa.Column("justification", sa.Text(), nullable=True),
        sa.Column("authored_by", sa.String(255), nullable=True),
        sa.Column("reviewed_by", sa.String(255), nullable=True),
        sa.Column("evidence_refs", sa.ARRAY(sa.Text()), nullable=True),
        sa.Column(
            "created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
        sa.PrimaryKeyConstraint("id", name="pk_vex_statements"),
        sa.ForeignKeyConstraint(
            ["org_id"], ["orgs.id"], name="fk_vex_statements_org_id_orgs", ondelete="CASCADE"
        ),
        sa.ForeignKeyConstraint(
            ["submission_id"],
            ["submissions.id"],
            name="fk_vex_statements_submission_id_submissions",
            ondelete="CASCADE",
        ),
    )
    op.create_index("ix_vex_statements_org_id", "vex_statements", ["org_id"])
    op.create_index("ix_vex_statements_submission_id", "vex_statements", ["submission_id"])
    op.create_index("ix_vex_statements_cve_id", "vex_statements", ["cve_id"])
    op.create_index(
        "ix_vex_statements_submission_id_cve", "vex_statements", ["submission_id", "cve_id"]
    )

    op.create_table(
        "csaf_advisories",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("org_id", sa.Uuid(), nullable=False),
        sa.Column("vex_statement_id", sa.Uuid(), nullable=True),
        sa.Column("tracking_id", sa.String(128), nullable=False),
        sa.Column("doc", sa.dialects.postgresql.JSONB(), nullable=False),
        sa.Column("published_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column(
            "created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
        sa.PrimaryKeyConstraint("id", name="pk_csaf_advisories"),
        sa.ForeignKeyConstraint(
            ["org_id"], ["orgs.id"], name="fk_csaf_advisories_org_id_orgs", ondelete="CASCADE"
        ),
        sa.ForeignKeyConstraint(
            ["vex_statement_id"],
            ["vex_statements.id"],
            name="fk_csaf_advisories_vex_statement_id_vex_statements",
            ondelete="CASCADE",
        ),
    )
    op.create_index("ix_csaf_advisories_org_id", "csaf_advisories", ["org_id"])
    op.create_index(
        "ix_csaf_advisories_vex_statement_id", "csaf_advisories", ["vex_statement_id"]
    )

    op.create_table(
        "assessments",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("org_id", sa.Uuid(), nullable=False),
        sa.Column("submission_id", sa.Uuid(), nullable=False),
        sa.Column("title", sa.String(255), nullable=False),
        sa.Column("status", sa.String(16), nullable=False, server_default="draft"),
        # Recorded so the approver can be checked against it: the assessor who
        # ran an assessment may never approve it (§11).
        sa.Column("authored_by", sa.Uuid(), nullable=True),
        sa.Column("reviewed_by", sa.Uuid(), nullable=True),
        sa.Column("approved_by", sa.Uuid(), nullable=True),
        sa.Column("s3_key", sa.String(512), nullable=True),
        sa.Column("current_version", sa.Integer(), nullable=False, server_default="1"),
        sa.Column("issued_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column(
            "created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
        sa.PrimaryKeyConstraint("id", name="pk_assessments"),
        sa.ForeignKeyConstraint(
            ["org_id"], ["orgs.id"], name="fk_assessments_org_id_orgs", ondelete="CASCADE"
        ),
        sa.ForeignKeyConstraint(
            ["submission_id"],
            ["submissions.id"],
            name="fk_assessments_submission_id_submissions",
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["authored_by"], ["users.id"], name="fk_assessments_authored_by_users",
            ondelete="SET NULL",
        ),
        sa.ForeignKeyConstraint(
            ["reviewed_by"], ["users.id"], name="fk_assessments_reviewed_by_users",
            ondelete="SET NULL",
        ),
        sa.ForeignKeyConstraint(
            ["approved_by"], ["users.id"], name="fk_assessments_approved_by_users",
            ondelete="SET NULL",
        ),
    )
    op.create_index("ix_assessments_org_id", "assessments", ["org_id"])
    op.create_index("ix_assessments_submission_id", "assessments", ["submission_id"])
    op.create_index("ix_assessments_org_id_status", "assessments", ["org_id", "status"])

    op.create_table(
        "assessment_sections",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("org_id", sa.Uuid(), nullable=False),
        sa.Column("assessment_id", sa.Uuid(), nullable=False),
        sa.Column("ord", sa.Integer(), nullable=False),
        sa.Column("section_type", sa.String(48), nullable=False),
        sa.Column("content", sa.Text(), nullable=True),
        # The provenance chain: what this section was written from.
        sa.Column("field_verdict_ids", sa.ARRAY(sa.Text()), nullable=True),
        sa.Column("correlation_finding_ids", sa.ARRAY(sa.Text()), nullable=True),
        sa.Column(
            "created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
        sa.PrimaryKeyConstraint("id", name="pk_assessment_sections"),
        sa.ForeignKeyConstraint(
            ["org_id"], ["orgs.id"], name="fk_assessment_sections_org_id_orgs", ondelete="CASCADE"
        ),
        sa.ForeignKeyConstraint(
            ["assessment_id"],
            ["assessments.id"],
            name="fk_assessment_sections_assessment_id_assessments",
            ondelete="CASCADE",
        ),
    )
    op.create_index("ix_assessment_sections_org_id", "assessment_sections", ["org_id"])
    op.create_index(
        "ix_assessment_sections_assessment_id", "assessment_sections", ["assessment_id"]
    )
    op.create_index(
        "ix_assessment_sections_assessment_id_ord",
        "assessment_sections",
        ["assessment_id", "ord"],
    )


def downgrade() -> None:
    for index in (
        "ix_assessment_sections_assessment_id_ord",
        "ix_assessment_sections_assessment_id",
        "ix_assessment_sections_org_id",
    ):
        op.drop_index(index, table_name="assessment_sections")
    op.drop_table("assessment_sections")

    for index in (
        "ix_assessments_org_id_status",
        "ix_assessments_submission_id",
        "ix_assessments_org_id",
    ):
        op.drop_index(index, table_name="assessments")
    op.drop_table("assessments")

    op.drop_index("ix_csaf_advisories_vex_statement_id", table_name="csaf_advisories")
    op.drop_index("ix_csaf_advisories_org_id", table_name="csaf_advisories")
    op.drop_table("csaf_advisories")

    for index in (
        "ix_vex_statements_submission_id_cve",
        "ix_vex_statements_cve_id",
        "ix_vex_statements_submission_id",
        "ix_vex_statements_org_id",
    ):
        op.drop_index(index, table_name="vex_statements")
    op.drop_table("vex_statements")
