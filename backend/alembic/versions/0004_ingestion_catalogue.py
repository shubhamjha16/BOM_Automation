"""Ingestion integrity and the catalogue as versioned data

Revision ID: 0004_ingestion_catalogue
Revises: 0003_auth
Create Date: 2026-08-04

Hand-reviewed per §5. Four objects autogenerate would not have produced:

  * `ix_raw_entries_bom_document_id_ord` — the rejected list is always read per
    document in document order, so a supplier sees entry 47 where entry 47 is.
  * `ix_field_verdicts_lane_result_id_verdict` — the field table is read per lane
    result and filtered by verdict on every page load.
  * `uq_minimum_elements_version_lane_key` — one row per element per lane per
    guideline version. Without it a re-seed silently duplicates the catalogue and
    every coverage denominator doubles.
  * `ON DELETE RESTRICT` on the two catalogue foreign keys, rather than CASCADE.
    Deleting a guideline version that assessments were scored under must fail
    loudly; cascading would erase the verdicts instead, which is the opposite of
    what a conformance record is for.
"""

from collections.abc import Sequence

import sqlalchemy as sa

from alembic import op

revision: str = "0004_ingestion_catalogue"
down_revision: str | None = "0003_auth"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

ELEMENT_TIER = "element_tier"
ELEMENT_DETERMINABILITY = "element_determinability"
LANE_VERDICT = "lane_verdict"
FIELD_VERDICT = "field_verdict"

TIERS = ("critical", "standard", "contextual")
DETERMINABILITIES = ("auto", "enrich", "human")
LANE_VERDICTS = (
    "pass",
    "conditional",
    "fail",
    "lane_absent",
    "lane_timeout",
    "lane_not_applicable",
)
FIELD_VERDICTS = ("present", "absent", "not_determinable")


def upgrade() -> None:
    tier = sa.Enum(*TIERS, name=ELEMENT_TIER)
    determinability = sa.Enum(*DETERMINABILITIES, name=ELEMENT_DETERMINABILITY)
    lane_verdict = sa.Enum(*LANE_VERDICTS, name=LANE_VERDICT)
    field_verdict = sa.Enum(*FIELD_VERDICTS, name=FIELD_VERDICT)

    # --- S6: every dropped entry, with a reason ----------------------------
    op.create_table(
        "raw_entries",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("org_id", sa.Uuid(), nullable=False),
        sa.Column("bom_document_id", sa.Uuid(), nullable=False),
        sa.Column("ord", sa.Integer(), nullable=False),
        sa.Column("parse_status", sa.String(20), nullable=False, server_default="rejected"),
        sa.Column("reason", sa.Text(), nullable=False),
        sa.Column("ref", sa.String(255), nullable=True),
        sa.Column("payload", sa.dialects.postgresql.JSONB(), nullable=True),
        sa.Column(
            "created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
        sa.PrimaryKeyConstraint("id", name="pk_raw_entries"),
        sa.ForeignKeyConstraint(
            ["org_id"], ["orgs.id"], name="fk_raw_entries_org_id_orgs", ondelete="CASCADE"
        ),
        sa.ForeignKeyConstraint(
            ["bom_document_id"],
            ["bom_documents.id"],
            name="fk_raw_entries_bom_document_id_bom_documents",
            ondelete="CASCADE",
        ),
    )
    op.create_index("ix_raw_entries_org_id", "raw_entries", ["org_id"])
    op.create_index("ix_raw_entries_bom_document_id", "raw_entries", ["bom_document_id"])
    op.create_index(
        "ix_raw_entries_bom_document_id_ord", "raw_entries", ["bom_document_id", "ord"]
    )

    # --- S7: the catalogue, pinned and checksummed -------------------------
    op.create_table(
        "guideline_versions",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("ref", sa.String(255), nullable=False),
        sa.Column("version", sa.String(20), nullable=False),
        sa.Column("published_on", sa.Date(), nullable=True),
        sa.Column("checksum", sa.String(64), nullable=False),
        sa.Column("reviewed_by", sa.String(255), nullable=True),
        sa.Column(
            "created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
        sa.PrimaryKeyConstraint("id", name="pk_guideline_versions"),
        sa.UniqueConstraint("version", name="uq_guideline_versions_version"),
    )

    op.create_table(
        "minimum_elements",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("guideline_version_id", sa.Uuid(), nullable=False),
        sa.Column("lane", sa.String(10), nullable=False),
        sa.Column("key", sa.String(64), nullable=False),
        sa.Column("label", sa.String(255), nullable=False),
        sa.Column("clause", sa.String(32), nullable=False),
        sa.Column("tier", tier, nullable=False),
        sa.Column("determinability", determinability, nullable=False),
        sa.Column("scope", sa.String(10), nullable=False, server_default="entity"),
        sa.Column("rationale", sa.Text(), nullable=True),
        sa.Column("consumer_action", sa.Text(), nullable=True),
        sa.Column(
            "created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
        sa.PrimaryKeyConstraint("id", name="pk_minimum_elements"),
        sa.ForeignKeyConstraint(
            ["guideline_version_id"],
            ["guideline_versions.id"],
            name="fk_minimum_elements_guideline_version_id_guideline_versions",
            ondelete="CASCADE",
        ),
        # One row per element per lane per version; a re-seed must not duplicate
        # the catalogue and double every coverage denominator.
        sa.UniqueConstraint(
            "guideline_version_id", "lane", "key", name="uq_minimum_elements_version_lane_key"
        ),
    )
    op.create_index(
        "ix_minimum_elements_version_lane", "minimum_elements", ["guideline_version_id", "lane"]
    )

    # --- S7: persisted verdicts, pinned to the version they were scored under
    op.create_table(
        "lane_results",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("org_id", sa.Uuid(), nullable=False),
        sa.Column("submission_id", sa.Uuid(), nullable=False),
        sa.Column("guideline_version_id", sa.Uuid(), nullable=True),
        sa.Column("lane", sa.String(10), nullable=False),
        # Null for absent/timeout/not-applicable. Never zero as a placeholder:
        # zero is a real score a supplier can earn.
        sa.Column("score", sa.Numeric(5, 2), nullable=True),
        sa.Column("verdict", lane_verdict, nullable=False),
        sa.Column("entity_count", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("detail", sa.Text(), nullable=True),
        sa.Column("engine_version", sa.String(20), nullable=False, server_default=""),
        sa.Column("inputs_hash", sa.String(64), nullable=True),
        sa.Column("computed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column(
            "created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
        sa.PrimaryKeyConstraint("id", name="pk_lane_results"),
        sa.ForeignKeyConstraint(
            ["org_id"], ["orgs.id"], name="fk_lane_results_org_id_orgs", ondelete="CASCADE"
        ),
        sa.ForeignKeyConstraint(
            ["submission_id"],
            ["submissions.id"],
            name="fk_lane_results_submission_id_submissions",
            ondelete="CASCADE",
        ),
        # RESTRICT, not CASCADE: deleting a guideline version that assessments
        # were scored under must fail loudly rather than erasing the verdicts.
        sa.ForeignKeyConstraint(
            ["guideline_version_id"],
            ["guideline_versions.id"],
            name="fk_lane_results_guideline_version_id_guideline_versions",
            ondelete="RESTRICT",
        ),
    )
    op.create_index("ix_lane_results_org_id", "lane_results", ["org_id"])
    op.create_index("ix_lane_results_submission_id", "lane_results", ["submission_id"])
    op.create_index(
        "ix_lane_results_submission_id_lane", "lane_results", ["submission_id", "lane"]
    )

    op.create_table(
        "field_verdicts",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("org_id", sa.Uuid(), nullable=False),
        sa.Column("lane_result_id", sa.Uuid(), nullable=False),
        sa.Column("minimum_element_id", sa.Uuid(), nullable=True),
        sa.Column("element_key", sa.String(64), nullable=False),
        sa.Column("clause", sa.String(32), nullable=False),
        sa.Column("verdict", field_verdict, nullable=False),
        sa.Column("populated", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("total", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("coverage", sa.Numeric(5, 4), nullable=True),
        sa.Column("weight", sa.Numeric(5, 2), nullable=True),
        sa.Column("detail", sa.Text(), nullable=True),
        sa.Column("consumer_action", sa.Text(), nullable=True),
        sa.Column(
            "created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
        sa.PrimaryKeyConstraint("id", name="pk_field_verdicts"),
        sa.ForeignKeyConstraint(
            ["org_id"], ["orgs.id"], name="fk_field_verdicts_org_id_orgs", ondelete="CASCADE"
        ),
        sa.ForeignKeyConstraint(
            ["lane_result_id"],
            ["lane_results.id"],
            name="fk_field_verdicts_lane_result_id_lane_results",
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["minimum_element_id"],
            ["minimum_elements.id"],
            name="fk_field_verdicts_minimum_element_id_minimum_elements",
            ondelete="RESTRICT",
        ),
    )
    op.create_index("ix_field_verdicts_org_id", "field_verdicts", ["org_id"])
    op.create_index("ix_field_verdicts_lane_result_id", "field_verdicts", ["lane_result_id"])
    op.create_index(
        "ix_field_verdicts_lane_result_id_verdict",
        "field_verdicts",
        ["lane_result_id", "verdict"],
    )


def downgrade() -> None:
    op.drop_index("ix_field_verdicts_lane_result_id_verdict", table_name="field_verdicts")
    op.drop_index("ix_field_verdicts_lane_result_id", table_name="field_verdicts")
    op.drop_index("ix_field_verdicts_org_id", table_name="field_verdicts")
    op.drop_table("field_verdicts")

    op.drop_index("ix_lane_results_submission_id_lane", table_name="lane_results")
    op.drop_index("ix_lane_results_submission_id", table_name="lane_results")
    op.drop_index("ix_lane_results_org_id", table_name="lane_results")
    op.drop_table("lane_results")

    op.drop_index("ix_minimum_elements_version_lane", table_name="minimum_elements")
    op.drop_table("minimum_elements")
    op.drop_table("guideline_versions")

    op.drop_index("ix_raw_entries_bom_document_id_ord", table_name="raw_entries")
    op.drop_index("ix_raw_entries_bom_document_id", table_name="raw_entries")
    op.drop_index("ix_raw_entries_org_id", table_name="raw_entries")
    op.drop_table("raw_entries")

    bind = op.get_bind()
    for name in (FIELD_VERDICT, LANE_VERDICT, ELEMENT_DETERMINABILITY, ELEMENT_TIER):
        sa.Enum(name=name).drop(bind, checkfirst=True)
