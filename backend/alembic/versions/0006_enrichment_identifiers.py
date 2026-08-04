"""Knowledge base, agent runs, supplier registry and identifier mappings

Revision ID: 0006_enrichment_identifiers
Revises: 0005_correlation
Create Date: 2026-08-04

Hand-reviewed per §5. Objects autogenerate would not have produced:

  * `uq_supplier_registry_type_namespace` — one entry per coordinate. A duplicate
    would make resolution order-dependent, so two assessments of the same BOM
    could name different suppliers.
  * `uq_eol_records_product_cycle` — one row per product per release cycle;
    without it a re-sync appends rather than updates and `match_cycle` picks
    arbitrarily between stale and fresh.
  * `supplier_registry_entries.successor_id` as a **self-referential** FK with
    ON DELETE SET NULL — Table 4 requires the identifier to survive rebranding
    and acquisition, and deleting a successor must break the link rather than
    cascade-delete the predecessor's history.
  * `ix_identifier_mappings_submission_id_source` — the identifier review screen
    reads "everything unresolved in this submission", which is a filter on
    source within a submission.
"""

from collections.abc import Sequence

import sqlalchemy as sa

from alembic import op

revision: str = "0006_enrichment_identifiers"
down_revision: str | None = "0005_correlation"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    # --- knowledge base ----------------------------------------------------
    op.create_table(
        "cves",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("cve_id", sa.String(32), nullable=False),
        sa.Column("published", sa.DateTime(timezone=True), nullable=True),
        sa.Column("modified", sa.DateTime(timezone=True), nullable=True),
        sa.Column("description", sa.Text(), nullable=True),
        sa.Column("cvss_v31_vector", sa.String(128), nullable=True),
        sa.Column("cvss_v31_score", sa.Float(), nullable=True),
        sa.Column("cwe_ids", sa.ARRAY(sa.Text()), nullable=True),
        sa.Column("synced_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column(
            "created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
        sa.PrimaryKeyConstraint("id", name="pk_cves"),
        sa.UniqueConstraint("cve_id", name="uq_cves_cve_id"),
    )
    op.create_table(
        "kev_entries",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("cve_id", sa.String(32), nullable=False),
        sa.Column("vendor_project", sa.String(255), nullable=True),
        sa.Column("product", sa.String(255), nullable=True),
        sa.Column("added_on", sa.Date(), nullable=True),
        sa.Column("due_date", sa.Date(), nullable=True),
        sa.Column("known_ransomware", sa.String(32), nullable=True),
        sa.Column("synced_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column(
            "created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
        sa.PrimaryKeyConstraint("id", name="pk_kev_entries"),
        sa.UniqueConstraint("cve_id", name="uq_kev_entries_cve_id"),
    )
    op.create_index("ix_kev_entries_cve_id", "kev_entries", ["cve_id"])

    op.create_table(
        "eol_records",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("product_key", sa.String(128), nullable=False),
        sa.Column("cycle", sa.String(64), nullable=False),
        sa.Column("eol_date", sa.Date(), nullable=True),
        sa.Column("support_end", sa.Date(), nullable=True),
        sa.Column("latest_version", sa.String(64), nullable=True),
        sa.Column("release_date", sa.Date(), nullable=True),
        sa.Column("source", sa.String(32), nullable=False, server_default="endoflife.date"),
        sa.Column("synced_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column(
            "created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
        sa.PrimaryKeyConstraint("id", name="pk_eol_records"),
        # One row per product per cycle: without it a re-sync appends rather
        # than updates and cycle matching picks arbitrarily between the two.
        sa.UniqueConstraint("product_key", "cycle", name="uq_eol_records_product_cycle"),
    )
    op.create_index("ix_eol_records_product_key", "eol_records", ["product_key"])

    op.create_table(
        "advisories",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("source", sa.String(32), nullable=False),
        sa.Column("ref", sa.String(128), nullable=False),
        sa.Column("title", sa.Text(), nullable=True),
        sa.Column("url", sa.String(512), nullable=True),
        sa.Column("published", sa.Date(), nullable=True),
        sa.Column("cve_ids", sa.ARRAY(sa.Text()), nullable=True),
        sa.Column("synced_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column(
            "created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
        sa.PrimaryKeyConstraint("id", name="pk_advisories"),
        sa.UniqueConstraint("source", "ref", name="uq_advisories_source_ref"),
    )

    # --- agent runs and their evidence -------------------------------------
    op.create_table(
        "agent_runs",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("org_id", sa.Uuid(), nullable=False),
        sa.Column("submission_id", sa.Uuid(), nullable=True),
        sa.Column("kind", sa.String(24), nullable=False),
        sa.Column("batch_key", sa.String(255), nullable=False),
        sa.Column("hops", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("verdict", sa.String(32), nullable=False),
        sa.Column("tokens", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("inr_cost", sa.Float(), nullable=False, server_default="0"),
        sa.Column(
            "created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
        sa.PrimaryKeyConstraint("id", name="pk_agent_runs"),
        sa.ForeignKeyConstraint(
            ["org_id"], ["orgs.id"], name="fk_agent_runs_org_id_orgs", ondelete="CASCADE"
        ),
        sa.ForeignKeyConstraint(
            ["submission_id"],
            ["submissions.id"],
            name="fk_agent_runs_submission_id_submissions",
            ondelete="CASCADE",
        ),
    )
    op.create_index("ix_agent_runs_org_id", "agent_runs", ["org_id"])
    op.create_index("ix_agent_runs_submission_id", "agent_runs", ["submission_id"])
    op.create_index("ix_agent_runs_submission_id_kind", "agent_runs", ["submission_id", "kind"])

    op.create_table(
        "agent_evidence",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("agent_run_id", sa.Uuid(), nullable=False),
        sa.Column("hop", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("query", sa.Text(), nullable=True),
        sa.Column("source_url", sa.String(512), nullable=True),
        sa.Column("snippet", sa.Text(), nullable=True),
        sa.Column("supports", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column("confidence", sa.Float(), nullable=True),
        sa.Column(
            "created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
        sa.PrimaryKeyConstraint("id", name="pk_agent_evidence"),
        sa.ForeignKeyConstraint(
            ["agent_run_id"],
            ["agent_runs.id"],
            name="fk_agent_evidence_agent_run_id_agent_runs",
            ondelete="CASCADE",
        ),
    )
    op.create_index("ix_agent_evidence_agent_run_id", "agent_evidence", ["agent_run_id"])

    # --- the curated asset -------------------------------------------------
    op.create_table(
        "supplier_registry_entries",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("purl_type", sa.String(32), nullable=False),
        sa.Column("namespace_or_name", sa.String(255), nullable=False),
        sa.Column("supplier_org", sa.String(255), nullable=False),
        sa.Column("source", sa.String(32), nullable=False, server_default="curated"),
        sa.Column("confidence", sa.Float(), nullable=False, server_default="1"),
        sa.Column("verified_by", sa.String(255), nullable=True),
        sa.Column("verified_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("successor_id", sa.Uuid(), nullable=True),
        sa.Column("note", sa.Text(), nullable=True),
        sa.Column(
            "created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
        sa.PrimaryKeyConstraint("id", name="pk_supplier_registry_entries"),
        # Self-referential, SET NULL: deleting a successor must break the link,
        # not cascade away the predecessor's history (Table 4).
        sa.ForeignKeyConstraint(
            ["successor_id"],
            ["supplier_registry_entries.id"],
            name="fk_supplier_registry_successor_id_self",
            ondelete="SET NULL",
        ),
        sa.UniqueConstraint(
            "purl_type", "namespace_or_name", name="uq_supplier_registry_type_namespace"
        ),
    )
    op.create_index(
        "ix_supplier_registry_namespace", "supplier_registry_entries", ["namespace_or_name"]
    )

    op.create_table(
        "registry_proposals",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("org_id", sa.Uuid(), nullable=False),
        sa.Column("agent_run_id", sa.Uuid(), nullable=True),
        sa.Column("purl_type", sa.String(32), nullable=False),
        sa.Column("namespace_or_name", sa.String(255), nullable=False),
        sa.Column("proposed_supplier", sa.String(255), nullable=False),
        sa.Column("confidence", sa.Float(), nullable=False, server_default="0"),
        sa.Column("status", sa.String(16), nullable=False, server_default="pending"),
        sa.Column("reviewed_by", sa.String(255), nullable=True),
        sa.Column("reviewed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("reason", sa.Text(), nullable=True),
        sa.Column(
            "created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
        sa.PrimaryKeyConstraint("id", name="pk_registry_proposals"),
        sa.ForeignKeyConstraint(
            ["org_id"], ["orgs.id"], name="fk_registry_proposals_org_id_orgs", ondelete="CASCADE"
        ),
        sa.ForeignKeyConstraint(
            ["agent_run_id"],
            ["agent_runs.id"],
            name="fk_registry_proposals_agent_run_id_agent_runs",
            ondelete="SET NULL",
        ),
    )
    op.create_index("ix_registry_proposals_org_id", "registry_proposals", ["org_id"])
    op.create_index("ix_registry_proposals_status", "registry_proposals", ["status"])

    op.create_table(
        "identifier_mappings",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("org_id", sa.Uuid(), nullable=False),
        sa.Column("submission_id", sa.Uuid(), nullable=True),
        sa.Column("component_name", sa.String(255), nullable=False),
        sa.Column("purl", sa.String(512), nullable=True),
        sa.Column("certin_id", sa.String(512), nullable=True),
        sa.Column("supplier_org", sa.String(255), nullable=True),
        sa.Column("source", sa.String(24), nullable=False, server_default="unresolved"),
        sa.Column("confidence", sa.Float(), nullable=False, server_default="0"),
        sa.Column("reviewed_by", sa.String(255), nullable=True),
        sa.Column(
            "created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
        sa.PrimaryKeyConstraint("id", name="pk_identifier_mappings"),
        sa.ForeignKeyConstraint(
            ["org_id"], ["orgs.id"], name="fk_identifier_mappings_org_id_orgs", ondelete="CASCADE"
        ),
        sa.ForeignKeyConstraint(
            ["submission_id"],
            ["submissions.id"],
            name="fk_identifier_mappings_submission_id_submissions",
            ondelete="CASCADE",
        ),
    )
    op.create_index("ix_identifier_mappings_org_id", "identifier_mappings", ["org_id"])
    op.create_index(
        "ix_identifier_mappings_submission_id", "identifier_mappings", ["submission_id"]
    )
    op.create_index(
        "ix_identifier_mappings_submission_id_source",
        "identifier_mappings",
        ["submission_id", "source"],
    )


def downgrade() -> None:
    for index, table in (
        ("ix_identifier_mappings_submission_id_source", "identifier_mappings"),
        ("ix_identifier_mappings_submission_id", "identifier_mappings"),
        ("ix_identifier_mappings_org_id", "identifier_mappings"),
    ):
        op.drop_index(index, table_name=table)
    op.drop_table("identifier_mappings")

    op.drop_index("ix_registry_proposals_status", table_name="registry_proposals")
    op.drop_index("ix_registry_proposals_org_id", table_name="registry_proposals")
    op.drop_table("registry_proposals")

    op.drop_index("ix_supplier_registry_namespace", table_name="supplier_registry_entries")
    op.drop_table("supplier_registry_entries")

    op.drop_index("ix_agent_evidence_agent_run_id", table_name="agent_evidence")
    op.drop_table("agent_evidence")

    op.drop_index("ix_agent_runs_submission_id_kind", table_name="agent_runs")
    op.drop_index("ix_agent_runs_submission_id", table_name="agent_runs")
    op.drop_index("ix_agent_runs_org_id", table_name="agent_runs")
    op.drop_table("agent_runs")

    op.drop_table("advisories")
    op.drop_index("ix_eol_records_product_key", table_name="eol_records")
    op.drop_table("eol_records")
    op.drop_index("ix_kev_entries_cve_id", table_name="kev_entries")
    op.drop_table("kev_entries")
    op.drop_table("cves")
