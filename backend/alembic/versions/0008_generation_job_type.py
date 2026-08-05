"""Add the generate_from_repo job type

Revision ID: 0008_generation_job_type
Revises: 0007_vex_assessments
Create Date: 2026-08-05

Hand-reviewed per §5.

Repository generation was a synchronous service call and left no durable record.
S21 meters it — separately from submissions, because it resolves dependencies in a
sandbox and takes minutes rather than seconds — and a quota cannot count what was
never written down. s.2.3 also requires regeneration on every release, update and
patch, which needs the same record to be auditable.

`ALTER TYPE ... ADD VALUE` cannot run inside a transaction on PostgreSQL before
12, and cannot be reversed at all: PostgreSQL has no `DROP VALUE`. The downgrade
therefore recreates the type without the new value, which fails loudly if any row
still uses it — the right outcome, since silently dropping those rows' type would
corrupt the job log.
"""

from collections.abc import Sequence

import sqlalchemy as sa

from alembic import op

revision: str = "0008_generation_job_type"
down_revision: str | None = "0007_vex_assessments"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

NEW_VALUE = "generate_from_repo"

EXISTING = (
    "assess_submission",
    "rescore_submission",
    "narrative_gap_report",
    "narrative_roadmap",
    "narrative_advisory",
    "vex_draft_justification",
    "vex_csaf_export",
)


def upgrade() -> None:
    if op.get_bind().dialect.name != "postgresql":
        # SQLite stores the enum as a constrained VARCHAR; nothing to alter.
        return
    op.execute(sa.text(f"ALTER TYPE job_type ADD VALUE IF NOT EXISTS '{NEW_VALUE}'"))


def downgrade() -> None:
    if op.get_bind().dialect.name != "postgresql":
        return
    values = ", ".join(f"'{value}'" for value in EXISTING)
    op.execute(sa.text("ALTER TYPE job_type RENAME TO job_type_old"))
    op.execute(sa.text(f"CREATE TYPE job_type AS ENUM ({values})"))
    # Fails if a row still carries the removed value, which is the point.
    op.execute(
        sa.text(
            "ALTER TABLE jobs ALTER COLUMN job_type TYPE job_type "
            "USING job_type::text::job_type"
        )
    )
    op.execute(sa.text("DROP TYPE job_type_old"))
