"""Auth: MFA columns and the audit trail

Revision ID: 0003_auth
Revises: 0002_submissions
Create Date: 2026-08-04

Hand-reviewed per §5.

`users.mfa_secret` is nullable because a secret is generated at enrolment but
only persisted once a code proves the user actually holds it — storing it at
generation would let a half-finished enrolment lock someone out of their account.

`ix_audit_events_org_id_created_at` is composite and org-first: the audit view is
always "what happened in this tenant, most recent first", and an index on
`org_id` alone would sort in memory.
"""

from collections.abc import Sequence

import sqlalchemy as sa

from alembic import op

revision: str = "0003_auth"
down_revision: str | None = "0002_submissions"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column("users", sa.Column("mfa_secret", sa.String(64), nullable=True))
    op.add_column(
        "users",
        sa.Column("is_active", sa.Boolean(), nullable=False, server_default=sa.true()),
    )

    op.create_table(
        "audit_events",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("org_id", sa.Uuid(), nullable=False),
        # Nullable: a failed sign-in has no authenticated actor by definition.
        sa.Column("actor_id", sa.Uuid(), nullable=True),
        sa.Column("action", sa.String(64), nullable=False),
        sa.Column("resource", sa.String(64), nullable=True),
        sa.Column("resource_id", sa.String(64), nullable=True),
        sa.Column("meta", sa.dialects.postgresql.JSONB(), nullable=True),
        sa.Column("ip", sa.String(45), nullable=True),
        sa.Column(
            "created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
        sa.PrimaryKeyConstraint("id", name="pk_audit_events"),
        sa.ForeignKeyConstraint(
            ["org_id"], ["orgs.id"], name="fk_audit_events_org_id_orgs", ondelete="CASCADE"
        ),
        sa.ForeignKeyConstraint(
            ["actor_id"], ["users.id"], name="fk_audit_events_actor_id_users", ondelete="SET NULL"
        ),
    )
    op.create_index("ix_audit_events_org_id", "audit_events", ["org_id"])
    op.create_index("ix_audit_events_action", "audit_events", ["action"])
    op.create_index(
        "ix_audit_events_org_id_created_at", "audit_events", ["org_id", "created_at"]
    )


def downgrade() -> None:
    op.drop_index("ix_audit_events_org_id_created_at", table_name="audit_events")
    op.drop_index("ix_audit_events_action", table_name="audit_events")
    op.drop_index("ix_audit_events_org_id", table_name="audit_events")
    op.drop_table("audit_events")

    op.drop_column("users", "is_active")
    op.drop_column("users", "mfa_secret")
