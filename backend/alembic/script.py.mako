"""${message}

Revision ID: ${up_revision}
Revises: ${down_revision | comma,n}
Create Date: ${create_date}

Hand-review checklist (§5) — autogenerate will not do these for you:
  * partial and composite indexes
  * unique constraints that dedupe (e.g. submissions on (org_id, checksum))
  * a `downgrade()` that actually reverses this revision, including enum drops
"""

from collections.abc import Sequence

from alembic import op
import sqlalchemy as sa
${imports if imports else ""}

revision: str = ${repr(up_revision)}
down_revision: str | None = ${repr(down_revision)}
branch_labels: str | Sequence[str] | None = ${repr(branch_labels)}
depends_on: str | Sequence[str] | None = ${repr(depends_on)}


def upgrade() -> None:
    ${upgrades if upgrades else "pass"}


def downgrade() -> None:
    ${downgrades if downgrades else "pass"}
