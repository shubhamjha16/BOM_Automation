"""Widen the clause column from 32 to 96 characters

Revision ID: 0010_widen_clause_column
Revises: 0009_corpus_retrieval
Create Date: 2026-11-24

The guideline's Tables 8 to 11 (QBOM and CBOM, AIBOM, HBOM) carry no clause numbers, so
the catalogue cites their elements by section, table and name, for example
``8.3 Table 9: Certificates - Signature Algorithm Reference`` (57 characters). The
longest citation is well inside 96.

Widening a VARCHAR is a metadata change on Postgres and does not rewrite the table.

**The downgrade narrows the column again, and fails if a row already holds a citation
longer than 32 characters.** That is the point: silently truncating a clause reference
would leave a verdict citing a clause that does not exist.
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0010_widen_clause_column"
down_revision: str | None = "0009_corpus_retrieval"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

TABLES = ("minimum_elements", "field_verdicts", "correlation_findings")


def upgrade() -> None:
    for table in TABLES:
        with op.batch_alter_table(table) as batch:
            batch.alter_column(
                "clause",
                existing_type=sa.String(32),
                type_=sa.String(96),
                existing_nullable=False,
            )


def downgrade() -> None:
    for table in TABLES:
        with op.batch_alter_table(table) as batch:
            batch.alter_column(
                "clause",
                existing_type=sa.String(96),
                type_=sa.String(32),
                existing_nullable=False,
            )
