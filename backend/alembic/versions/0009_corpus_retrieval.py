"""Corpus documents and chunks for org-scoped retrieval

Revision ID: 0009_corpus_retrieval
Revises: 0008_generation_job_type
Create Date: 2026-08-05

Hand-reviewed per §5.

**`CREATE EXTENSION vector` is conditional and the downgrade does not drop it.**
Creating it requires superuser on most managed Postgres, so a deployment where
the DBA has already installed it must not fail here; `IF NOT EXISTS` covers that.
Dropping it on the way down would be worse than useless — an extension is
database-wide, and another schema in the same database may be using it. A
downgrade that breaks an unrelated application is not a downgrade.

The embedding column is `vector(384)` on Postgres and JSON elsewhere. The
dimension is baked into the column type, so changing embedding model to one with
a different width is a migration rather than a setting — which is the honest
signal, because the old vectors are not comparable to the new ones either way.

The ANN index is deliberately **not** created here. `ivfflat` needs to be built
against a populated table to choose its list count sensibly, and an empty-table
index is both useless and misleading. Exact search is correct at every corpus
size; it is only slow at large ones, and the index is a follow-up once a real
corpus exists.
"""

from collections.abc import Sequence

import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

from alembic import op

revision: str = "0009_corpus_retrieval"
down_revision: str | None = "0008_generation_job_type"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

EMBEDDING_DIM = 384


def _embedding_type() -> sa.types.TypeEngine:
    if op.get_bind().dialect.name != "postgresql":
        return sa.JSON()
    try:
        from pgvector.sqlalchemy import Vector

        return Vector(EMBEDDING_DIM)
    except ImportError:  # pragma: no cover - the extra is installed in deployment
        return postgresql.JSONB()


def upgrade() -> None:
    is_postgres = op.get_bind().dialect.name == "postgresql"
    if is_postgres:
        op.execute(sa.text("CREATE EXTENSION IF NOT EXISTS vector"))

    op.create_table(
        "corpus_documents",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("org_id", sa.Uuid(), nullable=False),
        sa.Column("kind", sa.String(32), nullable=False),
        sa.Column("title", sa.String(255), nullable=False),
        sa.Column("source_ref", sa.String(512), nullable=True),
        sa.Column("engagement_id", sa.Uuid(), nullable=True),
        sa.Column(
            "meta",
            sa.JSON().with_variant(postgresql.JSONB(), "postgresql"),
            nullable=True,
        ),
        sa.Column(
            "created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
        sa.PrimaryKeyConstraint("id", name="pk_corpus_documents"),
        sa.ForeignKeyConstraint(
            ["org_id"], ["orgs.id"], name="fk_corpus_documents_org_id_orgs", ondelete="CASCADE"
        ),
        sa.ForeignKeyConstraint(
            ["engagement_id"],
            ["engagements.id"],
            name="fk_corpus_documents_engagement_id_engagements",
            ondelete="SET NULL",
        ),
    )
    op.create_index("ix_corpus_documents_org_id", "corpus_documents", ["org_id"])
    op.create_index(
        "ix_corpus_documents_org_id_kind", "corpus_documents", ["org_id", "kind"]
    )

    op.create_table(
        "corpus_chunks",
        sa.Column("id", sa.Uuid(), nullable=False),
        # Denormalised from the document on purpose: the scope predicate has to
        # be applicable to the chunk query itself, without a join.
        sa.Column("org_id", sa.Uuid(), nullable=False),
        sa.Column("document_id", sa.Uuid(), nullable=False),
        sa.Column("ord", sa.Integer(), nullable=False),
        sa.Column("content", sa.Text(), nullable=False),
        sa.Column("content_lower", sa.Text(), nullable=False),
        sa.Column("embedding", _embedding_type(), nullable=True),
        sa.Column("embedding_model", sa.String(64), nullable=True),
        sa.Column("embedding_dim", sa.Integer(), nullable=True),
        sa.Column("masked_count", sa.Integer(), nullable=False, server_default="0"),
        sa.Column(
            "created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
        sa.PrimaryKeyConstraint("id", name="pk_corpus_chunks"),
        sa.ForeignKeyConstraint(
            ["org_id"], ["orgs.id"], name="fk_corpus_chunks_org_id_orgs", ondelete="CASCADE"
        ),
        sa.ForeignKeyConstraint(
            ["document_id"],
            ["corpus_documents.id"],
            name="fk_corpus_chunks_document_id_corpus_documents",
            ondelete="CASCADE",
        ),
    )
    op.create_index("ix_corpus_chunks_org_id", "corpus_chunks", ["org_id"])
    op.create_index(
        "ix_corpus_chunks_org_id_document_id", "corpus_chunks", ["org_id", "document_id"]
    )

    if is_postgres:
        # The lexical half of hybrid search. Built over the same column the
        # SQLite path scans, so both dialects rank the same text.
        op.execute(
            sa.text(
                "CREATE INDEX ix_corpus_chunks_content_fts ON corpus_chunks "
                "USING gin (to_tsvector('english', content_lower))"
            )
        )


def downgrade() -> None:
    if op.get_bind().dialect.name == "postgresql":
        op.execute(sa.text("DROP INDEX IF EXISTS ix_corpus_chunks_content_fts"))
    op.drop_index("ix_corpus_chunks_org_id_document_id", table_name="corpus_chunks")
    op.drop_index("ix_corpus_chunks_org_id", table_name="corpus_chunks")
    op.drop_table("corpus_chunks")
    op.drop_index("ix_corpus_documents_org_id_kind", table_name="corpus_documents")
    op.drop_index("ix_corpus_documents_org_id", table_name="corpus_documents")
    op.drop_table("corpus_documents")
    # The `vector` extension is deliberately NOT dropped — it is database-wide and
    # another schema may depend on it. See the module docstring.
