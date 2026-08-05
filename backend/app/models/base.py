"""Declarative base and the column types every table shares.

**Dialect portability is deliberate, not incidental.** Production is Postgres 16
and the migrations target it. But the guards this sprint exists to enforce — the
terminal-finality rule and repository-layer tenancy — are logic, and logic that
can only be exercised against a running database gets exercised rarely. The
variant types below let the same models run on SQLite in the test suite while
emitting proper `JSONB`, `UUID` and `text[]` in Postgres.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import DateTime, MetaData, String, Text, Uuid, func
from sqlalchemy.dialects import postgresql
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column
from sqlalchemy.types import JSON, TypeEngine

#: Explicit naming convention so Alembic autogenerate emits stable, reviewable
#: names. Without it, dropping a constraint in a downgrade requires knowing a
#: name the database invented, and `downgrade()` quietly stops working.
NAMING_CONVENTION = {
    "ix": "ix_%(column_0_label)s",
    "uq": "uq_%(table_name)s_%(column_0_name)s",
    "ck": "ck_%(table_name)s_%(constraint_name)s",
    "fk": "fk_%(table_name)s_%(column_0_name)s_%(referred_table_name)s",
    "pk": "pk_%(table_name)s",
}


def jsonb() -> TypeEngine[Any]:
    """JSONB on Postgres, JSON elsewhere."""
    return JSON().with_variant(postgresql.JSONB(), "postgresql")


def text_array() -> TypeEngine[Any]:
    """`text[]` on Postgres, a JSON list elsewhere.

    SQLite has no array type. The JSON fallback preserves list semantics for the
    tests; only Postgres gets the real column.
    """
    return JSON().with_variant(postgresql.ARRAY(Text()), "postgresql")


#: Dimension of the default embedding space. Fixed rather than configurable
#: because it is a column type on Postgres: changing it is a migration, and a
#: setting that silently requires one is a trap.
EMBEDDING_DIM = 384


def embedding_vector(dim: int = EMBEDDING_DIM) -> TypeEngine[Any]:
    """`vector(n)` on Postgres via pgvector, a JSON float list elsewhere.

    The JSON fallback is not a toy: the same cosine similarity runs over it in
    Python, so retrieval ranking is exercised by the test suite on SQLite exactly
    as the tenancy guards are. What Postgres adds is the ANN index — a
    correctness-preserving speedup, not a behaviour change.
    """
    try:
        from pgvector.sqlalchemy import Vector
    except ImportError:
        # pgvector is an optional extra. Without it the models still load and the
        # JSON path still works, which keeps `make demo` and the test suite
        # running on a machine that has never seen Postgres.
        return JSON()
    return JSON().with_variant(Vector(dim), "postgresql")


def utcnow() -> datetime:
    return datetime.now(UTC)


class Base(DeclarativeBase):
    metadata = MetaData(naming_convention=NAMING_CONVENTION)


class UuidPrimaryKey:
    """UUID primary keys throughout.

    Generated application-side so a job carries its id before it is persisted —
    the id goes into the log line and the idempotency key at enqueue time, which
    a database-generated sequence could not provide until after the insert.
    """

    id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True), primary_key=True, default=uuid.uuid4
    )


class Timestamped:
    """`created_at` set by the database, so it cannot be backdated by a caller."""

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )


def short_string(length: int = 255, **kwargs: Any) -> Mapped[str]:
    return mapped_column(String(length), **kwargs)
