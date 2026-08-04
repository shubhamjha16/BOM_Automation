"""The migration and the models must describe the same schema.

Drift between them is the classic Alembic failure: the models are what the code
queries, the migration is what production actually has, and nothing complains
until a query hits a column that was never created.

`alembic check` would catch this but needs a live database. Alembic's **offline
mode** renders the migration to SQL without connecting, so the comparison runs
in CI on every push with no Postgres at all.
"""

from __future__ import annotations

import re
import subprocess
import sys
from functools import lru_cache
from pathlib import Path

import pytest

# Importing the package populates Base.metadata, exactly as alembic/env.py does.
from app.models import Base

BACKEND = Path(__file__).resolve().parent.parent
CREATE_TABLE = re.compile(r"CREATE TABLE (\w+) \((.*?)\n\);", re.DOTALL)


def _alembic(*args: str) -> str:
    result = subprocess.run(
        [sys.executable, "-m", "alembic", *args],
        capture_output=True,
        text=True,
        cwd=BACKEND,
        timeout=180,
    )
    if result.returncode != 0:
        pytest.fail(f"alembic {' '.join(args)} failed:\n{result.stderr}")
    return result.stdout


@lru_cache(maxsize=1)
def upgrade_sql() -> str:
    return _alembic("upgrade", "head", "--sql")


@lru_cache(maxsize=1)
def downgrade_sql() -> str:
    # head:base, not a pinned revision — a new migration must not silently
    # fall outside the range this test checks. That is exactly what happened
    # when 0002 landed against a hardcoded "0001_foundation:base".
    return _alembic("downgrade", "head:base", "--sql")


ADD_COLUMN = re.compile(r"ALTER TABLE (\w+) ADD COLUMN (\w+)")
DROP_COLUMN = re.compile(r"ALTER TABLE (\w+) DROP COLUMN (\w+)")


def _migration_tables() -> dict[str, set[str]]:
    """Table → column names, as the migrations actually leave them.

    Later revisions ALTER what earlier ones CREATE, so reading only CREATE TABLE
    misses every column added by a subsequent migration — which is precisely what
    happened when 0003 added `users.mfa_secret`.
    """
    sql = upgrade_sql()
    tables: dict[str, set[str]] = {}
    for name, body in CREATE_TABLE.findall(sql):
        if name == "alembic_version":
            continue
        columns = set()
        for line in body.splitlines():
            line = line.strip().rstrip(",")
            if not line or line.startswith("CONSTRAINT"):
                continue
            columns.add(line.split()[0])
        tables[name] = columns

    for table, column in ADD_COLUMN.findall(sql):
        tables.setdefault(table, set()).add(column)
    for table, column in DROP_COLUMN.findall(sql):
        tables.get(table, set()).discard(column)
    return tables


def _model_tables() -> dict[str, set[str]]:
    return {
        table.name: {column.name for column in table.columns}
        for table in Base.metadata.sorted_tables
    }


# --- the migration runs at all ---------------------------------------------


def test_the_migration_renders_without_a_database():
    assert "CREATE TABLE jobs" in upgrade_sql()


# --- models and migration agree --------------------------------------------


def test_the_migration_creates_exactly_the_tables_the_models_define():
    assert set(_migration_tables()) == set(_model_tables())


@pytest.mark.parametrize("table", sorted(_model_tables()))
def test_columns_match_per_table(table):
    migration = _migration_tables()[table]
    models = _model_tables()[table]

    assert not (models - migration), f"{table}: in the models, never created: {models - migration}"
    assert not (migration - models), f"{table}: created, but no model column: {migration - models}"


# --- the hand-added objects autogenerate would have missed (§5) -------------


def test_the_live_jobs_index_is_genuinely_partial():
    """The reconciler's query, against a table that is mostly terminal rows."""
    assert (
        "CREATE INDEX ix_jobs_live ON jobs (org_id, created_at) WHERE terminal_at IS NULL"
        in upgrade_sql()
    )


def test_the_tenant_scoped_status_index_is_composite_and_org_first():
    assert "CREATE INDEX ix_jobs_org_id_status ON jobs (org_id, status)" in upgrade_sql()


def test_email_is_unique_per_org_rather_than_globally():
    assert "CONSTRAINT uq_users_org_id_email UNIQUE (org_id, email)" in upgrade_sql()


def test_the_idempotency_key_is_unique():
    """One job and one execution per document set (S4)."""
    assert "CONSTRAINT uq_jobs_idempotency_key UNIQUE (idempotency_key)" in upgrade_sql()


def test_postgres_native_types_are_used_where_they_matter():
    sql = upgrade_sql()
    assert "instructions JSONB" in sql, "instructions should be JSONB, not JSON"
    assert "enabled_lanes TEXT[]" in sql, "enabled_lanes should be a real array"


def test_terminal_at_is_nullable_because_it_is_the_finality_signal():
    assert "terminal_at TIMESTAMP WITH TIME ZONE," in upgrade_sql()


# --- downgrade actually reverses ------------------------------------------


def test_downgrade_drops_every_table_upgrade_created():
    dropped = set(re.findall(r"DROP TABLE (\w+);", downgrade_sql()))
    assert set(_migration_tables()) <= dropped


def test_downgrade_drops_the_enum_types_too():
    """The part an autogenerated downgrade omits.

    Postgres enum types are independent schema objects that outlive the tables
    referencing them. Without these drops, `downgrade -1` then `upgrade head`
    fails with "type already exists" — so the round-trip this sprint exits on
    would not work.
    """
    created = set(re.findall(r"CREATE TYPE (\w+) AS ENUM", upgrade_sql()))
    dropped = set(re.findall(r"DROP TYPE (\w+);", downgrade_sql()))

    assert created, "expected native enum types on Postgres"
    assert created == dropped, f"created but never dropped: {created - dropped}"


def test_tables_are_dropped_in_reverse_dependency_order():
    """Dropping `orgs` before `jobs` would fail on the foreign key."""
    order = re.findall(r"DROP TABLE (\w+);", downgrade_sql())
    assert order.index("jobs") < order.index("orgs")
    assert order.index("node_runs") < order.index("jobs")
    assert order.index("engagements") < order.index("clients")
