"""The model registry must stay complete.

Regression: `Base.metadata.create_all` failed with
`NoReferencedTableError: Foreign key associated with column 'jobs.engagement_id'
could not find table 'engagements'` because only some model modules had been
imported. The test suite happened to import the rest and passed; a script that
imported only `Org` did not.

Importing `app.models` is now the single guarantee, and these assert it holds.
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

from sqlalchemy.schema import CreateTable

from app.models import Base

BACKEND = Path(__file__).resolve().parent.parent

EXPECTED_TABLES = {
    "orgs",
    "users",
    "clients",
    "engagements",
    "jobs",
    "node_runs",
    "submissions",
    "bom_documents",
}


def test_importing_the_package_registers_every_table():
    assert set(Base.metadata.tables) == EXPECTED_TABLES


def test_every_foreign_key_resolves_to_a_registered_table():
    """An unresolvable FK is the symptom a missing import produces."""
    for table in Base.metadata.sorted_tables:
        for fk in table.foreign_keys:
            assert fk.column is not None, (
                f"{table.name}.{fk.parent.name} references {fk.target_fullname}, "
                "which is not in the registry — its model module is not imported "
                "in app/models/__init__.py"
            )


def test_create_all_works_from_a_bare_import_of_the_package():
    """The exact failure, in the exact shape that produced it: a fresh process
    that imports only `app.models` and builds the schema."""
    script = (
        "import asyncio;"
        "from sqlalchemy.ext.asyncio import create_async_engine;"
        "from app.models import Base;"
        "e=create_async_engine('sqlite+aiosqlite:///:memory:');"
        "asyncio.run(_m()) if False else None;"
        "\n"
        "async def _go():\n"
        "    async with e.begin() as c:\n"
        "        await c.run_sync(Base.metadata.create_all)\n"
        "    await e.dispose()\n"
        "    print(sorted(Base.metadata.tables))\n"
        "asyncio.run(_go())\n"
    )
    result = subprocess.run(
        [sys.executable, "-c", script], capture_output=True, text=True, cwd=BACKEND, timeout=120
    )
    assert result.returncode == 0, result.stderr
    assert "engagements" in result.stdout


def test_the_schema_compiles_for_sqlite_so_the_guards_stay_testable():
    """Dialect portability is deliberate: repository logic is exercised without
    a live Postgres, so the models must render on SQLite too."""
    from sqlalchemy.dialects import sqlite

    for table in Base.metadata.sorted_tables:
        assert str(CreateTable(table).compile(dialect=sqlite.dialect()))
