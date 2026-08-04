"""Alembic environment.

Reads `DATABASE_URL` from the validated settings rather than `alembic.ini`, so a
migration cannot run against a different database than the application. That also
means `alembic upgrade head` fails fast with a named variable if the environment
is incomplete, exactly as the app does.
"""

from __future__ import annotations

import asyncio
from logging.config import fileConfig

from sqlalchemy import pool
from sqlalchemy.engine import Connection
from sqlalchemy.ext.asyncio import async_engine_from_config

from alembic import context
from app.configs.envConfig import settings

# Importing the package populates Base.metadata completely — that guarantee lives
# in app/models/__init__.py, so autogenerate can never miss a table because a
# module was not listed here.
from app.models import Base  # noqa: E402

config = context.config
config.set_main_option("sqlalchemy.url", settings.DATABASE_URL)

if config.config_file_name is not None:
    fileConfig(config.config_file_name)

target_metadata = Base.metadata


def _configure(connection: Connection) -> None:
    context.configure(
        connection=connection,
        target_metadata=target_metadata,
        # Without this, a column type change is invisible to autogenerate.
        compare_type=True,
        compare_server_default=True,
        # Postgres enums are schema objects; keep them in one place.
        include_schemas=False,
    )


def run_migrations_offline() -> None:
    context.configure(
        url=settings.DATABASE_URL,
        target_metadata=target_metadata,
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
    )
    with context.begin_transaction():
        context.run_migrations()


def _run(connection: Connection) -> None:
    _configure(connection)
    with context.begin_transaction():
        context.run_migrations()


async def run_migrations_online() -> None:
    connectable = async_engine_from_config(
        config.get_section(config.config_ini_section, {}),
        prefix="sqlalchemy.",
        poolclass=pool.NullPool,
    )
    async with connectable.connect() as connection:
        await connection.run_sync(_run)
    await connectable.dispose()


if context.is_offline_mode():
    run_migrations_offline()
else:
    asyncio.run(run_migrations_online())
