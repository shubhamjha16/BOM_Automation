"""Async engine and session factory.

Async everywhere in the backend — no sync engine exists here, so no route can
accidentally block the loop on a query.
"""

from __future__ import annotations

from collections.abc import AsyncIterator
from functools import lru_cache

from sqlalchemy.ext.asyncio import (
    AsyncEngine,
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)

from app.configs.envConfig import settings


@lru_cache(maxsize=1)
def get_engine() -> AsyncEngine:
    return create_async_engine(
        settings.DATABASE_URL,
        # Verifies a pooled connection before handing it out. Render's managed
        # Postgres drops idle connections, and without this the first request
        # after a quiet period fails rather than reconnecting.
        pool_pre_ping=True,
        pool_size=10,
        max_overflow=20,
        echo=False,
    )


@lru_cache(maxsize=1)
def get_sessionmaker() -> async_sessionmaker[AsyncSession]:
    return async_sessionmaker(
        get_engine(),
        expire_on_commit=False,
        autoflush=False,
    )


async def get_session() -> AsyncIterator[AsyncSession]:
    """FastAPI dependency. One session per request, committed or rolled back once.

    The session is never committed inside a repository: a repository that commits
    cannot participate in a larger transaction, and an assessment writes a job,
    its lane results and its node runs as one unit.
    """
    async with get_sessionmaker()() as session:
        try:
            yield session
            await session.commit()
        except Exception:
            await session.rollback()
            raise
