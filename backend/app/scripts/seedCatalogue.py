"""Seed the minimum-element catalogue. A deployment step, beside `alembic upgrade head`.

    uv run python -m app.scripts.seedCatalogue

Idempotent: re-running against an already-seeded version is a no-op. If the
encoded catalogue has changed without a version bump it exits non-zero and says
so, because editing v2.0's elements in place would silently change what every
assessment already issued under v2.0 reports against.
"""

from __future__ import annotations

import asyncio
import sys

from app.configs.dbConfig import get_engine, get_sessionmaker
from app.services.catalogue.seeder import CatalogueDrift, seed


async def run(reviewed_by: str | None) -> int:
    async with get_sessionmaker()() as session:
        try:
            version = await seed(session, reviewed_by=reviewed_by)
        except CatalogueDrift as error:
            print(f"catalogue drift: {error}", file=sys.stderr)
            return 1
        await session.commit()

        from sqlalchemy import func, select

        from app.models.guideline import MinimumElement

        count = await session.execute(
            select(func.count())
            .select_from(MinimumElement)
            .where(MinimumElement.guideline_version_id == version.id)
        )
        print(
            f"catalogue: {version.ref} v{version.version} "
            f"({version.published_on}) — {count.scalar_one()} elements, "
            f"checksum {version.checksum[:12]}"
        )
    await get_engine().dispose()
    return 0


def main() -> int:
    reviewed_by = sys.argv[1] if len(sys.argv) > 1 else None
    return asyncio.run(run(reviewed_by))


if __name__ == "__main__":
    raise SystemExit(main())
