"""Repository base. **Tenancy is enforced here, never in the router.**

A BOM is an architecture disclosure and this system holds many suppliers' at
once, so cross-tenant reachability is the failure that ends the product. Routers
are the wrong place to enforce it: a new endpoint is one forgotten `where` clause
away from leaking, and the omission looks like nothing at review.

So every repository is constructed *with* an org scope and every query it builds
carries it. There is no method that takes an id alone.

Not-found and forbidden are deliberately indistinguishable to callers: a request
for another tenant's submission returns nothing, exactly as a request for a
nonexistent one does, so existence does not leak (S5 returns 404 rather than 403
on top of this).
"""

from __future__ import annotations

import uuid
from typing import Any

from sqlalchemy import Select, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.base import Base


class TenantScopedRepository[ModelT: Base]:
    """Base for every repository over an org-scoped table."""

    model: type[ModelT]

    def __init__(self, session: AsyncSession, org_id: uuid.UUID) -> None:
        if org_id is None:  # pragma: no cover - defensive; typing forbids it
            raise ValueError("a repository cannot be constructed without an org scope")
        self.session = session
        self.org_id = org_id

    def scoped(self) -> Select[tuple[ModelT]]:
        """The only entry point for building a query.

        Every read in every subclass starts here. A method that builds a bare
        `select(self.model)` is a tenancy bug, and `tests/test_authz.py` greps
        for exactly that.
        """
        return select(self.model).where(self.model.org_id == self.org_id)  # type: ignore[attr-defined]

    async def get(self, entity_id: uuid.UUID) -> ModelT | None:
        result = await self.session.execute(self.scoped().where(self.model.id == entity_id))  # type: ignore[attr-defined]
        return result.scalar_one_or_none()

    async def list(self, *, limit: int = 100, offset: int = 0) -> list[ModelT]:
        result = await self.session.execute(self.scoped().limit(limit).offset(offset))
        return list(result.scalars().all())

    async def add(self, entity: ModelT) -> ModelT:
        """Persist, forcing the org scope rather than trusting the caller's."""
        if getattr(entity, "org_id", None) != self.org_id:
            raise ValueError(
                f"refusing to write a {self.model.__name__} for org "
                f"{getattr(entity, 'org_id', None)} through a repository scoped to {self.org_id}"
            )
        self.session.add(entity)
        await self.session.flush()
        return entity

    async def count(self, **filters: Any) -> int:
        from sqlalchemy import func

        query = select(func.count()).select_from(self.model).where(
            self.model.org_id == self.org_id  # type: ignore[attr-defined]
        )
        for column, value in filters.items():
            query = query.where(getattr(self.model, column) == value)
        result = await self.session.execute(query)
        return int(result.scalar_one())
