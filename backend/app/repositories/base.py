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
from sqlalchemy import false as sa_false
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.base import Base


class TenantScopedRepository[ModelT: Base]:
    """Base for every repository over an org-scoped table."""

    model: type[ModelT]

    def __init__(
        self,
        session: AsyncSession,
        org_id: uuid.UUID,
        *,
        engagement_ids: frozenset[uuid.UUID] | None = None,
        actor_id: uuid.UUID | None = None,
    ) -> None:
        if org_id is None:  # pragma: no cover - defensive; typing forbids it
            raise ValueError("a repository cannot be constructed without an org scope")
        self.session = session
        self.org_id = org_id
        #: A narrower scope than the org, for the `client` role (S16). None means
        #: "every engagement in this org" — the assessor's view. A frozenset means
        #: the caller may see only those engagements, and the restriction is
        #: applied in `scoped()` for exactly the reason tenancy is: a router-level
        #: check is one forgotten `where` clause away from leaking.
        self.engagement_ids = engagement_ids
        #: Recorded on a denied cross-tenant read. Optional because background
        #: workers have no acting user; the org and the resource are enough to
        #: make the row useful without one.
        self.actor_id = actor_id

    def scoped(self) -> Select[tuple[ModelT]]:
        """The only entry point for building a query.

        Every read in every subclass starts here. A method that builds a bare
        `select(self.model)` is a tenancy bug, and `tests/test_authz.py` greps
        for exactly that.

        Applies the engagement narrowing too, where the model carries an
        `engagement_id`. A `client` user is inside the right org and must still
        not read another engagement's submissions.
        """
        query = select(self.model).where(self.model.org_id == self.org_id)  # type: ignore[attr-defined]

        if self.engagement_ids is not None and hasattr(self.model, "engagement_id"):
            if not self.engagement_ids:
                # An empty scope reads nothing, rather than everything. The
                # difference matters: a client with no engagements assigned is a
                # misconfiguration, and returning the whole org would be the
                # worst possible interpretation of it.
                return query.where(sa_false())
            query = query.where(
                self.model.engagement_id.in_(self.engagement_ids)  # type: ignore[attr-defined]
            )
        return query

    async def get(self, entity_id: uuid.UUID) -> ModelT | None:
        result = await self.session.execute(self.scoped().where(self.model.id == entity_id))  # type: ignore[attr-defined]
        entity = result.scalar_one_or_none()
        if entity is None:
            await self._audit_if_another_tenants(entity_id)
        return entity

    async def _audit_if_another_tenants(self, entity_id: uuid.UUID) -> None:
        """Record a reachable-but-denied read. Tells the caller nothing.

        The caller gets the same empty answer either way — that is the whole
        point of the 404 — so **the audit row is the only place the attempt is
        recorded at all**. Without it a cross-tenant sweep is indistinguishable
        from a client with stale bookmarks, and neither shows up anywhere.

        This is the one query in the codebase that deliberately runs unscoped,
        which is why it lives here rather than in a subclass: it selects a single
        `org_id` column, never the row, so nothing crosses the boundary even
        inside this process. A miss inside the caller's own org is an ordinary
        404 and is not audited — noise would bury the signal.
        """
        if not hasattr(self.model, "org_id"):  # pragma: no cover - defensive
            return
        owner = await self.session.execute(
            select(self.model.org_id).where(self.model.id == entity_id)  # type: ignore[attr-defined]
        )
        owning_org = owner.scalar_one_or_none()
        if owning_org is None or owning_org == self.org_id:
            return

        from app.services.access.audit import CROSS_TENANT_DENIED, record_out_of_band

        await record_out_of_band(
            org_id=self.org_id,
            actor_id=self.actor_id,
            action=CROSS_TENANT_DENIED,
            resource=self.model.__tablename__,
            resource_id=str(entity_id),
            # The owning org is not named. Knowing *that* it belongs to someone
            # else is what the reviewer needs; naming the victim would put one
            # tenant's identity in another's audit trail.
            meta={"outcome": "not_found", "reason": "resource belongs to another tenant"},
        )

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
