"""User lookup.

**Deliberately not org-scoped, and the only repository that is not.** Sign-in
starts before a tenant is known — the email is what resolves the org, so a
scoped repository could not perform the lookup that establishes the scope.
Everything it returns carries an `org_id` that becomes the scope for every
subsequent repository, and it exposes no method that reads tenant data.
"""

from __future__ import annotations

import uuid

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.enums import Role
from app.models.user import User


class UserRepository:
    def __init__(self, session: AsyncSession) -> None:
        self.session = session

    async def by_email(self, email: str, *, org_id: uuid.UUID | None = None) -> User | None:
        """Case-insensitive, because email addresses are.

        `org_id` narrows the lookup when the tenant is already known — email is
        unique per org, not globally, so an address held at two firms resolves to
        two users and the caller must say which.
        """
        query = select(User).where(func.lower(User.email) == email.strip().lower())
        if org_id is not None:
            query = query.where(User.org_id == org_id)
        result = await self.session.execute(query)
        return result.scalars().first()

    async def by_google_sub(self, sub: str) -> User | None:
        result = await self.session.execute(select(User).where(User.google_sub == sub))
        return result.scalars().first()

    async def by_id(self, user_id: uuid.UUID, *, org_id: uuid.UUID) -> User | None:
        """Scoped: once a tenant is established, reads stay inside it."""
        result = await self.session.execute(
            select(User).where(User.id == user_id).where(User.org_id == org_id)
        )
        return result.scalars().first()

    async def create(
        self,
        *,
        org_id: uuid.UUID,
        email: str,
        hashed_password: str | None = None,
        google_sub: str | None = None,
        role: Role = Role.ASSESSOR,
    ) -> User:
        user = User(
            org_id=org_id,
            email=email.strip().lower(),
            hashed_password=hashed_password,
            google_sub=google_sub,
            role=role,
        )
        self.session.add(user)
        await self.session.flush()
        return user

    async def set_mfa(self, user: User, *, secret: str) -> User:
        """Persist the secret only once a code has proved the user holds it."""
        user.mfa_secret = secret
        user.mfa_enabled = True
        await self.session.flush()
        return user
