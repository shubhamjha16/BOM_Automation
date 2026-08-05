"""Shared route dependencies.

**The org scope is resolved here and nowhere else.** It comes from the verified
JWT, and every repository is constructed from it — a handler cannot obtain an
unscoped repository even by accident, because no repository constructor takes a
session alone.

The token carries the org, but the token is not the enforcement. The repository
layer applies the scope to every query regardless of where it came from, so a
forged or swapped claim still cannot reach another tenant's rows.
"""

from __future__ import annotations

import uuid
from typing import Annotated

from fastapi import Depends, HTTPException
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy.ext.asyncio import AsyncSession

from app.configs.dbConfig import get_session
from app.configs.envConfig import settings
from app.models.enums import Role
from app.models.user import User
from app.repositories.jobRepository import JobRepository
from app.repositories.laneRepository import LaneRepository
from app.repositories.submissionRepository import SubmissionRepository
from app.repositories.userRepository import UserRepository
from app.utils.security import InvalidToken, decode_token

SessionDep = Annotated[AsyncSession, Depends(get_session)]


bearer = HTTPBearer(auto_error=False)


async def current_claims(
    credentials: Annotated[HTTPAuthorizationCredentials | None, Depends(bearer)] = None,
) -> dict:
    """Verify the bearer token and return its claims.

    `expect="access"` is what stops a refresh token — or the short-lived
    `mfa_pending` token, which proves only that a password was accepted — being
    presented here. Without that check, surviving a password prompt would be
    enough to read a submission.
    """
    if credentials is None or not credentials.credentials:
        raise HTTPException(401, "authentication required", {"WWW-Authenticate": "Bearer"})
    try:
        claims = decode_token(credentials.credentials, expect="access")
    except InvalidToken as error:
        raise HTTPException(401, str(error), {"WWW-Authenticate": "Bearer"}) from None
    if settings.MFA_REQUIRED and not claims.get("mfa"):
        raise HTTPException(401, "multi-factor authentication was not completed")
    return claims


ClaimsDep = Annotated[dict, Depends(current_claims)]


async def current_org_id(claims: ClaimsDep) -> uuid.UUID:
    """The tenant this request acts within, from the verified token."""
    return uuid.UUID(claims["org"])


async def current_actor_id(claims: ClaimsDep) -> uuid.UUID:
    """Who is acting, for the audit trail. Not an authorisation input."""
    return uuid.UUID(claims["sub"])


async def current_role(claims: ClaimsDep) -> Role:
    return Role(claims["role"])


async def user_repository(session: SessionDep) -> UserRepository:
    return UserRepository(session)


UserRepoDep = Annotated[UserRepository, Depends(user_repository)]


async def current_user(claims: ClaimsDep, users: UserRepoDep) -> User:
    """The acting user, re-read rather than reconstructed from the token.

    A deactivated account must stop working immediately, not at token expiry.
    """
    user = await users.by_id(uuid.UUID(claims["sub"]), org_id=uuid.UUID(claims["org"]))
    if user is None or not user.is_active:
        raise HTTPException(401, "this account is no longer active")
    return user


OrgDep = Annotated[uuid.UUID, Depends(current_org_id)]
ActorDep = Annotated[uuid.UUID, Depends(current_actor_id)]
RoleDep = Annotated[Role, Depends(current_role)]
CurrentUserDep = Annotated[User, Depends(current_user)]


# Every repository is handed the acting user as well as the tenant. The actor is
# never an authorisation input — the org scope decides what is reachable — but a
# denied cross-tenant read is audited, and an audit row without an actor names
# only the firm, not the person.
async def submission_repository(
    session: SessionDep, org_id: OrgDep, actor_id: ActorDep
) -> SubmissionRepository:
    return SubmissionRepository(session, org_id, actor_id=actor_id)


async def job_repository(session: SessionDep, org_id: OrgDep, actor_id: ActorDep) -> JobRepository:
    return JobRepository(session, org_id, actor_id=actor_id)


async def lane_repository(
    session: SessionDep, org_id: OrgDep, actor_id: ActorDep
) -> LaneRepository:
    return LaneRepository(session, org_id, actor_id=actor_id)


SubmissionRepoDep = Annotated[SubmissionRepository, Depends(submission_repository)]
JobRepoDep = Annotated[JobRepository, Depends(job_repository)]
LaneRepoDep = Annotated[LaneRepository, Depends(lane_repository)]
