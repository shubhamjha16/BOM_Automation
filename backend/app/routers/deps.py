"""Shared route dependencies.

**The org scope is resolved here and nowhere else.** Every repository is
constructed from it, so a handler cannot obtain an unscoped repository even by
accident — there is no constructor that takes a session alone.

Real authentication lands in S5 with JWT, Google OAuth and enforced MFA. Until
then the scope comes from a header, which is why `main.py` mounts this only when
the deployment is not production and why the header is named as a development
affordance rather than something that looks like auth.
"""

from __future__ import annotations

import uuid
from typing import Annotated

from fastapi import Depends, Header, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession

from app.configs.dbConfig import get_session
from app.repositories.jobRepository import JobRepository
from app.repositories.submissionRepository import SubmissionRepository

SessionDep = Annotated[AsyncSession, Depends(get_session)]


async def current_org_id(
    x_dev_org_id: Annotated[str | None, Header(alias="X-Dev-Org-Id")] = None,
) -> uuid.UUID:
    """The tenant this request acts within.

    S5 replaces this with the JWT subject's org. The shape does not change:
    everything downstream already takes an org id and cannot be constructed
    without one.
    """
    if not x_dev_org_id:
        raise HTTPException(401, "X-Dev-Org-Id is required until authentication lands (S5)")
    try:
        return uuid.UUID(x_dev_org_id)
    except ValueError:
        raise HTTPException(401, "X-Dev-Org-Id is not a valid UUID") from None


OrgDep = Annotated[uuid.UUID, Depends(current_org_id)]


async def submission_repository(session: SessionDep, org_id: OrgDep) -> SubmissionRepository:
    return SubmissionRepository(session, org_id)


async def job_repository(session: SessionDep, org_id: OrgDep) -> JobRepository:
    return JobRepository(session, org_id)


SubmissionRepoDep = Annotated[SubmissionRepository, Depends(submission_repository)]
JobRepoDep = Annotated[JobRepository, Depends(job_repository)]
