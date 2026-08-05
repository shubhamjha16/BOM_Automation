"""Audit writing.

Refusals are audited because the caller is told nothing: a cross-tenant read
returns 404 so existence does not leak, which makes this table the only place the
attempt is recorded at all.
"""

from __future__ import annotations

import uuid
from typing import Any

from sqlalchemy.ext.asyncio import AsyncSession

from app.models.auditEvent import AuditEvent
from app.utils.logger import get_logger

logger = get_logger(__name__)

# Actions worth a permanent row rather than only a log line.
SIGNIN_SUCCEEDED = "auth.signin.succeeded"
SIGNIN_FAILED = "auth.signin.failed"
MFA_CHALLENGED = "auth.mfa.challenged"
MFA_FAILED = "auth.mfa.failed"
MFA_ENROLLED = "auth.mfa.enrolled"
SIGNUP = "auth.signup"
CROSS_TENANT_DENIED = "access.cross_tenant.denied"
SUBMISSION_CREATED = "submission.created"
ASSESSMENT_ENQUEUED = "assessment.enqueued"


async def record(
    session: AsyncSession,
    *,
    org_id: uuid.UUID,
    action: str,
    actor_id: uuid.UUID | None = None,
    resource: str | None = None,
    resource_id: str | None = None,
    meta: dict[str, Any] | None = None,
    ip: str | None = None,
) -> AuditEvent:
    """Write one audit row.

    `meta` must never carry BOM content — component names are supplier-controlled
    text and a BOM is an architecture disclosure. Identifiers and outcomes only.
    """
    event = AuditEvent(
        org_id=org_id,
        actor_id=actor_id,
        action=action,
        resource=resource,
        resource_id=resource_id,
        meta=meta,
        ip=ip,
    )
    session.add(event)
    await session.flush()
    logger.info("audit", action=action, org_id=str(org_id), resource_id=resource_id)
    return event


async def record_out_of_band(
    *,
    org_id: uuid.UUID,
    action: str,
    actor_id: uuid.UUID | None = None,
    resource: str | None = None,
    resource_id: str | None = None,
    meta: dict[str, Any] | None = None,
) -> None:
    """Write one audit row on its own session, committed independently.

    **A denial ends in an exception, and the request session is rolled back when
    it does.** An audit row written on that session would be discarded along with
    the 404 — the record would disappear at exactly the moment it mattered. So
    the refusal path gets its own connection and its own commit.

    Failure to audit never propagates: an attacker who could make this write fail
    would otherwise be able to convert a logged denial into a 500, which is both
    a different response and a louder oracle than the 404 they were given.
    """
    from app.configs.dbConfig import get_sessionmaker

    try:
        async with get_sessionmaker()() as session:
            await record(
                session,
                org_id=org_id,
                action=action,
                actor_id=actor_id,
                resource=resource,
                resource_id=resource_id,
                meta=meta,
            )
            await session.commit()
    except Exception as error:  # pragma: no cover - never masks the denial
        logger.error("audit_write_failed", action=action, error=str(error))
