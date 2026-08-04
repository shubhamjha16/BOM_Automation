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
