"""Audit events.

Written for authentication outcomes and for refusals. A denied cross-tenant read
returns 404 to the caller so existence does not leak, which means the *only*
record that the attempt happened is this table — without it, probing another
org's submission ids is indistinguishable from ordinary 404 traffic.
"""

from __future__ import annotations

import uuid

from sqlalchemy import ForeignKey, Index, String, Uuid
from sqlalchemy.orm import Mapped, mapped_column

from app.models.base import Base, Timestamped, UuidPrimaryKey, jsonb


class AuditEvent(UuidPrimaryKey, Timestamped, Base):
    __tablename__ = "audit_events"
    __table_args__ = (
        Index("ix_audit_events_org_id_created_at", "org_id", "created_at"),
        Index("ix_audit_events_action", "action"),
    )

    org_id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True), ForeignKey("orgs.id", ondelete="CASCADE"), nullable=False, index=True
    )
    #: Nullable: a failed sign-in has no authenticated actor by definition.
    actor_id: Mapped[uuid.UUID | None] = mapped_column(
        Uuid(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL")
    )
    action: Mapped[str] = mapped_column(String(64), nullable=False)
    resource: Mapped[str | None] = mapped_column(String(64))
    resource_id: Mapped[str | None] = mapped_column(String(64))
    meta: Mapped[dict | None] = mapped_column(jsonb())
    ip: Mapped[str | None] = mapped_column(String(45))
