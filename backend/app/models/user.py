"""Users belong to exactly one org. Roles gate what the console reveals; the
repository layer gates what is reachable at all.
"""

from __future__ import annotations

import uuid

from sqlalchemy import Boolean, Enum, ForeignKey, String, UniqueConstraint, Uuid
from sqlalchemy.orm import Mapped, mapped_column

from app.models.base import Base, Timestamped, UuidPrimaryKey
from app.models.enums import Role


class User(UuidPrimaryKey, Timestamped, Base):
    __tablename__ = "users"
    __table_args__ = (
        # Email is unique per org, not globally: the same person may hold an
        # account at two firms using this platform.
        UniqueConstraint("org_id", "email", name="uq_users_org_id_email"),
    )

    org_id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True), ForeignKey("orgs.id", ondelete="CASCADE"), nullable=False, index=True
    )
    email: Mapped[str] = mapped_column(String(320), nullable=False)
    hashed_password: Mapped[str | None] = mapped_column(String(255))
    google_sub: Mapped[str | None] = mapped_column(String(255), unique=True)
    role: Mapped[Role] = mapped_column(
        Enum(Role, name="user_role", values_callable=lambda enum: [item.value for item in enum]),
        nullable=False,
        default=Role.ASSESSOR,
    )
    mfa_enabled: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    #: TOTP shared secret. Null until enrolment completes — a secret is generated
    #: at enrolment but only stored once a code proves the user has it, so a
    #: half-finished enrolment cannot lock anyone out.
    mfa_secret: Mapped[str | None] = mapped_column(String(64))
    is_active: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
