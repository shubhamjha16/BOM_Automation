"""Auth request bodies."""

from __future__ import annotations

from uuid import UUID

from pydantic import BaseModel, EmailStr, Field


class SignUpIn(BaseModel):
    org_id: UUID
    email: EmailStr
    #: Length is the control that matters most; complexity rules push users
    #: toward predictable substitutions.
    password: str = Field(min_length=12, max_length=256)
    role: str = "assessor"


class SignInIn(BaseModel):
    email: EmailStr
    password: str = Field(min_length=1, max_length=256)
    #: Email is unique per org, not globally, so an address held at two firms
    #: needs the tenant naming which account to sign in to.
    org_id: UUID | None = None


class MfaVerifyIn(BaseModel):
    pending_token: str
    code: str = Field(min_length=6, max_length=6, pattern=r"^\d{6}$")


class MfaEnrolIn(BaseModel):
    secret: str
    code: str = Field(min_length=6, max_length=6, pattern=r"^\d{6}$")
