"""Auth response bodies."""

from __future__ import annotations

from pydantic import BaseModel


class TokenOut(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"
    role: str
    org_id: str
    user_id: str


class MfaChallengeOut(BaseModel):
    """Returned instead of tokens when a second factor is required.

    Carries no access of any kind: `pending_token` proves only that a password
    was accepted, and expires in five minutes.
    """

    mfa_required: bool = True
    enrolled: bool
    pending_token: str


class MfaEnrolmentOut(BaseModel):
    secret: str
    provisioning_uri: str


class UserOut(BaseModel):
    id: str
    email: str
    role: str
    org_id: str
    mfa_enabled: bool
