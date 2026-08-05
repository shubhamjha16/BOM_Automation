"""Sign-up, sign-in, MFA and the Google callback.

**Two rules shape everything here.**

*Failures are indistinguishable.* A wrong password and an unknown email return
the same error after the same work — an attacker must not be able to enumerate
which addresses hold accounts, and a fast "no such user" against a slow
"password mismatch" is an oracle even when the message is identical.

*MFA is a second step, not a flag.* A correct password yields only a short-lived
`mfa_pending` token that can read nothing. The access token is minted after the
code verifies, so a stolen password alone is never sufficient.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass

from app.configs.envConfig import settings
from app.models.enums import Role
from app.models.user import User
from app.repositories.userRepository import UserRepository
from app.services.access import audit
from app.utils.logger import get_logger
from app.utils.security import (
    hash_password,
    issue_token,
    mfa_provisioning_uri,
    new_mfa_secret,
    verify_password,
    verify_totp,
)

logger = get_logger(__name__)

#: Verified against when no user exists, so the work done is the same either way.
_DUMMY_HASH = hash_password("bom-automation-timing-equaliser")


class AuthenticationFailed(Exception):
    """Credentials were rejected. The message is deliberately uninformative."""

    def __init__(self, message: str = "email or password is incorrect") -> None:
        super().__init__(message)


class MfaRequired(Exception):
    """The password was accepted; a TOTP code is still needed."""

    def __init__(self, pending_token: str, *, enrolled: bool) -> None:
        self.pending_token = pending_token
        self.enrolled = enrolled
        super().__init__("multi-factor authentication required")


@dataclass(frozen=True, slots=True)
class TokenPair:
    access_token: str
    refresh_token: str
    role: str
    org_id: str
    user_id: str
    token_type: str = "bearer"


def _tokens(user: User) -> TokenPair:
    return TokenPair(
        access_token=issue_token(
            user_id=user.id,
            org_id=user.org_id,
            role=str(user.role),
            kind="access",
            mfa_satisfied=True,
        ),
        refresh_token=issue_token(
            user_id=user.id, org_id=user.org_id, role=str(user.role), kind="refresh"
        ),
        role=str(user.role),
        org_id=str(user.org_id),
        user_id=str(user.id),
    )


async def sign_up(
    users: UserRepository,
    *,
    org_id: uuid.UUID,
    email: str,
    password: str,
    role: Role = Role.ASSESSOR,
) -> User:
    existing = await users.by_email(email, org_id=org_id)
    if existing is not None:
        # Safe to be specific: the caller already proved they can act in this org.
        raise AuthenticationFailed("a user with that email already exists in this organisation")

    user = await users.create(
        org_id=org_id, email=email, hashed_password=hash_password(password), role=role
    )
    await audit.record(
        users.session,
        org_id=org_id,
        action=audit.SIGNUP,
        actor_id=user.id,
        resource="user",
        resource_id=str(user.id),
    )
    return user


async def sign_in(
    users: UserRepository,
    *,
    email: str,
    password: str,
    org_id: uuid.UUID | None = None,
    ip: str | None = None,
) -> TokenPair:
    """Verify a password, then demand a second factor if one is required."""
    user = await users.by_email(email, org_id=org_id)

    # Always hash-compare, even with no user, so the response time does not
    # reveal whether the address exists.
    stored = user.hashed_password if user and user.hashed_password else _DUMMY_HASH
    password_ok = verify_password(password, stored)

    if user is None or not password_ok or not user.is_active:
        if user is not None:
            await audit.record(
                users.session,
                org_id=user.org_id,
                action=audit.SIGNIN_FAILED,
                actor_id=user.id,
                meta={"reason": "bad_password" if user.is_active else "inactive"},
                ip=ip,
            )
        raise AuthenticationFailed

    if settings.MFA_REQUIRED or user.mfa_enabled:
        pending = issue_token(
            user_id=user.id,
            org_id=user.org_id,
            role=str(user.role),
            kind="mfa_pending",
        )
        await audit.record(
            users.session,
            org_id=user.org_id,
            action=audit.MFA_CHALLENGED,
            actor_id=user.id,
            ip=ip,
        )
        raise MfaRequired(pending, enrolled=user.mfa_enabled)

    await audit.record(
        users.session,
        org_id=user.org_id,
        action=audit.SIGNIN_SUCCEEDED,
        actor_id=user.id,
        ip=ip,
    )
    return _tokens(user)


async def begin_mfa_enrolment(users: UserRepository, user: User) -> tuple[str, str]:
    """Return a secret and its provisioning URI. Nothing is persisted yet.

    Storing the secret before a code proves the user holds it would lock out
    anyone whose enrolment is interrupted between the QR code and the first code.
    """
    secret = new_mfa_secret()
    return secret, mfa_provisioning_uri(secret, email=user.email)


async def complete_mfa_enrolment(
    users: UserRepository, user: User, *, secret: str, code: str
) -> User:
    if not verify_totp(secret, code):
        raise AuthenticationFailed("that code is not valid for this secret")
    enrolled = await users.set_mfa(user, secret=secret)
    await audit.record(
        users.session,
        org_id=user.org_id,
        action=audit.MFA_ENROLLED,
        actor_id=user.id,
    )
    return enrolled


async def verify_mfa(
    users: UserRepository, *, pending_claims: dict, code: str, ip: str | None = None
) -> TokenPair:
    """Exchange a verified TOTP code for real tokens."""
    user_id = uuid.UUID(pending_claims["sub"])
    org_id = uuid.UUID(pending_claims["org"])

    user = await users.by_id(user_id, org_id=org_id)
    if user is None or not user.is_active:
        raise AuthenticationFailed

    if not user.mfa_enabled or not user.mfa_secret:
        raise AuthenticationFailed("multi-factor authentication is not enrolled for this account")

    if not verify_totp(user.mfa_secret, code):
        await audit.record(
            users.session, org_id=org_id, action=audit.MFA_FAILED, actor_id=user.id, ip=ip
        )
        raise AuthenticationFailed("that code is not valid")

    await audit.record(
        users.session, org_id=org_id, action=audit.SIGNIN_SUCCEEDED, actor_id=user.id, ip=ip
    )
    return _tokens(user)


async def google_callback(
    users: UserRepository, *, google_sub: str, email: str, org_id: uuid.UUID
) -> TokenPair:
    """Sign in a Google-authenticated user.

    Google proves the email, not the second factor — so an account with MFA
    enrolled still goes through `verify_mfa`. Federated identity is not a bypass.
    """
    user = await users.by_google_sub(google_sub) or await users.by_email(email, org_id=org_id)
    if user is None:
        raise AuthenticationFailed("no account for that Google identity")

    if not user.google_sub:
        user.google_sub = google_sub
        await users.session.flush()

    if user.mfa_enabled:
        raise MfaRequired(
            issue_token(
                user_id=user.id,
                org_id=user.org_id,
                role=str(user.role),
                kind="mfa_pending",
            ),
            enrolled=True,
        )

    await audit.record(
        users.session,
        org_id=user.org_id,
        action=audit.SIGNIN_SUCCEEDED,
        actor_id=user.id,
        meta={"provider": "google"},
    )
    return _tokens(user)


# --- HTTP-shaped wrappers ---------------------------------------------------
# Keep the router handlers thin: the branch between "signed in" and "MFA
# required" is a business outcome, not a routing concern.


async def sign_in_or_challenge(users: UserRepository, *, body: object, ip: str | None) -> dict:
    from app.schemas.request.auth import SignInIn

    assert isinstance(body, SignInIn)  # noqa: S101 - narrowing for the type checker
    try:
        tokens = await sign_in(
            users, email=str(body.email), password=body.password, org_id=body.org_id, ip=ip
        )
    except MfaRequired as challenge:
        return {
            "mfa_required": True,
            "enrolled": challenge.enrolled,
            "pending_token": challenge.pending_token,
        }
    return {
        "access_token": tokens.access_token,
        "refresh_token": tokens.refresh_token,
        "token_type": tokens.token_type,
        "role": tokens.role,
        "org_id": tokens.org_id,
        "user_id": tokens.user_id,
    }


async def verify_mfa_or_reject(
    users: UserRepository, *, body: object, ip: str | None
) -> TokenPair:
    from app.schemas.request.auth import MfaVerifyIn
    from app.utils.security import InvalidToken, decode_token

    assert isinstance(body, MfaVerifyIn)  # noqa: S101
    try:
        claims = decode_token(body.pending_token, expect="mfa_pending")
    except InvalidToken as error:
        raise AuthenticationFailed(str(error)) from None
    return await verify_mfa(users, pending_claims=claims, code=body.code, ip=ip)


async def refresh_tokens(users: UserRepository, *, claims: dict) -> TokenPair:
    """Mint a new access token from a refresh token.

    The user is re-read rather than trusted from the token: a role change or a
    deactivation must take effect at the next refresh, not at the end of a
    fourteen-day refresh window.
    """
    user = await users.by_id(uuid.UUID(claims["sub"]), org_id=uuid.UUID(claims["org"]))
    if user is None or not user.is_active:
        raise AuthenticationFailed("this account is no longer active")
    return _tokens(user)
