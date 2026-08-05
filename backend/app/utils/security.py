"""Password hashing, token signing and TOTP.

Kept together because they are the primitives auth is built from, and separate
from `services/access/` which decides what a caller may *do*. Nothing here reads
a database or knows what a user is.
"""

from __future__ import annotations

import hmac
import secrets
import uuid
from datetime import UTC, datetime, timedelta
from typing import Any, Literal

import jwt
import pyotp
from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerifyMismatchError

from app.configs.envConfig import settings

#: Argon2id — memory-hard, so a stolen hash dump is expensive to attack on GPUs
#: in a way bcrypt's fixed memory footprint is not.
_hasher = PasswordHasher()

TokenKind = Literal["access", "refresh", "mfa_pending"]


class InvalidToken(ValueError):
    """The token is malformed, expired, or not the kind that was expected."""


# --- passwords --------------------------------------------------------------


def hash_password(password: str) -> str:
    return _hasher.hash(password)


def verify_password(password: str, hashed: str) -> bool:
    """Constant-time where it matters; never raises on a bad hash."""
    try:
        return _hasher.verify(hashed, password)
    except (VerifyMismatchError, InvalidHashError, TypeError):
        return False


def needs_rehash(hashed: str) -> bool:
    """True when the stored hash predates the current parameters."""
    try:
        return _hasher.check_needs_rehash(hashed)
    except InvalidHashError:
        return True


# --- tokens -----------------------------------------------------------------


def _ttl(kind: TokenKind) -> timedelta:
    if kind == "refresh":
        return timedelta(days=settings.REFRESH_TOKEN_TTL_DAYS)
    if kind == "mfa_pending":
        # Deliberately short: this token proves a password was accepted and
        # nothing more. It cannot read anything.
        return timedelta(minutes=5)
    return timedelta(minutes=settings.ACCESS_TOKEN_TTL_MINUTES)


def issue_token(
    *,
    user_id: uuid.UUID,
    org_id: uuid.UUID,
    role: str,
    kind: TokenKind = "access",
    mfa_satisfied: bool = False,
) -> str:
    """Sign a token carrying the tenant scope.

    `org_id` is in the token because it is the tenant boundary, and resolving it
    per request from a database read would be one more place to get wrong. It is
    still never trusted as authorisation on its own — the repository layer
    enforces the scope regardless of where it came from.
    """
    now = datetime.now(UTC)
    payload = {
        "sub": str(user_id),
        "org": str(org_id),
        "role": role,
        "kind": kind,
        "mfa": mfa_satisfied,
        "iat": now,
        "exp": now + _ttl(kind),
        "jti": secrets.token_urlsafe(16),
    }
    return jwt.encode(payload, settings.JWT_SECRET, algorithm=settings.JWT_ALGORITHM)


def decode_token(token: str, *, expect: TokenKind = "access") -> dict[str, Any]:
    """Verify and decode, refusing a token of the wrong kind.

    Checking `kind` is what stops a refresh token — or, worse, the short-lived
    `mfa_pending` token — being presented as an access token. Without it,
    surviving a password check would be enough to read a submission.
    """
    try:
        claims = jwt.decode(
            token,
            settings.JWT_SECRET,
            algorithms=[settings.JWT_ALGORITHM],
            options={"require": ["exp", "sub", "org", "kind"]},
        )
    except jwt.ExpiredSignatureError:
        raise InvalidToken("token has expired") from None
    except jwt.InvalidTokenError as error:
        raise InvalidToken(f"token is not valid: {error}") from None

    if not hmac.compare_digest(str(claims.get("kind")), expect):
        raise InvalidToken(f"expected a {expect} token, got {claims.get('kind')!r}")
    return claims


# --- MFA --------------------------------------------------------------------


def new_mfa_secret() -> str:
    return pyotp.random_base32()


def mfa_provisioning_uri(secret: str, *, email: str, issuer: str = "BOM Automation") -> str:
    return pyotp.TOTP(secret).provisioning_uri(name=email, issuer_name=issuer)


def verify_totp(secret: str, code: str) -> bool:
    """One step of clock drift either way, and no more.

    A wider window is a longer replay opportunity on a code that is only six
    digits to begin with.
    """
    if not secret or not code:
        return False
    return pyotp.TOTP(secret).verify(code.strip(), valid_window=1)
