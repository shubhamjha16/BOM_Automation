"""Connecting a repository. Read-only scope, always.

**The permission set is the security control.** A conformance platform needs to
read manifests and nothing else: no write access, no secrets, no Actions. An
integration that asks for more is one whose compromise costs a client their
source, and the ask itself is what a security reviewer will object to first.

Live token exchange is not implemented here — it needs GitHub App credentials
this environment does not have — and the module says so rather than shipping an
untested auth path that appears to work.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum

from app.configs.envConfig import settings


class Provider(StrEnum):
    GITHUB = "github"
    GITLAB = "gitlab"


#: The only permissions this platform requests. Read-only, contents and
#: metadata: enough to clone and read manifests, and nothing more.
REQUIRED_SCOPES: dict[Provider, tuple[str, ...]] = {
    Provider.GITHUB: ("contents:read", "metadata:read"),
    Provider.GITLAB: ("read_repository",),
}

FORBIDDEN_SCOPES: frozenset[str] = frozenset(
    {
        "contents:write",
        "actions:write",
        "secrets:read",
        "administration:write",
        "write_repository",
        "api",
    }
)


class ScopeTooBroad(ValueError):
    """An installation granted more than this platform should ever hold."""


class ConnectionUnavailable(RuntimeError):
    """The provider integration is not configured in this deployment."""


@dataclass(frozen=True, slots=True)
class Connection:
    provider: Provider
    full_name: str
    default_branch: str
    installation_id: str
    scopes: tuple[str, ...]


def assert_scopes_minimal(provider: Provider, granted: tuple[str, ...]) -> None:
    """Refuse an installation that holds write access.

    Checked on connect rather than trusted from the app manifest: an
    organisation administrator can grant more than the app requested, and
    holding write access to a client's source is a liability whether or not it is
    used.
    """
    excessive = sorted(set(granted) & FORBIDDEN_SCOPES)
    if excessive:
        raise ScopeTooBroad(
            f"this installation granted {excessive}, which this platform must never "
            f"hold. It requires {list(REQUIRED_SCOPES[provider])} and nothing more — "
            "reduce the installation's permissions and reconnect."
        )


def is_configured(provider: Provider) -> bool:
    if provider is Provider.GITHUB:
        return bool(settings.GOOGLE_CLIENT_ID) is not None and bool(
            getattr(settings, "GITHUB_APP_ID", None)
        )
    return bool(getattr(settings, "GITLAB_WEBHOOK_SECRET", None))


def connect(
    provider: Provider, *, full_name: str, default_branch: str, installation_id: str,
    granted_scopes: tuple[str, ...],
) -> Connection:
    """Record a connection after checking its scope."""
    assert_scopes_minimal(provider, granted_scopes)
    return Connection(
        provider=provider,
        full_name=full_name,
        default_branch=default_branch,
        installation_id=installation_id,
        scopes=granted_scopes,
    )
