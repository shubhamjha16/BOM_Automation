"""What a caller may do, given their role.

Separate from tenancy, which is not a role question: **no role grants access to
another org's data.** A partner at firm A has no more reach into firm B than an
anonymous request does, because the boundary is enforced in the repository layer
and the repository is constructed from the token's org.

This module answers the second question — within their own tenant, may this user
perform this action?
"""

from __future__ import annotations

from app.models.enums import Role

#: Ordered by breadth. Used for "at least this role" checks, never for tenancy.
ROLE_RANK: dict[Role, int] = {
    Role.CLIENT: 0,
    Role.READONLY: 1,
    Role.ASSESSOR: 2,
    Role.MANAGER: 3,
    Role.PARTNER: 4,
}


class Forbidden(PermissionError):
    """The caller's role does not permit this action within their own org."""


def at_least(role: Role, minimum: Role) -> bool:
    return ROLE_RANK[role] >= ROLE_RANK[minimum]


def require(role: Role, minimum: Role, *, action: str) -> None:
    if not at_least(role, minimum):
        raise Forbidden(f"{action} requires {minimum} or above; caller is {role}")


def can_submit(role: Role) -> bool:
    """A readonly user cannot create work; a client submits into their own
    engagement, which is why they are permitted here and not by rank."""
    return role in (Role.PARTNER, Role.MANAGER, Role.ASSESSOR, Role.CLIENT)


def can_approve(role: Role) -> bool:
    """Manager or above (S13). Approval is also subject to a separation rule the
    rank cannot express: the assessor who ran an assessment may never approve it,
    however senior they are."""
    return at_least(role, Role.MANAGER)


def may_approve_assessment(role: Role, *, assessor_id: str, approver_id: str) -> bool:
    """Nothing is issued on one person's judgement.

    Rank alone is not enough: a manager who ran the assessment is still the same
    pair of eyes, so self-approval is refused regardless of role.
    """
    return can_approve(role) and assessor_id != approver_id


def engagement_visible(role: Role, *, user_engagement_ids: set[str], engagement_id: str) -> bool:
    """A `client` user sees only their own engagement.

    Every other role sees their org's engagements — the org boundary already
    contained them before this check ran.
    """
    if role is Role.CLIENT:
        return engagement_id in user_engagement_ids
    return True
