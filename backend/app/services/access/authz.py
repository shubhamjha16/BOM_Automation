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
from app.services.access.matrix import Action, Resource, may

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


# The predicates below read the matrix rather than restate it. Two hand-written
# lists of roles drift the moment one of them is edited, and the drift is silent
# — the endpoint keeps working while the documented matrix quietly stops
# describing it.
def can_submit(role: Role) -> bool:
    """Neither `readonly` nor `client` may create work.

    This corrects an inconsistency the matrix exposed: `can_submit` used to admit
    `client` while `is_read_only` also called the same role read-only, and both
    were true at once because nothing forced them to agree. §S16 specifies a
    *read-only* client role, so the matrix records no submission-create
    permission for it and both predicates now follow from that one cell.
    """
    return may(role, Resource.SUBMISSION, Action.CREATE)


def can_approve(role: Role) -> bool:
    """Manager or above (S13). Approval is also subject to a separation rule no
    matrix cell can express: the assessor who ran an assessment may never approve
    it, however senior they are — see `may_approve_assessment`."""
    return may(role, Resource.ASSESSMENT, Action.APPROVE)


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


def engagement_scope_for(
    role: Role, *, assigned_engagement_ids: set[str]
) -> frozenset[str] | None:
    """The engagement scope a repository should be constructed with.

    `None` means "every engagement in the org" — what an assessor, manager or
    partner sees. A `client` gets a frozenset of exactly their own, and the
    restriction is then enforced in `repositories/base.scoped()` rather than in a
    router, for the same reason tenancy is.
    """
    if role is Role.CLIENT:
        return frozenset(assigned_engagement_ids)
    return None


def is_read_only(role: Role) -> bool:
    """`readonly` and `client` may not create work."""
    return not may(role, Resource.SUBMISSION, Action.CREATE)
