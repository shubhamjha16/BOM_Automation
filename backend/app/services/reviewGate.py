"""The review gate. **Nothing is issued on one person's judgement** (§11).

Three rules, and the second is the one that actually bites:

1. **Approval requires manager or above.** Rank, checked in `access/authz.py`.
2. **The assessor who ran it cannot approve it, however senior.** A partner who
   wrote the assessment is still the same pair of eyes. Rank cannot express this,
   which is why it is a separate check rather than a permission.
3. **An unapproved export carries a watermark.** Drafts leave the building —
   emailed to a colleague, dropped in a shared folder — and a draft that looks
   like an issued assessment will eventually be read as one.

The watermark says "AI-assisted draft — not reviewed" because both halves matter:
that a model contributed, and that no human has signed it.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum

from app.models.enums import Role
from app.services.access.authz import can_approve

WATERMARK = "AI-assisted draft — not reviewed"


class AssessmentStatus(StrEnum):
    DRAFT = "draft"
    IN_REVIEW = "in_review"
    APPROVED = "approved"
    ISSUED = "issued"


#: Statuses whose exports carry the watermark. `approved` does not: a human has
#: signed it, which is precisely what the watermark denies.
UNREVIEWED = frozenset({AssessmentStatus.DRAFT, AssessmentStatus.IN_REVIEW})


class ReviewGateViolation(RuntimeError):
    """An attempt to approve or issue that the gate refuses."""


@dataclass(frozen=True, slots=True)
class ApprovalRequest:
    assessment_id: str
    current_status: AssessmentStatus
    authored_by: str | None
    approver_id: str
    approver_role: Role


def assert_can_approve(request: ApprovalRequest) -> None:
    """Raise unless this person may approve this assessment."""
    if not can_approve(request.approver_role):
        raise ReviewGateViolation(
            f"approval requires manager or above; {request.approver_role} cannot "
            "approve an assessment"
        )

    if request.authored_by and request.authored_by == request.approver_id:
        # The rule rank cannot express.
        raise ReviewGateViolation(
            "the assessor who ran this assessment cannot approve it. Nothing is "
            "issued on one person's judgement, and seniority does not make one "
            "person into two."
        )

    if request.current_status is AssessmentStatus.ISSUED:
        raise ReviewGateViolation("this assessment has already been issued")


def assert_can_issue(status: AssessmentStatus) -> None:
    """An assessment reaches `issued` only from `approved`."""
    if status is not AssessmentStatus.APPROVED:
        raise ReviewGateViolation(
            f"an assessment can only be issued from `approved`; this one is "
            f"`{status}`. Issuing an unapproved assessment is the thing the review "
            "gate exists to prevent."
        )


def requires_watermark(status: AssessmentStatus | str) -> bool:
    resolved = status if isinstance(status, AssessmentStatus) else AssessmentStatus(str(status))
    return resolved in UNREVIEWED


def watermark_for(status: AssessmentStatus | str) -> str | None:
    """The watermark text, or None once a human has approved it."""
    return WATERMARK if requires_watermark(status) else None
