"""VEX authoring. The four statuses of rec. 7.1.6 are exhaustive.

**Why "exhaustive" is enforced rather than documented.** VEX exists so a consumer
can act on a vulnerability report without re-doing the analysis. That only works
if every statement means one of four things. A fifth status — `mitigated`,
`partially_affected`, `wont_fix` — is not a richer vocabulary; it is a statement
the consumer's tooling cannot interpret, and an uninterpretable VEX statement is
worse than none because it looks like an answer.

**A `not_affected` determination requires a written justification.** It is the
strongest claim in VEX: it tells a consumer to stop worrying about a
vulnerability that is genuinely present in a component they are running. Made
without a reason, it is indistinguishable from not having looked.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import StrEnum
from typing import Any


class VexStatus(StrEnum):
    """The four, and only four, statuses of recommendation 7.1.6."""

    NOT_AFFECTED = "not_affected"
    AFFECTED = "affected"
    FIXED = "fixed"
    UNDER_INVESTIGATION = "under_investigation"


VALID_STATUSES: tuple[str, ...] = tuple(status.value for status in VexStatus)

#: Statuses that require a written justification before they can be saved.
#: `not_affected` because it tells a consumer to stop looking; `fixed` because it
#: asserts a remediation exists, which a consumer will act on by upgrading.
REQUIRES_JUSTIFICATION: frozenset[VexStatus] = frozenset(
    {VexStatus.NOT_AFFECTED, VexStatus.FIXED}
)

#: A justification has to say something. These are the shapes of "nothing".
_EMPTY_JUSTIFICATIONS = frozenset(
    {"n/a", "na", "none", "-", "tbd", "not applicable", "no", "ok", "fine", "checked"}
)

MINIMUM_JUSTIFICATION_CHARS = 20

_CVE = re.compile(r"^CVE-\d{4}-\d{4,}$", re.IGNORECASE)


class InvalidVexStatement(ValueError):
    """The statement is not conformant with rec. 7.1.6."""


@dataclass(frozen=True, slots=True)
class VexStatement:
    cve_id: str
    status: VexStatus
    justification: str | None = None
    component_ref: str | None = None
    authored_by: str | None = None
    reviewed_by: str | None = None
    created_at: datetime = field(default_factory=lambda: datetime.now(UTC))
    #: Evidence the S12 agent assembled. Advisory, never authority.
    evidence_refs: tuple[str, ...] = ()

    @property
    def is_reviewed(self) -> bool:
        return bool(self.reviewed_by)

    def as_row(self) -> dict[str, Any]:
        return {
            "cve_id": self.cve_id,
            "status": str(self.status),
            "justification": self.justification,
            "component_ref": self.component_ref,
            "authored_by": self.authored_by,
            "reviewed_by": self.reviewed_by,
            "evidence_refs": list(self.evidence_refs),
        }


def parse_status(raw: str) -> VexStatus:
    """Map a string to a status, or refuse it naming all four valid ones."""
    try:
        return VexStatus(str(raw).strip().lower())
    except ValueError:
        raise InvalidVexStatement(
            f"{raw!r} is not a valid VEX status. Recommendation 7.1.6 defines four "
            f"exhaustive statuses: {', '.join(VALID_STATUSES)}. A fifth status is "
            "not a richer vocabulary — it is a statement a consumer's tooling "
            "cannot interpret."
        ) from None


def validate_justification(status: VexStatus, justification: str | None) -> None:
    """Refuse a determination that asserts something without saying why."""
    if status not in REQUIRES_JUSTIFICATION:
        return

    text = (justification or "").strip()
    if not text:
        raise InvalidVexStatement(
            f"a {status} statement requires a written justification. It is the "
            "strongest claim in VEX — it tells a consumer to stop investigating a "
            "vulnerability that is present in what they are running — and without "
            "a reason it is indistinguishable from not having looked."
        )
    if text.lower() in _EMPTY_JUSTIFICATIONS or len(text) < MINIMUM_JUSTIFICATION_CHARS:
        raise InvalidVexStatement(
            f"the justification for a {status} statement is too thin to act on "
            f"({text!r}). A consumer has to be able to check the reasoning, not "
            "merely observe that a box was filled."
        )


def author(
    *,
    cve_id: str,
    status: str | VexStatus,
    justification: str | None = None,
    component_ref: str | None = None,
    authored_by: str | None = None,
    evidence_refs: tuple[str, ...] = (),
) -> VexStatement:
    """Create a VEX statement, or refuse it.

    Every refusal here names the rule it enforces, because the person hitting it
    is an analyst mid-workflow who needs to know what to do differently.
    """
    identifier = str(cve_id).strip().upper()
    if not _CVE.match(identifier):
        raise InvalidVexStatement(
            f"{cve_id!r} is not a CVE identifier (expected CVE-YYYY-NNNN). A VEX "
            "statement is about a specific vulnerability."
        )

    resolved = status if isinstance(status, VexStatus) else parse_status(status)
    validate_justification(resolved, justification)

    return VexStatement(
        cve_id=identifier,
        status=resolved,
        justification=(justification or "").strip() or None,
        component_ref=component_ref,
        authored_by=authored_by,
        evidence_refs=evidence_refs,
    )


def default_status_for_insufficient_evidence() -> VexStatus:
    """What to propose when the evidence does not support a determination.

    `under_investigation` — the honest answer, and the only one that does not
    assert something unproven. Reasoning toward `not_affected` because nothing
    was found is how an absence of evidence becomes a clearance.
    """
    return VexStatus.UNDER_INVESTIGATION
