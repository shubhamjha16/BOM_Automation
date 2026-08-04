"""Score → verdict. The threshold comparison, and the critical-gap override.

Kept separate from `weighting.py` because the override is not arithmetic: a
critical element at zero coverage fails the lane at any score, and that rule has
to be visible rather than buried in a sum.
"""

from __future__ import annotations

from collections.abc import Sequence
from typing import Any

from app.configs.jobTypes import LaneVerdict
from app.configs.scoringConfig import (
    CONDITIONAL_FLOOR,
    CRITICAL_GAP_FAILS_SUBMISSION,
    PASS_THRESHOLD,
)
from app.services.score.fieldCheck import FieldResult


def critical_gaps(results: Sequence[FieldResult]) -> list[FieldResult]:
    return [result for result in results if result.is_critical_gap]


def lane_verdict(
    score: float,
    results: Sequence[FieldResult],
    *,
    configuration_findings: Sequence[Any] = (),
) -> tuple[LaneVerdict, str]:
    """The lane's verdict and the sentence explaining it.

    **A high-severity configuration finding caps the verdict below `pass`.**
    Coverage measures whether a supplier *declared* their cryptography; it cannot
    see that what they declared is an expired certificate, TLS 1.0 and 3DES. A
    lane reporting `pass` on that document would be complete, arithmetically
    correct, and wrong in the client's favour — the same failure mode §11 forbids
    when it refuses to score a `not_determinable` field as compliant.

    The finding does not zero the score. Declaration quality and configuration
    quality are different measurements and the assessment reports both; what the
    cap prevents is the *verdict* claiming the second when it measured the first.
    """
    severe = [
        finding
        for finding in configuration_findings
        if str(getattr(finding, "severity", "")) in ("high", "critical")
    ]
    gaps = critical_gaps(results)
    if gaps and CRITICAL_GAP_FAILS_SUBMISSION:
        clauses = ", ".join(f"{gap.clause} {gap.label}" for gap in gaps)
        return (
            LaneVerdict.FAIL,
            f"scored {score}% but fails on critical gap(s): {clauses} — absent across "
            "every entity",
        )
    if score >= PASS_THRESHOLD:
        if severe:
            clauses = ", ".join(
                f"s.{getattr(finding, 'clause', '?')} {getattr(finding, 'check_key', '?')}"
                for finding in severe[:3]
            )
            return (
                LaneVerdict.CONDITIONAL,
                f"scored {score}% on declaration completeness, but {len(severe)} "
                f"configuration finding(s) prevent a pass: {clauses}. What was "
                "declared is complete; what it declares is not acceptable.",
            )
        return LaneVerdict.PASS, f"scored {score}%, at or above the {PASS_THRESHOLD}% threshold"
    if score >= CONDITIONAL_FLOOR:
        return (
            LaneVerdict.CONDITIONAL,
            f"scored {score}%, below the {PASS_THRESHOLD}% threshold and above the "
            f"{CONDITIONAL_FLOOR}% floor — remediable",
        )
    return LaneVerdict.FAIL, f"scored {score}%, below the {CONDITIONAL_FLOOR}% floor"
