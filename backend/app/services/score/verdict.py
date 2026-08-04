"""Score → verdict. The threshold comparison, and the critical-gap override.

Kept separate from `weighting.py` because the override is not arithmetic: a
critical element at zero coverage fails the lane at any score, and that rule has
to be visible rather than buried in a sum.
"""

from __future__ import annotations

from collections.abc import Sequence

from app.configs.jobTypes import LaneVerdict
from app.configs.scoringConfig import (
    CONDITIONAL_FLOOR,
    CRITICAL_GAP_FAILS_SUBMISSION,
    PASS_THRESHOLD,
)
from app.services.score.fieldCheck import FieldResult


def critical_gaps(results: Sequence[FieldResult]) -> list[FieldResult]:
    return [result for result in results if result.is_critical_gap]


def lane_verdict(score: float, results: Sequence[FieldResult]) -> tuple[LaneVerdict, str]:
    """The lane's verdict and the sentence explaining it."""
    gaps = critical_gaps(results)
    if gaps and CRITICAL_GAP_FAILS_SUBMISSION:
        clauses = ", ".join(f"{gap.clause} {gap.label}" for gap in gaps)
        return (
            LaneVerdict.FAIL,
            f"scored {score}% but fails on critical gap(s): {clauses} — absent across "
            "every entity",
        )
    if score >= PASS_THRESHOLD:
        return LaneVerdict.PASS, f"scored {score}%, at or above the {PASS_THRESHOLD}% threshold"
    if score >= CONDITIONAL_FLOOR:
        return (
            LaneVerdict.CONDITIONAL,
            f"scored {score}%, below the {PASS_THRESHOLD}% threshold and above the "
            f"{CONDITIONAL_FLOOR}% floor — remediable",
        )
    return LaneVerdict.FAIL, f"scored {score}%, below the {CONDITIONAL_FLOOR}% floor"
