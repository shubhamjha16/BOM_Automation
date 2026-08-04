"""Supplier scorecards, return-to-supplier, and resubmission diffing.

**The diff is per field, not per total.** Two compensating changes give the same
overall score from different verdicts — a supplier who adds licences and drops
versions can score identically while having got materially worse. A total-only
diff would report "no change" for exactly the resubmission a reviewer most needs
to look at.

Return-to-supplier carries the gap register because the supplier's question is
never "what did we score", it is "what do we fix". A score with no field list is
a grade, not a work item.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any


class Movement(StrEnum):
    IMPROVED = "improved"
    REGRESSED = "regressed"
    UNCHANGED = "unchanged"
    ADDED = "added"
    REMOVED = "removed"


@dataclass(frozen=True, slots=True)
class FieldDelta:
    element_key: str
    clause: str
    before: str | None
    after: str | None
    coverage_before: float | None
    coverage_after: float | None
    movement: Movement

    @property
    def is_regression(self) -> bool:
        return self.movement is Movement.REGRESSED

    def as_row(self) -> dict[str, Any]:
        return {
            "element_key": self.element_key,
            "clause": self.clause,
            "before": self.before,
            "after": self.after,
            "coverage_before": self.coverage_before,
            "coverage_after": self.coverage_after,
            "movement": str(self.movement),
        }


@dataclass(slots=True)
class SubmissionDiff:
    score_before: float | None
    score_after: float | None
    fields: list[FieldDelta] = field(default_factory=list)

    @property
    def score_delta(self) -> float | None:
        if self.score_before is None or self.score_after is None:
            return None
        return round(self.score_after - self.score_before, 2)

    @property
    def regressions(self) -> list[FieldDelta]:
        """Fields that got worse. **Reported even when the total improved** —
        that is the case a total-only diff hides."""
        return [item for item in self.fields if item.is_regression]

    @property
    def improvements(self) -> list[FieldDelta]:
        return [item for item in self.fields if item.movement is Movement.IMPROVED]

    def as_report(self) -> dict[str, Any]:
        return {
            "score_before": self.score_before,
            "score_after": self.score_after,
            "score_delta": self.score_delta,
            "improved": len(self.improvements),
            "regressed": len(self.regressions),
            "unchanged": sum(
                1 for item in self.fields if item.movement is Movement.UNCHANGED
            ),
            "fields": [item.as_row() for item in self.fields],
            # Surfaced separately: a resubmission that improves overall while
            # dropping a field is the one a reviewer must not miss.
            "regressions": [item.as_row() for item in self.regressions],
        }


def _coverage(row: dict[str, Any]) -> float | None:
    value = row.get("coverage")
    return round(float(value), 4) if value is not None else None


def _movement(before: dict[str, Any], after: dict[str, Any]) -> Movement:
    """Compare one field across two submissions.

    Verdict first, then coverage: `absent` → `present` is an improvement whatever
    the numbers, and coverage decides where the verdict is unchanged.
    """
    verdict_before, verdict_after = str(before.get("verdict")), str(after.get("verdict"))

    if verdict_before != verdict_after:
        # not_determinable is neither better nor worse — it left the supplier
        # score entirely, so movement into or out of it is not a supplier change.
        if "not_determinable" in (verdict_before, verdict_after):
            return Movement.UNCHANGED
        return Movement.IMPROVED if verdict_after == "present" else Movement.REGRESSED

    coverage_before, coverage_after = _coverage(before), _coverage(after)
    if coverage_before is None or coverage_after is None:
        return Movement.UNCHANGED
    if coverage_after > coverage_before:
        return Movement.IMPROVED
    if coverage_after < coverage_before:
        return Movement.REGRESSED
    return Movement.UNCHANGED


def diff_submissions(
    before_fields: list[dict[str, Any]],
    after_fields: list[dict[str, Any]],
    *,
    score_before: float | None = None,
    score_after: float | None = None,
) -> SubmissionDiff:
    """Field-by-field comparison of two scored submissions."""
    before_index = {row["element_key"]: row for row in before_fields}
    after_index = {row["element_key"]: row for row in after_fields}

    deltas: list[FieldDelta] = []

    for key in sorted(set(before_index) | set(after_index)):
        before = before_index.get(key)
        after = after_index.get(key)

        if before is None and after is not None:
            deltas.append(
                FieldDelta(key, str(after.get("clause")), None, str(after.get("verdict")),
                           None, _coverage(after), Movement.ADDED)
            )
            continue
        if after is None and before is not None:
            deltas.append(
                FieldDelta(key, str(before.get("clause")), str(before.get("verdict")), None,
                           _coverage(before), None, Movement.REMOVED)
            )
            continue

        assert before is not None and after is not None  # noqa: S101 - both present here
        deltas.append(
            FieldDelta(
                element_key=key,
                clause=str(after.get("clause")),
                before=str(before.get("verdict")),
                after=str(after.get("verdict")),
                coverage_before=_coverage(before),
                coverage_after=_coverage(after),
                movement=_movement(before, after),
            )
        )

    return SubmissionDiff(
        score_before=score_before, score_after=score_after, fields=deltas
    )


@dataclass(slots=True)
class SupplierScorecard:
    """A supplier's conformance across every submission they have made."""

    supplier: str
    submissions: list[dict[str, Any]] = field(default_factory=list)

    @property
    def latest_score(self) -> float | None:
        return self.submissions[-1].get("score") if self.submissions else None

    @property
    def trend(self) -> str:
        """Direction of travel, or `insufficient_history` with fewer than two.

        Never "stable" on a single submission: one data point has no direction,
        and reporting one would be inventing a trend.
        """
        scores = [
            item["score"] for item in self.submissions if item.get("score") is not None
        ]
        if len(scores) < 2:
            return "insufficient_history"
        if scores[-1] > scores[-2]:
            return "improving"
        if scores[-1] < scores[-2]:
            return "regressing"
        return "flat"

    @property
    def worst_gap(self) -> dict[str, Any] | None:
        """The lowest-coverage critical field in the most recent submission —
        what a partner needs on one screen (S16)."""
        if not self.submissions:
            return None
        fields = self.submissions[-1].get("fields") or []
        critical = [
            row
            for row in fields
            if row.get("tier") == "critical" and str(row.get("verdict")) == "absent"
        ]
        if not critical:
            return None
        return min(critical, key=lambda row: row.get("coverage") or 0.0)


def gap_register(fields: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """What a supplier actually works from: every unmet field, with its clause.

    Ordered by tier then clause, because a supplier fixing gaps in clause order
    would start at 4.2(1) rather than at the critical ones.
    """
    tier_order = {"critical": 0, "standard": 1, "contextual": 2}
    gaps = [row for row in fields if str(row.get("verdict")) == "absent"]
    return sorted(
        (
            {
                "clause": row.get("clause"),
                "element": row.get("label") or row.get("element_key"),
                "tier": row.get("tier"),
                "coverage": row.get("coverage"),
                "populated": row.get("populated"),
                "total": row.get("total"),
                "detail": row.get("detail"),
            }
            for row in gaps
        ),
        key=lambda row: (tier_order.get(str(row["tier"]), 3), str(row["clause"])),
    )
