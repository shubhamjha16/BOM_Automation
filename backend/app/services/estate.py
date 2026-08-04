"""Estate rollup, score trend and drift detection.

**The estate view answers a partner's question, which is not an assessor's.** An
assessor asks "is this submission conformant?"; a partner asks "which of my forty
suppliers should I chase first?". That is a different sort over the same data:
worst first, with the single worst gap named, on one screen.

**Drift is per field, and that is the whole point.** s.2.3 requires
re-assessment on every release, update and patch — which only produces value if
a regression is visible. A release that adds licences and drops versions scores
identically and is materially worse, so a total-only trend would report it as
stable. `supplierWorkflow.diff_submissions` already does the field comparison;
this module applies it across a release sequence and raises the regressions.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from app.services.supplierWorkflow import Movement, SubmissionDiff, diff_submissions

TIER_RANK = {"critical": 0, "standard": 1, "contextual": 2}


@dataclass(frozen=True, slots=True)
class EstateRow:
    """One supplier's current position, as a partner needs to see it."""

    supplier: str
    latest_score: float | None
    latest_verdict: str | None
    submissions: int
    trend: str
    worst_gap: dict[str, Any] | None
    #: Regressions in the most recent release. The reason to chase this supplier.
    open_regressions: int = 0

    def as_row(self) -> dict[str, Any]:
        return {
            "supplier": self.supplier,
            "latest_score": self.latest_score,
            "latest_verdict": self.latest_verdict,
            "submissions": self.submissions,
            "trend": self.trend,
            "worst_gap": self.worst_gap,
            "open_regressions": self.open_regressions,
        }


def _worst_gap(fields: list[dict[str, Any]]) -> dict[str, Any] | None:
    """The lowest-coverage critical gap — the single thing to fix first."""
    gaps = [
        row
        for row in fields
        if str(row.get("verdict")) == "absent"
    ]
    if not gaps:
        return None
    worst = min(
        gaps,
        key=lambda row: (
            TIER_RANK.get(str(row.get("tier")), 3),
            row.get("coverage") if row.get("coverage") is not None else 0.0,
        ),
    )
    return {
        "clause": worst.get("clause"),
        "element": worst.get("label") or worst.get("element_key"),
        "tier": worst.get("tier"),
        "coverage": worst.get("coverage"),
    }


def _trend(scores: list[float]) -> str:
    """Direction of travel, or `insufficient_history`.

    Never "stable" on one submission: a single data point has no direction, and
    reporting one would invent a trend.
    """
    if len(scores) < 2:
        return "insufficient_history"
    if scores[-1] > scores[-2]:
        return "improving"
    if scores[-1] < scores[-2]:
        return "regressing"
    return "flat"


def supplier_row(supplier: str, submissions: list[dict[str, Any]]) -> EstateRow:
    """Roll one supplier's submission history into a single line."""
    if not submissions:
        return EstateRow(supplier, None, None, 0, "insufficient_history", None)

    ordered = sorted(submissions, key=lambda item: str(item.get("assessed_at") or ""))
    latest = ordered[-1]
    scores = [
        float(item["score"]) for item in ordered if item.get("score") is not None
    ]

    regressions = 0
    if len(ordered) >= 2:
        regressions = len(
            diff_submissions(
                ordered[-2].get("fields") or [], latest.get("fields") or []
            ).regressions
        )

    return EstateRow(
        supplier=supplier,
        latest_score=scores[-1] if scores else None,
        latest_verdict=latest.get("verdict"),
        submissions=len(ordered),
        trend=_trend(scores),
        worst_gap=_worst_gap(latest.get("fields") or []),
        open_regressions=regressions,
    )


def rollup(by_supplier: dict[str, list[dict[str, Any]]]) -> list[EstateRow]:
    """Every supplier, worst first.

    Sorted so the partner's first screen is their actual work queue: open
    regressions first (something got worse), then lowest score. A supplier who
    never submitted sorts to the top, because an absent submission is the
    strongest signal of all.
    """
    rows = [supplier_row(supplier, items) for supplier, items in by_supplier.items()]
    return sorted(
        rows,
        key=lambda row: (
            -row.open_regressions,
            row.latest_score if row.latest_score is not None else -1.0,
            row.supplier,
        ),
    )


@dataclass(slots=True)
class DriftFinding:
    """A release that got worse than its predecessor."""

    clause: str
    element: str
    before: str | None
    after: str | None
    detail: str

    def as_row(self) -> dict[str, Any]:
        return {
            "clause": self.clause,
            "element": self.element,
            "before": self.before,
            "after": self.after,
            "detail": self.detail,
        }


@dataclass(slots=True)
class ReleaseTrend:
    """A product's score across sequential releases, and what moved."""

    product: str
    points: list[dict[str, Any]] = field(default_factory=list)
    diffs: list[SubmissionDiff] = field(default_factory=list)
    drift: list[DriftFinding] = field(default_factory=list)

    @property
    def direction(self) -> str:
        scores = [point["score"] for point in self.points if point.get("score") is not None]
        return _trend(scores)

    def as_report(self) -> dict[str, Any]:
        return {
            "product": self.product,
            "direction": self.direction,
            "points": self.points,
            "drift": [item.as_row() for item in self.drift],
            # Every movement, so a trend line is never an unexplained curve.
            "movements": [
                {
                    "from": self.points[index]["release"],
                    "to": self.points[index + 1]["release"],
                    "score_delta": diff.score_delta,
                    "improved": [item.clause for item in diff.improvements],
                    "regressed": [item.clause for item in diff.regressions],
                }
                for index, diff in enumerate(self.diffs)
            ],
        }


def release_trend(product: str, releases: list[dict[str, Any]]) -> ReleaseTrend:
    """Compare a product's releases in order, raising drift on any regression.

    Every movement traces to a field verdict change, which is what makes the
    trend defensible: a client asking "why did this drop?" gets clauses, not a
    slope.
    """
    ordered = sorted(releases, key=lambda item: str(item.get("released_on") or ""))
    trend = ReleaseTrend(
        product=product,
        points=[
            {
                "release": item.get("release"),
                "released_on": item.get("released_on"),
                "score": item.get("score"),
            }
            for item in ordered
        ],
    )

    for previous, current in zip(ordered, ordered[1:], strict=False):
        diff = diff_submissions(
            previous.get("fields") or [],
            current.get("fields") or [],
            score_before=previous.get("score"),
            score_after=current.get("score"),
        )
        trend.diffs.append(diff)

        for delta in diff.fields:
            # A previously-present field that is now absent is the drift finding
            # s.2.3 re-assessment exists to surface.
            if delta.movement is Movement.REGRESSED and delta.before == "present":
                trend.drift.append(
                    DriftFinding(
                        clause=delta.clause,
                        element=delta.element_key,
                        before=delta.before,
                        after=delta.after,
                        detail=(
                            f"{delta.clause} was declared in "
                            f"{previous.get('release')} and is not in "
                            f"{current.get('release')}; the release regressed on a "
                            "minimum element it had already met"
                        ),
                    )
                )
    return trend


def requires_reassessment(previous_release: str | None, current_release: str | None) -> bool:
    """s.2.3: a new SBOM on every release, update and patch.

    Any change of release string triggers it. Deliberately not a semver
    comparison — a patch is as much a trigger as a major, and a supplier's
    versioning scheme is not ours to interpret.
    """
    if current_release is None:
        return False
    return previous_release != current_release
