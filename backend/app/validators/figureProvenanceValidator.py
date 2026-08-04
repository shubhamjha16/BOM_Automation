"""No figure in narrative prose that did not come from the scorer.

This is the S8 clause gate extended to numbers. A drafter writing "conformance
reached 92%" where no lane result holds 92 has invented a figure, and an invented
figure in an assessment is indistinguishable from a computed one to the client
reading it — which is precisely why the LLM never produces a verdict, a figure or
a clause reference (§11).

**Not every number is a figure.** Clause references contain digits, so do dates,
CVE identifiers, version strings and component counts the scorer did produce. The
check therefore extracts *percentages and scores* specifically, and compares them
against the set the engine computed.
"""

from __future__ import annotations

import re
from collections.abc import Iterable
from typing import Any


class FigureNotTraceable(RuntimeError):
    """Prose contained a figure the scorer never produced."""


#: A percentage: "92%", "92.5 %", "43.9 percent".
_PERCENT = re.compile(r"(\d+(?:\.\d+)?)\s*(?:%|percent\b)", re.IGNORECASE)
#: "scored 43.9", "a score of 43.9".
_SCORE = re.compile(r"(?:scored|score of)\s+(\d+(?:\.\d+)?)", re.IGNORECASE)

#: Percentages carry rounding differences between the engine and prose ("43.9"
#: for 43.92). A tolerance admits honest rounding without admitting invention.
TOLERANCE = 0.05


def figures_in(text: str) -> list[float]:
    """Every percentage or score stated in prose."""
    found = [float(match) for match in _PERCENT.findall(text or "")]
    found.extend(float(match) for match in _SCORE.findall(text or ""))
    return found


def permitted_figures(
    lane_results: Iterable[Any], field_rows: Iterable[dict] | None = None
) -> set[float]:
    """Every figure the engine actually computed.

    Lane scores, plus per-field coverage percentages — a narrative legitimately
    says "licences were declared on 3% of components", and that 3 came from the
    scorer.
    """
    allowed: set[float] = {0.0, 100.0}

    for result in lane_results:
        score = getattr(result, "score", None)
        if score is not None:
            allowed.add(round(float(score), 2))
        for row in getattr(result, "field_results", []) or []:
            coverage = row.get("coverage")
            if coverage is not None:
                allowed.add(round(float(coverage) * 100, 2))
            if row.get("total"):
                allowed.add(float(row["total"]))
            if row.get("populated") is not None:
                allowed.add(float(row["populated"]))

    for row in field_rows or []:
        if (coverage := row.get("coverage")) is not None:
            allowed.add(round(float(coverage) * 100, 2))

    return allowed


def assert_figures_traceable(
    text: str, *, lane_results: Iterable[Any], field_rows: Iterable[dict] | None = None
) -> None:
    """Raise if prose states a figure the engine did not produce."""
    allowed = permitted_figures(lane_results, field_rows)
    stated = figures_in(text)

    invented = [
        figure
        for figure in stated
        if not any(abs(figure - candidate) <= TOLERANCE for candidate in allowed)
    ]
    if invented:
        raise FigureNotTraceable(
            f"prose states figure(s) the scorer never produced: "
            f"{', '.join(str(figure) for figure in sorted(set(invented)))}. "
            "The model may restate a computed figure; it may not produce one."
        )
