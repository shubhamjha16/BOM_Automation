"""The clause-trace gate. **No bypass flag, by design.**

No verdict may render unless its clause resolves to an element in the pinned
guideline version. There is no parameter, environment variable or override that
skips this — a flag would be used, eventually, by someone under deadline, and the
assessment it let through would carry a clause reference that resolves to
nothing. One fabricated citation reaching a client discredits every assessment
the firm has issued, so this refuses to render rather than degrading gracefully.

Correlation findings are checked here too. They cite the guideline exactly as
field verdicts do (s.8.4.1.2, s.9.3(6), s.8.5.1), so they pass the same gate —
otherwise the one class of finding no single-lane tool can produce would be the
one class nobody verified.
"""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass
from typing import Any

from app.configs.envConfig import ALL_LANES, Lane
from app.services.catalogue.loader import get_catalogue
from app.services.correlate.engine import RULES


class ClauseNotTraceable(RuntimeError):
    """A verdict cited a clause the pinned guideline version does not contain."""


@dataclass(frozen=True, slots=True)
class Citation:
    """One clause reference, and enough context to name what made it."""

    clause: str
    lane: Lane | None
    source: str


def known_clauses(lanes: Iterable[Lane] | None = None) -> set[str]:
    """Every clause the pinned catalogue can legitimately cite."""
    return {
        element.clause
        for lane in (lanes if lanes is not None else ALL_LANES)
        for element in get_catalogue(lane).elements
    }


def correlation_clauses() -> set[str]:
    """Clauses the correlation rules cite.

    These come from sections the minimum-element tables do not cover — s.8.4.1.2
    and s.8.5.1 are requirements about the *presence* of a declaration rather
    than about a field within one — so they are a second legitimate source, held
    beside the rules themselves rather than hardcoded here.
    """
    return {rule.clause for rule in RULES}


def assert_traceable(clause: str, lane: Lane) -> None:
    """Raise unless ``clause`` exists in ``lane``'s pinned catalogue."""
    catalogue = get_catalogue(lane)
    if clause not in {element.clause for element in catalogue.elements}:
        raise ClauseNotTraceable(
            f"clause {clause!r} does not resolve to a minimum element in the {lane} "
            f"catalogue for guideline version {catalogue.guideline_version}; "
            "refusing to render"
        )


def _resolves(citation: Citation) -> str | None:
    """Return an error string, or None when the citation is traceable."""
    if citation.lane is not None:
        catalogue = get_catalogue(citation.lane)
        if citation.clause in {element.clause for element in catalogue.elements}:
            return None
        return (
            f"{citation.source}: clause {citation.clause!r} does not resolve to a "
            f"minimum element in the {citation.lane} catalogue for guideline "
            f"version {catalogue.guideline_version}"
        )

    # A lane-less citation is a correlation finding.
    if citation.clause in correlation_clauses():
        return None
    return (
        f"{citation.source}: clause {citation.clause!r} is not cited by any "
        "correlation rule and resolves to nothing"
    )


def assert_all_traceable(citations: Iterable[Citation]) -> None:
    """Check a whole assessment's citations, reporting every failure at once.

    One at a time would mean an analyst fixes a report, re-runs, and finds the
    next fabricated clause.
    """
    failures = [message for citation in citations if (message := _resolves(citation))]
    if failures:
        raise ClauseNotTraceable(
            f"{len(failures)} untraceable clause reference(s):\n  " + "\n  ".join(failures)
        )


def citations_from(
    lane_results: Iterable[Any], correlation_findings: Iterable[Any]
) -> list[Citation]:
    """Every clause an assessment would render, gathered for the gate.

    Field verdicts *and* correlation findings, because both reach the reader as
    a clause reference and both must resolve.
    """
    citations: list[Citation] = []

    for result in lane_results:
        for field in getattr(result, "field_results", []) or []:
            citations.append(
                Citation(
                    clause=str(field.get("clause")),
                    lane=result.lane,
                    source=f"{result.lane}.{field.get('element_key')}",
                )
            )

    for finding in correlation_findings:
        citations.append(
            Citation(
                clause=str(getattr(finding, "clause", "")),
                lane=None,
                source=f"correlation.{getattr(finding, 'rule_key', '?')}",
            )
        )

    return citations
