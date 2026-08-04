"""The clause-trace gate. No bypass flag, by design.

No verdict may render unless its clause resolves to an element in the pinned
guideline version. A fabricated clause reference reaching a client's assessment
discredits every assessment the firm has issued, so this refuses to render rather
than degrading gracefully.

Full enforcement is S8; the rule is here from S1 because every node written
between now and then has to be written against it.
"""

from __future__ import annotations

from collections.abc import Iterable

from app.configs.envConfig import ALL_LANES, Lane
from app.services.catalogue.loader import get_catalogue


class ClauseNotTraceable(RuntimeError):
    """A verdict cited a clause the pinned guideline version does not contain."""


def known_clauses(lanes: Iterable[Lane] | None = None) -> set[str]:
    """Every clause the pinned catalogue can legitimately cite."""
    return {
        element.clause
        for lane in (lanes if lanes is not None else ALL_LANES)
        for element in get_catalogue(lane).elements
    }


def assert_traceable(clause: str, lane: Lane) -> None:
    """Raise unless ``clause`` exists in ``lane``'s pinned catalogue."""
    catalogue = get_catalogue(lane)
    if clause not in {element.clause for element in catalogue.elements}:
        raise ClauseNotTraceable(
            f"clause {clause!r} does not resolve to a minimum element in the {lane} "
            f"catalogue for guideline version {catalogue.guideline_version}; "
            "refusing to render"
        )


def assert_all_traceable(citations: Iterable[tuple[str, Lane]]) -> None:
    """Check a whole assessment's citations, reporting every failure at once.

    One at a time would mean an analyst fixes a report, re-runs, and finds the
    next fabricated clause.
    """
    failures = []
    for clause, lane in citations:
        try:
            assert_traceable(clause, lane)
        except ClauseNotTraceable as error:
            failures.append(str(error))
    if failures:
        raise ClauseNotTraceable(
            f"{len(failures)} untraceable clause reference(s):\n  " + "\n  ".join(failures)
        )
