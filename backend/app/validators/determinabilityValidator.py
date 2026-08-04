"""`not_determinable` never enters the supplier score and never renders as
compliant.

Two ways this goes wrong, and this module refuses both:

* Scoring a HUMAN-determinability element as a **defect** produces a report wrong
  in the client's favour — the supplier is blamed for something they could not
  have supplied, and the client fails a real audit holding a clean assessment.
* Scoring it as **compliant** puts a green tick on a field nobody checked.

Both end the same way. The only correct outcome is its own section, with the
consumer action required.
"""

from __future__ import annotations

from collections.abc import Iterable

from app.configs.jobTypes import Determinability, FieldVerdict
from app.services.score.fieldCheck import FieldResult


class DeterminabilityViolation(RuntimeError):
    """A not_determinable field was scored, or a human field given a verdict."""


def assert_not_scored(results: Iterable[FieldResult]) -> None:
    """Raise if any not_determinable result would reach the supplier score."""
    leaked = [
        result
        for result in results
        if result.verdict is FieldVerdict.NOT_DETERMINABLE
        and result.counts_toward_supplier_score
    ]
    if leaked:
        raise DeterminabilityViolation(
            "not_determinable field(s) reached the supplier score: "
            + ", ".join(f"{result.clause} {result.label}" for result in leaked)
        )


def assert_human_fields_undetermined(results: Iterable[FieldResult]) -> None:
    """Raise if a HUMAN-determinability element was given present or absent.

    This is the direction that matters most: a bug in a probe that returns True
    for Criticality would silently mark a consumer determination as met.
    """
    misjudged = [
        result
        for result in results
        if result.determinability is Determinability.HUMAN
        and result.verdict is not FieldVerdict.NOT_DETERMINABLE
    ]
    if misjudged:
        raise DeterminabilityViolation(
            "consumer-determined field(s) were given a supplier verdict: "
            + ", ".join(
                f"{result.clause} {result.label} = {result.verdict}" for result in misjudged
            )
            + " — these cannot be established from a BOM artifact at all"
        )


def consumer_determinations(results: Iterable[FieldResult]) -> list[FieldResult]:
    """The fields that render in their own section, each with its action."""
    return [
        result for result in results if result.verdict is FieldVerdict.NOT_DETERMINABLE
    ]


def validate(results: Iterable[FieldResult]) -> None:
    materialised = list(results)
    assert_not_scored(materialised)
    assert_human_fields_undetermined(materialised)
