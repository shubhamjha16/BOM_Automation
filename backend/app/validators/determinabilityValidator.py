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


# --- row-shaped checks, for the gate ----------------------------------------
#
# The gate sees field verdicts as the flat dicts the lanes carry, not as
# `FieldResult` objects. Same two rules, applied to that shape.


HUMAN_DETERMINABILITY = "human"
NOT_DETERMINABLE = "not_determinable"


def assert_rows_not_scored(rows: Iterable[dict]) -> None:
    """Both determinability rules, over the graph's flat field rows.

    Checked at the gate rather than trusted from the scorer: the scorer is
    correct today, and the point of a gate is that nothing renders on the basis
    of a component being correct today.
    """
    leaked: list[str] = []
    misjudged: list[str] = []

    for row in rows:
        verdict = str(row.get("verdict", ""))
        determinability = str(row.get("determinability", ""))
        clause = row.get("clause", "?")
        label = row.get("label") or row.get("element_key", "?")

        # A not_determinable field carrying coverage means it was scored.
        if verdict == NOT_DETERMINABLE and int(row.get("total") or 0) > 0:
            leaked.append(f"{clause} {label}")

        # A consumer determination given a supplier verdict.
        if determinability == HUMAN_DETERMINABILITY and verdict != NOT_DETERMINABLE:
            misjudged.append(f"{clause} {label} = {verdict}")

        # A not_determinable field with no action reads as a shrug, and the
        # reader assumes it passed.
        if verdict == NOT_DETERMINABLE and not row.get("consumer_action"):
            misjudged.append(f"{clause} {label} is not determinable but names no action")

    problems: list[str] = []
    if leaked:
        problems.append(
            "not_determinable field(s) carry coverage and so entered the supplier "
            "score: " + ", ".join(leaked)
        )
    if misjudged:
        problems.append(
            "consumer-determined field(s) were mishandled: " + ", ".join(misjudged)
        )
    if problems:
        raise DeterminabilityViolation("; ".join(problems))
