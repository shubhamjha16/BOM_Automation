"""One element against one entity set → one field verdict.

The whole of field scoring is here, and it is a table lookup plus a division.
That is the claim the product rests on: no model produces a verdict.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass
from typing import Any

from app.configs.jobTypes import Determinability, FieldVerdict, Tier
from app.configs.scoringConfig import TIER_WEIGHTS
from app.services.catalogue.types import MinimumElement
from app.services.score.coverage import Coverage, measure


@dataclass(frozen=True, slots=True)
class FieldResult:
    element_key: str
    label: str
    clause: str
    tier: Tier
    determinability: Determinability
    verdict: FieldVerdict
    coverage: Coverage
    weight: float
    detail: str
    consumer_action: str = ""

    @property
    def counts_toward_supplier_score(self) -> bool:
        """not_determinable is excluded from the supplier score, always (§11)."""
        return self.verdict is not FieldVerdict.NOT_DETERMINABLE

    @property
    def is_critical_gap(self) -> bool:
        """A critical element at zero coverage fails the submission regardless of
        the arithmetic. A BOM with no versions can score respectably on descriptive
        fields while being useless for every purpose the guideline exists to serve."""
        return (
            self.tier is Tier.CRITICAL
            and self.counts_toward_supplier_score
            and self.coverage.populated == 0
        )


def check(element: MinimumElement, entities: Sequence[dict[str, Any]]) -> FieldResult:
    """Score one minimum element."""
    weight = TIER_WEIGHTS[element.tier]

    if not element.scores_against_supplier:
        # HUMAN determinability: not a supplier defect and not a pass. It leaves
        # the scoring path here and renders in its own section with its action.
        return FieldResult(
            element_key=element.key,
            label=element.label,
            clause=element.clause,
            tier=element.tier,
            determinability=element.determinability,
            verdict=FieldVerdict.NOT_DETERMINABLE,
            coverage=Coverage(populated=0, total=0),
            weight=weight,
            detail=element.rationale
            or "cannot be established from a BOM artifact; consumer determination",
            consumer_action=element.consumer_action,
        )

    coverage = measure(entities, element)
    if coverage.populated == 0:
        verdict = FieldVerdict.ABSENT
        detail = f"absent across all {coverage.total} entities"
    elif coverage.populated == coverage.total:
        verdict = FieldVerdict.PRESENT
        detail = f"populated on all {coverage.total} entities"
    else:
        # Partial coverage is a defect, scored proportionally. It is not a pass.
        verdict = FieldVerdict.ABSENT
        detail = (
            f"populated on {coverage.populated} of {coverage.total} entities "
            f"({coverage.percent}%) — partial coverage does not meet {element.clause}"
        )

    return FieldResult(
        element_key=element.key,
        label=element.label,
        clause=element.clause,
        tier=element.tier,
        determinability=element.determinability,
        verdict=verdict,
        coverage=coverage,
        weight=weight,
        detail=detail,
    )
