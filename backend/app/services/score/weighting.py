"""Tier-weighted aggregation of field results into a lane score.

Weighted *coverage*, not weighted pass-count: a field populated on 380 of 400
components contributes 95% of its weight, and a field populated on 12 of 400
contributes 3%. Aggregating booleans instead would let a supplier reach the
threshold by populating a majority of fields badly.
"""

from __future__ import annotations

from collections.abc import Sequence

from app.services.score.fieldCheck import FieldResult


def lane_score(results: Sequence[FieldResult]) -> float:
    """Weighted coverage across the supplier-scored fields, as a percentage.

    Returns 0.0 when nothing is scorable — an unimplemented or empty catalogue
    must not produce a perfect score by vacuity.
    """
    scored = [result for result in results if result.counts_toward_supplier_score]
    total_weight = sum(result.weight for result in scored)
    if total_weight == 0:
        return 0.0
    earned = sum(result.weight * result.coverage.ratio for result in scored)
    return round(earned / total_weight * 100, 2)


def overall_score(lane_scores: dict[str, float | None]) -> float | None:
    """Unweighted mean across the lanes that count.

    Callers pass ``None`` for a lane excluded from the overall score —
    ``lane_not_applicable`` and ``lane_timeout``. All lanes excluded means there
    is no overall score, which is reported as such rather than as zero.
    """
    contributing = [score for score in lane_scores.values() if score is not None]
    if not contributing:
        return None
    return round(sum(contributing) / len(contributing), 2)
