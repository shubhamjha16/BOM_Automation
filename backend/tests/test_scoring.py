"""Scoring rules from §11, each as an executable assertion.

These are the rules the product is, so every one of them fails loudly rather than
drifting. S7 adds `tests/vectors/` — BOMs hand-scored by an assessor — on top.
"""

from __future__ import annotations

import pytest

from app.configs.jobTypes import Determinability, FieldVerdict, LaneVerdict, Tier
from app.services.catalogue.loader import get_catalogue
from app.services.catalogue.probes import is_meaningful
from app.services.score.coverage import Coverage, measure
from app.services.score.fieldCheck import check
from app.services.score.verdict import lane_verdict
from app.services.score.weighting import lane_score, overall_score
from app.validators.determinabilityValidator import DeterminabilityViolation, validate


def _element(key: str):
    return get_catalogue("sbom").by_key(key)


# --- partial coverage is not a pass ----------------------------------------


def test_licences_on_12_of_400_scores_three_percent_not_a_pass():
    """The §11 case, verbatim."""
    entities = [
        {"name": f"c{index}", "license_expr": "MIT" if index < 12 else None}
        for index in range(400)
    ]
    result = check(_element("license"), entities)

    assert result.verdict is FieldVerdict.ABSENT
    assert result.coverage.percent == 3.0
    assert "12 of 400" in result.detail
    assert "does not meet 4.2(5)" in result.detail


def test_full_coverage_is_present():
    entities = [{"name": f"c{index}", "license_expr": "MIT"} for index in range(10)]
    assert check(_element("license"), entities).verdict is FieldVerdict.PRESENT


def test_an_empty_entity_set_scores_zero_not_vacuously_true():
    """A BOM with no components must not render as fully conformant."""
    assert Coverage(populated=0, total=0).ratio == 0.0
    assert check(_element("license"), []).verdict is FieldVerdict.ABSENT


def test_coverage_rejects_impossible_counts():
    with pytest.raises(ValueError, match="exceeds total"):
        Coverage(populated=5, total=3)


# --- null tokens are absences, not values ----------------------------------


@pytest.mark.parametrize(
    "value", ["NOASSERTION", "NONE", "", "  ", "unknown", "N/A", "TBD", None, []]
)
def test_placeholder_values_do_not_count_as_populated(value):
    assert not is_meaningful(value)


def test_noassertion_licence_is_not_a_licence():
    entities = [{"name": "c", "license_expr": "NOASSERTION"}]
    assert check(_element("license"), entities).verdict is FieldVerdict.ABSENT


def test_a_real_value_counts():
    assert is_meaningful("Apache-2.0")
    assert is_meaningful(["MIT"])


# --- not_determinable is never compliant and never a defect ----------------


def test_criticality_is_not_determinable_and_leaves_the_supplier_score():
    result = check(_element("criticality"), [{"name": "c", "criticality": "high"}])

    assert result.verdict is FieldVerdict.NOT_DETERMINABLE
    assert result.counts_toward_supplier_score is False
    assert result.consumer_action, "a consumer determination without an action is a shrug"


def test_usage_restrictions_likewise():
    result = check(_element("usage_restrictions"), [{"name": "c"}])
    assert result.verdict is FieldVerdict.NOT_DETERMINABLE
    assert result.counts_toward_supplier_score is False


def test_aibom_intended_and_out_of_scope_usage_are_consumer_determinations():
    catalogue = get_catalogue("aibom")
    for key in ("intended_usage", "out_of_scope_usage"):
        element = catalogue.by_key(key)
        assert element.determinability is Determinability.HUMAN
        assert check(element, [{"model_name": "m"}]).counts_toward_supplier_score is False


def test_a_human_field_given_a_supplier_verdict_is_refused():
    """The validator catches a probe bug that would tick a box nobody checked."""
    good = check(_element("criticality"), [{"name": "c"}])
    validate([good])

    from dataclasses import replace

    forged = replace(good, verdict=FieldVerdict.PRESENT)
    with pytest.raises(DeterminabilityViolation, match="consumer-determined"):
        validate([forged])


def test_not_determinable_fields_are_excluded_from_the_weighted_score():
    entities = [{"name": "c", "license_expr": "MIT"}]
    catalogue = get_catalogue("sbom")
    results = [check(element, entities) for element in catalogue.elements]

    scored = [result for result in results if result.counts_toward_supplier_score]
    assert len(scored) == len(catalogue.supplier_scored)
    assert all(
        result.determinability is not Determinability.HUMAN for result in scored
    )


# --- critical gaps fail regardless of score --------------------------------


def test_a_critical_field_at_zero_coverage_fails_the_lane():
    """A BOM with no versions can score respectably on descriptive fields."""
    entities = [{"name": f"c{index}", "version": None} for index in range(50)]
    results = [check(element, entities) for element in get_catalogue("sbom").elements]
    verdict, detail = lane_verdict(lane_score(results), results)

    assert verdict is LaneVerdict.FAIL
    assert "4.2(2) Version of the Component" in detail
    assert "critical gap" in detail


def test_verdict_thresholds():
    assert lane_verdict(92.0, [])[0] is LaneVerdict.PASS
    assert lane_verdict(70.0, [])[0] is LaneVerdict.CONDITIONAL
    assert lane_verdict(20.0, [])[0] is LaneVerdict.FAIL


# --- weighting -------------------------------------------------------------


def test_lane_score_weights_by_coverage_not_by_pass_count():
    element = _element("license")
    half = [{"name": f"c{i}", "license_expr": "MIT" if i < 5 else None} for i in range(10)]
    assert lane_score([check(element, half)]) == 50.0


def test_an_empty_catalogue_scores_zero_not_one_hundred():
    """An unimplemented lane must not reach a perfect score by vacuity."""
    assert lane_score([]) == 0.0


def test_overall_score_excludes_lanes_that_do_not_count():
    assert overall_score({"sbom": 90.0, "aibom": 70.0, "cbom": None}) == 80.0
    assert overall_score({"cbom": None, "qbom": None}) is None


# --- measure ---------------------------------------------------------------


def test_measure_counts_per_entity():
    entities = [{"version": "1.0"}, {"version": None}, {"version": "2.0"}]
    coverage = measure(entities, _element("version"))
    assert (coverage.populated, coverage.total) == (2, 3)


def test_tier_weights_are_ordered():
    from app.configs.scoringConfig import TIER_WEIGHTS

    assert TIER_WEIGHTS[Tier.CRITICAL] > TIER_WEIGHTS[Tier.STANDARD] > TIER_WEIGHTS[Tier.CONTEXTUAL]


# --- document-scoped elements ----------------------------------------------
#
# Regression: 4.2(19) and 4.2(20) were modelled as per-component fields and
# scored 0/855 against a real cdxgen SBOM that carried both. A false negative
# against the supplier is as damaging as one in their favour, and the weighted
# score hides it completely — 0/855 looks exactly like a genuine gap.


def test_author_and_timestamp_are_document_scoped_not_per_component():
    from app.services.catalogue.types import Scope

    catalogue = get_catalogue("sbom")
    assert {element.key for element in catalogue.document_scoped} == {
        "author_name",
        "timestamp",
    }
    for element in catalogue.entity_scoped:
        assert element.scope is Scope.ENTITY


def test_a_document_carrying_author_and_timestamp_meets_those_clauses():
    from app.services.score.documentChecks import check_all, document_metadata

    catalogue = get_catalogue("sbom")
    entities = [{"name": f"c{index}"} for index in range(855)]
    documents = [document_metadata(author="OWASP Foundation", timestamp="2026-08-04T13:06:56Z")]

    results = {result.element_key: result for result in check_all(catalogue, entities, documents)}
    assert results["author_name"].verdict is FieldVerdict.PRESENT
    assert results["timestamp"].verdict is FieldVerdict.PRESENT
    # Scored once per document, not once per component.
    assert results["author_name"].coverage.total == 1


def test_a_document_missing_them_still_fails_those_clauses():
    from app.services.score.documentChecks import check_all, document_metadata

    catalogue = get_catalogue("sbom")
    documents = [document_metadata(author=None, timestamp=None)]
    scored = check_all(catalogue, [{"name": "c"}], documents)
    results = {result.element_key: result for result in scored}

    assert results["author_name"].verdict is FieldVerdict.ABSENT
    assert results["timestamp"].verdict is FieldVerdict.ABSENT


def test_partial_coverage_applies_to_documents_too():
    """Two documents, one timestamped, is not a pass."""
    from app.services.score.documentChecks import check_document, document_metadata

    element = get_catalogue("sbom").by_key("timestamp")
    documents = [
        document_metadata(author="a", timestamp="2026-08-04T00:00:00Z"),
        document_metadata(author="a", timestamp=None),
    ]
    result = check_document(element, documents)

    assert result.verdict is FieldVerdict.ABSENT
    assert (result.coverage.populated, result.coverage.total) == (1, 2)


def test_routing_an_entity_element_through_the_document_checker_is_refused():
    from app.services.score.documentChecks import check_document

    with pytest.raises(ValueError, match="entity-scoped"):
        check_document(get_catalogue("sbom").by_key("license"), [{}])
