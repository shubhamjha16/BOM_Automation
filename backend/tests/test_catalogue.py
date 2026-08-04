"""The catalogue is the product's factual basis; one wrong clause discredits
every assessment issued.

The anchored clause numbers are asserted here so a careless edit fails the build.
S20's catalogue audit — an independent assessor re-deriving every element from
the published PDF — turns each provisional ordinal into an anchored one, and
every discrepancy it finds becomes a permanent case in this file.
"""

from __future__ import annotations

import pytest

from app.configs.envConfig import ALL_LANES
from app.configs.jobTypes import Determinability
from app.services.catalogue import aibom, sbom
from app.services.catalogue.loader import all_catalogues, catalogue_checksum, get_catalogue


@pytest.mark.parametrize(("key", "clause"), sorted(sbom.ANCHORED_CLAUSES.items()))
def test_anchored_sbom_clauses(key, clause):
    assert get_catalogue("sbom").by_key(key).clause == clause


@pytest.mark.parametrize(("key", "clause"), sorted(aibom.ANCHORED_CLAUSES.items()))
def test_anchored_aibom_clauses(key, clause):
    assert get_catalogue("aibom").by_key(key).clause == clause


def test_sbom_carries_twenty_one_minimum_elements():
    assert len(get_catalogue("sbom").elements) == 21


def test_every_clause_sits_under_its_lane_root():
    for lane, catalogue in all_catalogues().items():
        for element in catalogue.elements:
            assert element.clause.startswith(catalogue.clause_root), (
                f"{lane}.{element.key} cites {element.clause}, outside {catalogue.clause_root}"
            )


def test_clause_ordinals_are_unique_and_contiguous_within_a_lane():
    for lane in ("sbom", "aibom"):
        ordinals = [
            int(element.clause.split("(")[1].rstrip(")"))
            for element in get_catalogue(lane).elements
        ]
        assert ordinals == sorted(ordinals), f"{lane} elements are out of clause order"
        assert len(ordinals) == len(set(ordinals)), f"{lane} has a duplicated clause ordinal"
        assert ordinals == list(range(1, len(ordinals) + 1)), f"{lane} skips a clause ordinal"


def test_every_human_element_carries_a_consumer_action():
    """A not_determinable verdict without an action reads as a shrug."""
    for catalogue in all_catalogues().values():
        for element in catalogue.elements:
            if element.determinability is Determinability.HUMAN:
                assert element.consumer_action, f"{element.key} has no consumer action"
                assert element.rationale, f"{element.key} has no rationale"


def test_human_elements_are_excluded_from_the_supplier_score():
    for catalogue in all_catalogues().values():
        for element in catalogue.elements:
            expected = element.determinability is not Determinability.HUMAN
            assert element.scores_against_supplier is expected


def test_the_four_known_consumer_determinations():
    """4.2(12), 4.2(13), 9.3(15) and 9.3(16) — named in the specification."""
    assert {element.clause for element in get_catalogue("sbom").consumer_determined} == {
        "4.2(12)",
        "4.2(13)",
    }
    assert {element.clause for element in get_catalogue("aibom").consumer_determined} == {
        "9.3(15)",
        "9.3(16)",
    }


def test_the_unimplemented_lane_is_empty_rather_than_approximated():
    """A guessed catalogue would produce a score against invented clauses.

    CBOM and QBOM were encoded in S14; HBOM waits for S16, because its data is
    procurement data — asset registers and purchase records, not scanner output.
    """
    assert get_catalogue("hbom").elements == ()


def test_the_crypto_lanes_are_now_encoded():
    assert len(get_catalogue("cbom").elements) >= 15
    assert len(get_catalogue("qbom").elements) >= 8


def test_checksums_are_stable_and_distinct_per_lane():
    assert catalogue_checksum("sbom") == catalogue_checksum("sbom")
    checksums = {lane: catalogue_checksum(lane) for lane in ("sbom", "aibom")}
    assert len(set(checksums.values())) == 2


def test_every_lane_has_a_catalogue():
    assert set(all_catalogues()) == set(ALL_LANES)


def test_duplicate_element_keys_are_refused():
    from app.services.catalogue.types import Catalogue

    element = get_catalogue("sbom").elements[0]
    with pytest.raises(ValueError, match="duplicate element keys"):
        Catalogue(lane="sbom", clause_root="4.2", guideline_version="2.0",
                  elements=(element, element))


def test_a_human_element_without_a_consumer_action_is_refused_at_construction():
    from app.configs.jobTypes import Tier
    from app.services.catalogue.probes import never
    from app.services.catalogue.types import MinimumElement

    with pytest.raises(ValueError, match="consumer action"):
        MinimumElement(
            key="x",
            label="X",
            clause="4.2(99)",
            tier=Tier.CONTEXTUAL,
            determinability=Determinability.HUMAN,
            probe=never,
        )
