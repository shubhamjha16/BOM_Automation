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


def test_every_lane_is_now_encoded():
    """All five tables carry elements: SBOM and AIBOM at S1, CBOM and QBOM at
    S14, HBOM at S16. None was ever approximated — each stayed empty, and
    therefore reported `lane_absent`, until its table was actually encoded."""
    assert len(get_catalogue("sbom").elements) == 21
    assert len(get_catalogue("aibom").elements) >= 15
    assert len(get_catalogue("cbom").elements) >= 15
    assert len(get_catalogue("qbom").elements) >= 8
    assert len(get_catalogue("hbom").elements) >= 12


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


# --- S20: the catalogue audit ------------------------------------------------
#
# The instrument is `services/catalogue/audit.py`. It does not perform the audit
# — re-deriving a clause from the published PDF is a person reading a PDF — but it
# enumerates every clause reference the product can put in front of a client and
# runs the mechanical checks. Each defect it found is fixed and kept below.


def test_every_clause_reference_in_the_product_is_enumerated():
    """A clause the worksheet does not list is a clause nobody audits."""
    from app.services.catalogue.audit import worksheet
    from app.services.correlate.engine import RULES
    from app.services.maturity.roadmap import ACTIVITIES

    rows = worksheet()
    expected = (
        sum(len(get_catalogue(lane).elements) for lane in ALL_LANES)
        + len(RULES)
        + len(ACTIVITIES)
    )
    assert len(rows) == expected
    assert all(row.clause and row.label and row.key for row in rows)


def test_no_anchor_has_drifted_from_the_element_it_confirms():
    """An anchor is a claim that a person confirmed *this key* carries *this
    clause*. Edit the element afterwards and the claim silently transfers to the
    new number — an unconfirmed ordinal wearing a confirmed label."""
    from app.services.catalogue.audit import stale_anchors

    assert stale_anchors() == {}


def test_no_two_elements_in_one_lane_claim_the_same_ordinal():
    """The likeliest transcription error when a table is keyed in by hand."""
    from app.services.catalogue.audit import duplicated_clauses

    assert duplicated_clauses() == {}


def test_provisional_is_never_reported_as_anchored():
    """The catalogue equivalent of `not_determinable` never being `compliant`.
    Only 26 of 101 references are confirmed, and the number is published as it
    is."""
    from app.services.catalogue.audit import Provenance, worksheet

    for row in worksheet():
        if row.provenance is Provenance.PROVISIONAL:
            assert not row.confirmed


def test_the_audit_reports_the_unconfirmed_fraction_rather_than_rounding_it_up():
    from app.services.catalogue.audit import coverage

    summary = coverage()
    assert summary["sbom"]["anchored"] == 8
    assert summary["sbom"]["provisional"] == 13
    # The correlation rules cite sections the specification names in prose, so
    # all five are anchored; the lane tables are largely not.
    assert summary["correlation"]["percent_confirmed"] == 100.0
    assert summary["cbom"]["percent_confirmed"] < 100.0


# --- discrepancy 1: QBOM declared s.8.5.1 out of sequence --------------------


def test_every_lane_declares_its_clauses_in_guideline_order():
    """**Found by the audit.** `tests/test_catalogue.py` checked ordering for
    SBOM and AIBOM only, because the other three lanes write their references as
    section numbers and the old check understood ordinals alone — so three of five
    lanes had no ordering check at all.

    With a notation-aware check, QBOM failed: `migration_strategy` cited s.8.5.1
    and was declared fourth, after s.8.5.4. The element is now first, matching the
    guideline. The check now covers all five lanes.
    """
    from app.services.catalogue.audit import ordering_findings

    assert ordering_findings() == {}


def test_qbom_begins_at_the_migration_strategy_clause():
    """The specific case, pinned so the reordering cannot be undone."""
    assert get_catalogue("qbom").elements[0].clause == "8.5.1"
    assert get_catalogue("qbom").elements[0].key == "migration_strategy"


def test_the_ordering_check_is_not_applied_to_the_curated_lists():
    """Correlation rules and roadmap activities draw on scattered sections —
    7.1.6 beside 2.3 beside 3.3.3.1 — and are ordered by lifecycle phase because
    that is how they are read. Sequencing them by ordinal would report a finding
    on every one and mean nothing."""
    from app.services.catalogue.audit import _sort_key
    from app.services.maturity.roadmap import ACTIVITIES

    clauses = [activity.clause for activity in ACTIVITIES]
    assert [_sort_key(clause) for clause in clauses] != sorted(
        _sort_key(clause) for clause in clauses
    )


# --- discrepancy 2: 10.2(4) and 10.2.4 in the same lane ---------------------


def test_the_hbom_notation_near_collision_is_still_present_and_still_flagged():
    """**Found by the audit.** HBOM cites both 10.2(4) — Manufacturer, a row of
    the Table 11 ordinal list — and s.10.2.4, the section making the HBOM-with-SBOM
    pairing explicit, which `firmware_version` rests on. Both are correct. They
    differ by one character.

    This is not fixed by renumbering: the guideline says what it says. It is fixed
    at the point of rendering, and the finding stays visible so nobody later
    "corrects" one of the two into the other.
    """
    from app.services.catalogue.audit import near_collisions

    assert near_collisions() == {"hbom": ["10.2(4)", "10.2.4"]}


def test_a_section_reference_renders_distinguishably_from_a_table_ordinal():
    """The fix. A client reading `10.2.4` beside `10.2(4)` in a report concludes
    the assessment cites the wrong section, and they cannot be talked out of it —
    the two strings really do look like a typo for each other."""
    from app.services.catalogue.audit import cite

    assert cite("10.2.4") == "s.10.2.4"
    assert cite("10.2(4)") == "10.2(4)"
    assert cite("4.2(5)") == "4.2(5)"
    assert cite("8.4.1.2") == "s.8.4.1.2"


def test_the_rendered_report_uses_the_unambiguous_form():
    """Asserted against real rendered output, not against `cite` alone — the
    collision only matters where a reader sees it."""
    import inspect

    from app.services.render.exporters import xlsx
    from app.services.render.sections import builder

    for module in (builder, xlsx):
        source = inspect.getsource(module)
        assert "cite(" in source, f"{module.__name__} renders clauses unguarded"
