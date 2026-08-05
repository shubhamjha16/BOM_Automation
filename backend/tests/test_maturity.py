"""S19: evidence-based SSDLC maturity.

**What this file does not establish.** The sprint exits on a practitioner running
a conventional interview-based maturity review in parallel and every divergence
being explained. That comparison has not happened — it is a human exercise. What
is tested is the rule the comparison would rest on: attested is never evidenced,
and an evidenced verdict without an artifact cannot be constructed.
"""

from __future__ import annotations

import tempfile
from pathlib import Path

import pytest

from app.services.maturity.evidence import (
    ActivityVerdict,
    Basis,
    PlatformSignals,
    RepositorySignals,
    Verdict,
    attested,
    derive,
    observe_repository,
)
from app.services.maturity.roadmap import (
    ACTIVITIES,
    Activity,
    Phase,
    attestable,
    by_key,
    catalogue,
)
from app.services.maturity.scorecard import Scorecard
from app.services.self.maturity import build as build_self_scorecard

REPO_ROOT = Path(__file__).resolve().parent.parent.parent


# --- the roadmap as data -----------------------------------------------------


def test_every_activity_carries_its_clause():
    """The activities are the scorecard's factual basis; a wrong clause
    discredits it exactly as a wrong minimum-element clause does."""
    assert len(ACTIVITIES) >= 12
    for activity in ACTIVITIES:
        assert activity.clause
        assert activity.phase in set(Phase)


def test_an_observable_activity_must_name_its_signal():
    """Otherwise `evidenced` means nothing."""
    with pytest.raises(ValueError, match="must name the signal"):
        Activity(key="x", phase=Phase.START, label="X", clause="3.3.1.1", observable=True)


def test_an_attestable_activity_must_carry_its_question():
    """An attestation without its question is unreviewable."""
    with pytest.raises(ValueError, match="must carry the question"):
        Activity(key="x", phase=Phase.START, label="X", clause="3.3.1.1", observable=False)


def test_the_three_unobservable_activities_are_the_expected_ones():
    """Governance, procurement clauses and training: none is derivable from a
    repository, and pretending otherwise is what makes a scorecard a
    questionnaire in disguise."""
    assert {activity.clause for activity in attestable()} == {
        "3.3.1.4",
        "7.2.15",
        "5.1(d)",
    }


def test_the_roadmap_is_inspectable():
    rows = catalogue()
    assert len(rows) == len(ACTIVITIES)
    assert all(row["signal"] or row["question"] for row in rows)


# --- attested is never evidenced ---------------------------------------------


def test_an_evidenced_verdict_without_an_artifact_cannot_be_constructed():
    """The rule the whole sprint rests on, enforced at construction."""
    with pytest.raises(ValueError, match="must name the artifact"):
        ActivityVerdict(
            activity_key="pin_dependencies",
            clause="3.3.1.2",
            label="Pin dependencies",
            verdict=Verdict.MET,
            basis=Basis.EVIDENCED,
        )


def test_an_attested_verdict_without_its_question_cannot_be_constructed():
    with pytest.raises(ValueError, match="must carry the question"):
        ActivityVerdict(
            activity_key="governance_body",
            clause="5.1(d)",
            label="Governance body",
            verdict=Verdict.MET,
            basis=Basis.ATTESTED,
        )


def test_an_observable_activity_cannot_be_recorded_as_attested():
    """Recording a fact we could have checked as something somebody told us."""
    with pytest.raises(ValueError, match="is observable"):
        attested(by_key("pin_dependencies"), Verdict.MET, answer="we pin them")


def test_an_attested_verdict_carries_the_question_that_was_asked():
    verdict = attested(by_key("governance_body"), Verdict.NOT_MET, answer="none exists")
    assert verdict.basis is Basis.ATTESTED
    assert verdict.question
    assert "terms of reference" in verdict.question
    assert not verdict.is_evidenced


def test_a_not_met_evidenced_verdict_needs_no_artifact():
    """Nothing was found; there is no artifact to point at. The distinction is
    that we looked, which is why it is evidenced rather than unknown."""
    verdict = ActivityVerdict(
        activity_key="incident_playbook",
        clause="3.3.3.2",
        label="Playbook",
        verdict=Verdict.NOT_MET,
        basis=Basis.EVIDENCED,
        detail="no SECURITY.md found",
    )
    assert verdict.is_evidenced
    assert verdict.evidence_ref is None


# --- observation --------------------------------------------------------------


def test_this_repository_is_observed_accurately():
    signals = observe_repository(REPO_ROOT)

    assert any("uv.lock" in item for item in signals.lockfiles)
    assert signals.workflows, "this repository has CI workflows"
    assert signals.sbom_steps, "self-bom.yml runs SBOM generation in CI"
    assert signals.audit_steps, "backend.yml runs pip-audit"


def test_an_empty_repository_yields_no_signals():
    with tempfile.TemporaryDirectory() as workspace:
        signals = observe_repository(Path(workspace))
    assert signals.lockfiles == ()
    assert signals.workflows == ()


def test_vendored_directories_are_not_observed():
    with tempfile.TemporaryDirectory() as workspace:
        root = Path(workspace)
        (root / "node_modules").mkdir()
        (root / "node_modules" / "yarn.lock").write_text("")
        assert observe_repository(root).lockfiles == ()


def test_every_evidenced_verdict_links_to_the_artifact_that_proves_it():
    """The §S19 exit proof."""
    verdicts = derive(observe_repository(REPO_ROOT), PlatformSignals())
    met = [item for item in verdicts if item.verdict is Verdict.MET]

    assert met
    for verdict in met:
        assert verdict.is_evidenced
        assert verdict.evidence_ref, f"{verdict.activity_key} claims met with no artifact"


def test_a_missing_signal_is_not_met_rather_than_unknown():
    """We looked and found nothing; that is a different answer from not looking."""
    verdicts = {item.activity_key: item for item in derive(RepositorySignals())}
    assert verdicts["pin_dependencies"].verdict is Verdict.NOT_MET
    assert "no lockfile" in verdicts["pin_dependencies"].detail


def test_partial_cadence_is_reported_as_partial():
    """Some releases assessed is not the same as all of them."""
    verdicts = {
        item.activity_key: item
        for item in derive(
            RepositorySignals(),
            PlatformSignals(releases_assessed=3, releases_total=10),
        )
    }
    assert verdicts["release_cadence"].verdict is Verdict.PARTIAL


# --- the scorecard -------------------------------------------------------------


def _complete_start() -> Scorecard:
    signals = RepositorySignals(
        manifests=("pyproject.toml",),
        lockfiles=("uv.lock",),
        sbom_steps=(".github/workflows/self-bom.yml",),
    )
    scorecard = Scorecard(verdicts=derive(signals, PlatformSignals()))
    scorecard.verdicts.append(
        attested(by_key("procurement_clauses"), Verdict.MET, answer="clause 7.2 of our MSA")
    )
    return scorecard


def test_a_phase_is_complete_only_when_every_activity_is_met():
    """A phase is a floor, not an average: partial does not complete it."""
    scorecard = _complete_start()
    assert scorecard.phase(Phase.START).is_complete
    assert scorecard.position is Phase.START


def test_a_position_below_start_is_reported_rather_than_rounded_up():
    """Claiming a phase nobody reached is the maturity equivalent of scoring an
    empty BOM as compliant."""
    scorecard = Scorecard(verdicts=derive(RepositorySignals()))
    assert scorecard.position is None
    assert scorecard.as_report()["position"] == "below start"


def test_the_scorecard_reports_evidenced_and_attested_separately():
    """A reader must see how much of a position rests on observation."""
    report = _complete_start().as_report()

    assert report["evidenced"] >= 1
    assert report["attested"] >= 1
    for phase in report["phases"]:
        assert "evidenced" in phase and "attested" in phase


def test_gaps_are_ordered_earliest_phase_first():
    """The work queue: an unmet START activity outranks an unmet ADVANCE one,
    because the phases are sequential."""
    scorecard = Scorecard(verdicts=derive(RepositorySignals()))
    phases = [by_key(gap.activity_key).phase for gap in scorecard.gaps]
    assert phases == sorted(
        phases, key=lambda item: {"start": 0, "progress": 1, "advance": 2}[str(item)]
    )


# --- we assess ourselves, gaps included ---------------------------------------


def test_our_own_scorecard_names_what_we_do_not_do():
    """The §S19 exit proof. A maturity tool that reports only its own strengths
    is not evidence of anything."""
    report = build_self_scorecard().as_report()

    assert report["gaps"], "a scorecard with no gaps is not credible"
    clauses = {gap["clause"] for gap in report["gaps"]}
    # The three we genuinely do not do, stated rather than omitted.
    assert {"5.1(d)", "7.2.15", "3.3.1.4"} <= clauses


def test_our_own_attestations_are_marked_attested_not_evidenced():
    report = build_self_scorecard().as_report()
    attestations = [row for row in report["activities"] if row["basis"] == "attested"]

    assert len(attestations) == 3
    for row in attestations:
        assert row["question"], "an attestation must show what was asked"
        assert row["evidence_ref"] is None


def test_our_evidenced_verdicts_point_at_real_files():
    report = build_self_scorecard().as_report()
    refs = [
        row["evidence_ref"]
        for row in report["activities"]
        if row["basis"] == "evidenced" and row["verdict"] == "met" and row["evidence_ref"]
    ]

    assert refs
    for ref in refs:
        # Some refs are platform facts rather than paths; the file-shaped ones
        # must actually exist, or "evidenced" is decoration.
        if "/" in ref and not ref.endswith(")") and " " not in ref:
            assert (REPO_ROOT / ref).exists(), f"{ref} does not exist"
