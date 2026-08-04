"""S12 + S13: VEX, CSAF, the review gate, redaction and resubmission diffing."""

from __future__ import annotations

import pytest

from app.models.enums import Role
from app.services.agents.loop import Retrieved
from app.services.agents.vexEvidenceAgent import (
    draft_batch,
    draft_for,
    supports_determination,
)
from app.services.reviewGate import (
    WATERMARK,
    ApprovalRequest,
    AssessmentStatus,
    ReviewGateViolation,
    assert_can_approve,
    assert_can_issue,
    watermark_for,
)
from app.services.supplierWorkflow import (
    Movement,
    SupplierScorecard,
    diff_submissions,
    gap_register,
)
from app.services.vex.authoring import (
    VALID_STATUSES,
    InvalidVexStatement,
    VexStatus,
    author,
    default_status_for_insufficient_evidence,
)
from app.services.vex.csaf import CsafExportError, to_csaf, validate
from app.utils.redaction import redact_text, redact_value, redaction_processor

GOOD_JUSTIFICATION = (
    "The vulnerable JndiLookup class is removed at build time and the affected "
    "logging path is unreachable in this configuration."
)


# --- the four statuses are exhaustive ---------------------------------------


def test_there_are_exactly_four_statuses():
    assert set(VALID_STATUSES) == {
        "not_affected",
        "affected",
        "fixed",
        "under_investigation",
    }


def test_a_fifth_status_is_rejected_naming_all_four():
    """The §S12 exit proof."""
    with pytest.raises(InvalidVexStatement) as raised:
        author(cve_id="CVE-2021-44228", status="mitigated")

    message = str(raised.value)
    assert "'mitigated' is not a valid VEX status" in message
    for status in VALID_STATUSES:
        assert status in message
    assert "cannot interpret" in message


@pytest.mark.parametrize("status", ["partially_affected", "wont_fix", "unknown", ""])
def test_every_other_status_is_refused(status):
    with pytest.raises(InvalidVexStatement):
        author(cve_id="CVE-2021-44228", status=status)


def test_a_malformed_cve_identifier_is_refused():
    with pytest.raises(InvalidVexStatement, match="not a CVE identifier"):
        author(cve_id="log4shell", status="affected")


# --- justification is mandatory where it matters ----------------------------


def test_a_not_affected_statement_without_justification_cannot_be_saved():
    """The §S12 exit proof. It is the strongest claim in VEX."""
    with pytest.raises(InvalidVexStatement, match="requires a written justification"):
        author(cve_id="CVE-2021-44228", status="not_affected")


def test_a_fixed_statement_also_requires_one():
    """A consumer acts on `fixed` by upgrading."""
    with pytest.raises(InvalidVexStatement, match="requires a written justification"):
        author(cve_id="CVE-2021-44228", status="fixed")


@pytest.mark.parametrize("thin", ["n/a", "none", "checked", "ok", "fine"])
def test_a_token_justification_is_refused(thin):
    with pytest.raises(InvalidVexStatement, match="too thin to act on"):
        author(cve_id="CVE-2021-44228", status="not_affected", justification=thin)


def test_affected_and_under_investigation_need_no_justification():
    """They assert nothing a consumer would stop investigating over."""
    assert author(cve_id="CVE-2021-44228", status="affected").status is VexStatus.AFFECTED
    assert (
        author(cve_id="CVE-2021-44228", status="under_investigation").status
        is VexStatus.UNDER_INVESTIGATION
    )


def test_a_well_justified_statement_is_accepted():
    statement = author(
        cve_id="cve-2021-44228",
        status="not_affected",
        justification=GOOD_JUSTIFICATION,
        component_ref="log4j-core@2.17.1",
        authored_by="analyst@firm.example",
    )
    assert statement.cve_id == "CVE-2021-44228"  # normalised
    assert statement.authored_by == "analyst@firm.example"
    assert not statement.is_reviewed


# --- the agent drafts, and never decides ------------------------------------


def _retriever(snippet: str, *, url: str = "https://vendor.example/advisory"):
    async def retrieve(query: str) -> Retrieved:
        return Retrieved(url=url, snippet=snippet, candidate="found")

    return retrieve


async def test_evidence_that_merely_mentions_the_cve_is_insufficient():
    """The distinction the whole module exists for: an advisory listing a CVE
    proves the CVE exists, not that this product is affected."""
    draft = await draft_for(
        "CVE-2021-44228",
        component_ref="log4j-core",
        retriever=_retriever("CVE-2021-44228 appears in our reference table."),
        max_hops=2,
    )
    assert draft.justification is None
    assert not draft.is_drafted


async def test_insufficient_evidence_proposes_under_investigation_never_not_affected():
    """The §S12 exit proof. An absence of evidence is not a clearance."""
    draft = await draft_for(
        "CVE-2021-44228",
        component_ref="log4j-core",
        retriever=_retriever("nothing relevant here"),
        max_hops=2,
    )
    assert draft.suggested_status is VexStatus.UNDER_INVESTIGATION
    assert draft.suggested_status is not VexStatus.NOT_AFFECTED
    assert default_status_for_insufficient_evidence() is VexStatus.UNDER_INVESTIGATION


async def test_a_real_determination_is_drafted_with_its_sources():
    draft = await draft_for(
        "CVE-2021-44228",
        component_ref="log4j-core",
        retriever=_retriever(
            "CVE-2021-44228: affected versions 2.0 through 2.14.1. Fixed in 2.17.1."
        ),
        max_hops=2,
    )
    assert draft.is_drafted
    assert "https://vendor.example/advisory" in draft.justification
    assert "not a determination" in draft.justification


async def test_the_agent_never_produces_a_status():
    """§11: a machine-set VEX status is professional judgement laundered through
    a model. There is no code path that sets one."""
    draft = await draft_for(
        "CVE-2021-44228",
        component_ref="log4j-core",
        retriever=_retriever("CVE-2021-44228: affected versions 2.0 to 2.14.1, fixed in 2.17.1"),
        max_hops=2,
    )
    row = draft.as_row()

    assert row["status"] is None
    assert row["requires_analyst_determination"] is True
    # Even with strong evidence, the agent declines to suggest a determination.
    assert draft.suggested_status is None


def test_the_agent_module_has_no_path_to_a_determination_status():
    """Structural: `not_affected` and `fixed` never appear as an agent output."""
    import ast
    from pathlib import Path

    source = (
        Path(__file__).resolve().parent.parent
        / "app"
        / "services"
        / "agents"
        / "vexEvidenceAgent.py"
    ).read_text()

    attributes = {
        node.attr for node in ast.walk(ast.parse(source)) if isinstance(node, ast.Attribute)
    }
    assert "NOT_AFFECTED" not in attributes
    assert "FIXED" not in attributes
    assert "AFFECTED" not in attributes


def test_the_sufficiency_gate_distinguishes_mention_from_determination():
    mention = supports_determination("CVE-2021-44228|log4j", "See CVE-2021-44228 in the appendix.")
    assert not mention.sufficient
    assert "proves the vulnerability exists" in mention.reason

    determination = supports_determination(
        "CVE-2021-44228|log4j", "CVE-2021-44228: affected versions 2.0-2.14.1, fixed in 2.17.1"
    )
    assert determination.sufficient


async def test_a_batch_reports_its_hops():
    drafts, report = await draft_batch(
        [("CVE-2021-44228", "log4j-core"), ("CVE-2022-22965", "spring-core")],
        retriever=_retriever("unrelated"),
        max_hops=2,
    )
    assert len(drafts) == 2
    assert report.as_table()["batches"] == 2


# --- CSAF --------------------------------------------------------------------


def _statements():
    return [
        author(
            cve_id="CVE-2021-44228",
            status="not_affected",
            justification=GOOD_JUSTIFICATION,
            component_ref="log4j-core@2.17.1",
            evidence_refs=("https://vendor.example/advisory",),
        ),
        author(
            cve_id="CVE-2022-22965",
            status="under_investigation",
            component_ref="spring-core@5.3.0",
        ),
    ]


def _document():
    return to_csaf(
        _statements(),
        document_title="BOM Factory VEX",
        publisher_name="Firm A",
        publisher_namespace="https://firm-a.example",
        tracking_id="VEX-2026-0001",
    )


def test_a_csaf_export_validates():
    """The §S12 exit proof."""
    assert validate(_document()) == []


def test_statuses_map_to_the_right_csaf_groups():
    """A wrong mapping makes a consumer's tooling read not_affected as affected."""
    document = _document()
    groups = {
        entry["cve"]: next(iter(entry["product_status"])) for entry in document["vulnerabilities"]
    }
    assert groups["CVE-2021-44228"] == "known_not_affected"
    assert groups["CVE-2022-22965"] == "under_investigation"


def test_a_not_affected_entry_carries_both_prose_and_a_machine_flag():
    entry = next(item for item in _document()["vulnerabilities"] if item["cve"] == "CVE-2021-44228")
    assert entry["flags"], "CSAF mandates a justification flag on known_not_affected"
    assert entry["notes"][0]["text"] == GOOD_JUSTIFICATION


def test_an_empty_advisory_is_refused():
    """An empty advisory asserts nothing and reads as 'nothing applies'."""
    with pytest.raises(CsafExportError, match="at least one VEX statement"):
        to_csaf(
            [], document_title="x", publisher_name="x", publisher_namespace="x", tracking_id="x"
        )


def test_validation_reports_every_defect_at_once():
    problems = validate({"document": {}, "vulnerabilities": []})
    assert len(problems) > 3


# --- the review gate ---------------------------------------------------------


def _request(role: Role, *, author_id="u1", approver_id="u2"):
    return ApprovalRequest(
        assessment_id="a",
        current_status=AssessmentStatus.IN_REVIEW,
        authored_by=author_id,
        approver_id=approver_id,
        approver_role=role,
    )


def test_an_assessor_cannot_approve_at_all():
    with pytest.raises(ReviewGateViolation, match="manager or above"):
        assert_can_approve(_request(Role.ASSESSOR))


@pytest.mark.parametrize("role", [Role.MANAGER, Role.PARTNER])
def test_the_assessor_who_ran_it_cannot_approve_it_however_senior(role):
    """The §S13 exit proof. Seniority does not make one person into two."""
    with pytest.raises(ReviewGateViolation, match="cannot approve it"):
        assert_can_approve(_request(role, author_id="u1", approver_id="u1"))


def test_a_distinct_manager_may_approve():
    assert_can_approve(_request(Role.MANAGER, author_id="u1", approver_id="u2"))


def test_an_already_issued_assessment_cannot_be_approved_again():
    with pytest.raises(ReviewGateViolation, match="already been issued"):
        assert_can_approve(
            ApprovalRequest(
                assessment_id="a",
                current_status=AssessmentStatus.ISSUED,
                authored_by="u1",
                approver_id="u2",
                approver_role=Role.MANAGER,
            )
        )


@pytest.mark.parametrize("status", [AssessmentStatus.DRAFT, AssessmentStatus.IN_REVIEW])
def test_an_unapproved_assessment_cannot_be_issued(status):
    with pytest.raises(ReviewGateViolation, match="only be issued from"):
        assert_can_issue(status)


def test_an_approved_assessment_can_be_issued():
    assert_can_issue(AssessmentStatus.APPROVED)


@pytest.mark.parametrize("status", ["draft", "in_review"])
def test_unapproved_exports_carry_the_watermark(status):
    assert watermark_for(status) == WATERMARK
    assert "not reviewed" in WATERMARK


def test_an_approved_export_carries_no_watermark():
    """A human has signed it, which is precisely what the watermark denies."""
    assert watermark_for("approved") is None
    assert watermark_for("issued") is None


# --- redaction ---------------------------------------------------------------


def test_file_paths_never_reach_logs():
    assert "/Users/apple/Desktop" not in redact_text("read /Users/apple/Desktop/x/bom.json")


def test_internal_hostnames_never_reach_logs():
    assert "build-07.internal" not in redact_text("fetched from build-07.internal:8443")


def test_emails_and_addresses_are_stripped():
    assert "@client.example" not in redact_text("contact analyst@client.example")
    assert "10.0.0.5" not in redact_text("upstream 10.0.0.5")


@pytest.mark.parametrize("key", ["payload", "components", "justification", "access_token"])
def test_forbidden_keys_are_dropped_whatever_they_contain(key):
    assert redact_value(key, {"anything": "here"}) == "[redacted]"


def test_identifiers_and_scores_survive():
    """The observability requirement needs these; redaction must not break it."""
    assert redact_value("job_id", "j-1") == "j-1"
    assert redact_value("score", 43.9) == 43.9
    assert redact_value("clause", "4.2(5)") == "4.2(5)"


def test_the_processor_redacts_a_whole_event():
    event = redaction_processor(
        None,
        "info",
        {
            "event": "assessment_complete",
            "job_id": "j-1",
            "detail": "parsed /srv/app/secret/bom.json",
            "payload": {"components": [{"name": "internal-service"}]},
        },
    )
    assert event["job_id"] == "j-1"
    assert "/srv/app" not in event["detail"]
    assert event["payload"] == "[redacted]"


# --- resubmission diffing ----------------------------------------------------


def _field(key, clause, verdict, coverage, tier="critical"):
    return {
        "element_key": key,
        "clause": clause,
        "verdict": verdict,
        "coverage": coverage,
        "tier": tier,
        "label": key,
    }


def test_a_per_field_diff_surfaces_a_regression_the_total_hides():
    """The §S13 exit proof, and why the diff is per field.

    Two compensating changes give an identical total from different verdicts.
    """
    before = [
        _field("license", "4.2(5)", "absent", 0.03),
        _field("version", "4.2(2)", "present", 1.0),
    ]
    after = [
        _field("license", "4.2(5)", "present", 1.0),
        _field("version", "4.2(2)", "absent", 0.4),
    ]
    diff = diff_submissions(before, after, score_before=50.0, score_after=50.0)

    assert diff.score_delta == 0.0, "the totals are identical"
    assert [item.clause for item in diff.improvements] == ["4.2(5)"]
    assert [item.clause for item in diff.regressions] == ["4.2(2)"]


def test_coverage_movement_is_detected_within_an_unchanged_verdict():
    before = [_field("license", "4.2(5)", "absent", 0.03)]
    after = [_field("license", "4.2(5)", "absent", 0.60)]
    diff = diff_submissions(before, after)
    assert diff.fields[0].movement is Movement.IMPROVED


def test_movement_into_not_determinable_is_not_a_supplier_change():
    """It left the supplier score entirely; it is neither better nor worse."""
    before = [_field("criticality", "4.2(12)", "absent", 0.0)]
    after = [_field("criticality", "4.2(12)", "not_determinable", None)]
    assert diff_submissions(before, after).fields[0].movement is Movement.UNCHANGED


def test_added_and_removed_fields_are_reported():
    diff = diff_submissions(
        [_field("a", "4.2(1)", "present", 1.0)], [_field("b", "4.2(2)", "present", 1.0)]
    )
    movements = {item.element_key: item.movement for item in diff.fields}
    assert movements["a"] is Movement.REMOVED
    assert movements["b"] is Movement.ADDED


def test_the_gap_register_is_ordered_by_tier_not_clause():
    """A supplier fixing gaps in clause order would start at the wrong end."""
    register = gap_register(
        [
            _field("description", "4.2(3)", "absent", 0.0, tier="contextual"),
            _field("version", "4.2(2)", "absent", 0.0, tier="critical"),
            _field("origin", "4.2(6)", "absent", 0.0, tier="standard"),
        ]
    )
    assert [row["tier"] for row in register] == ["critical", "standard", "contextual"]


def test_a_single_submission_has_no_trend():
    """One data point has no direction, and reporting one would invent a trend."""
    assert SupplierScorecard("Acme", [{"score": 50.0}]).trend == "insufficient_history"


def test_a_second_submission_gives_a_direction():
    card = SupplierScorecard("Acme", [{"score": 50.0}, {"score": 62.0}])
    assert card.trend == "improving"
    assert card.latest_score == 62.0


# --- we ship what we ask for -------------------------------------------------


def test_our_own_aibom_declares_every_model_we_use():
    from app.services.self import aibom

    document = aibom.build()
    names = {component["name"] for component in document["components"]}
    assert len(names) == len(aibom.MODELS)
    assert all(
        component["type"] == "machine-learning-model" for component in document["components"]
    )


def test_our_own_aibom_carries_the_two_governance_declarations():
    """9.3(15)-(16) score not_determinable for every supplier because they are
    governance statements. We can supply ours; we are the deployer."""
    from app.services.self import aibom

    properties = {item["name"]: item["value"] for item in aibom.build()["metadata"]["properties"]}
    assert "certin:9.3(15):intended_usage" in properties
    assert "certin:9.3(16):out_of_scope_usage" in properties


def test_the_out_of_scope_statement_disclaims_legal_opinions():
    """The §S13 exit proof, stated plainly."""
    from app.services.self.aibom import OUT_OF_SCOPE_USAGE

    assert "does not issue legal or regulatory opinions" in OUT_OF_SCOPE_USAGE
    assert "does not determine VEX status" in OUT_OF_SCOPE_USAGE
    assert "not a vulnerability scanner" in OUT_OF_SCOPE_USAGE


def test_our_own_cbom_declares_the_cryptography_we_use():
    from app.services.self import cbom

    document = cbom.build()
    names = {component["name"] for component in document["components"]}
    assert {"HMAC-SHA256", "SHA-256", "TLS 1.3", "Argon2id"} <= names


def test_we_declare_no_quantum_exposed_cryptography():
    """If this ever becomes non-empty, our own CBOM must gain a QBOM entry —
    the same rule we apply to suppliers under s.8.5.1."""
    from app.services.self.cbom import quantum_exposed_assets

    assert quantum_exposed_assets() == []
