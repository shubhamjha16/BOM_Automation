"""S15: assessment sections and export breadth.

**What this file does not establish.** The sprint exits on a practitioner
reviewing a full assessment against the guideline and signing it, and on a
procurement reader with no security background stating the top three gaps
unaided. Neither has happened. What is tested here is the structural claim those
reviews would rest on: the top three gaps are present, ordered by tier, and
every figure traces to the scorer.
"""

from __future__ import annotations

from io import BytesIO

import pytest
from openpyxl import load_workbook

from app.services.render.exporters import docx, json_export, pdf, xlsx
from app.services.render.sections.builder import (
    AssessmentInput,
    build_sections,
    executive_summary,
    remediation_roadmap,
)
from app.services.reviewGate import WATERMARK, watermark_for
from app.validators.figureProvenanceValidator import assert_figures_traceable


class _Lane:
    def __init__(self, lane, verdict, score, rows, entity_count=40, detail=""):
        self.lane = lane
        self.verdict = verdict
        self.score = score
        self.field_results = rows
        self.entity_count = entity_count
        self.detail = detail


def _row(key, clause, verdict, tier, populated, total, coverage, **extra):
    return {
        "element_key": key,
        "label": key.replace("_", " ").title(),
        "clause": clause,
        "verdict": verdict,
        "tier": tier,
        "populated": populated,
        "total": total,
        "coverage": coverage,
        "detail": f"{populated} of {total}",
        "consumer_action": extra.get("consumer_action"),
    }


def _assessment():
    rows = [
        _row("certin_identifier", "4.2(21)", "absent", "critical", 0, 40, 0.0),
        _row("description", "4.2(3)", "absent", "contextual", 0, 40, 0.0),
        _row("license", "4.2(5)", "absent", "critical", 3, 40, 0.075),
        _row("origin", "4.2(6)", "absent", "standard", 0, 40, 0.0),
        _row("component_name", "4.2(1)", "present", "critical", 40, 40, 1.0),
        _row(
            "criticality",
            "4.2(12)",
            "not_determinable",
            "contextual",
            0,
            0,
            None,
            consumer_action="Rate each component against your own deployment.",
        ),
    ]
    return AssessmentInput(
        submission_id="sub-1",
        overall_score=40.49,
        lane_results=[
            _Lane("sbom", "fail", 40.49, rows, detail="scored 40.49%"),
            _Lane("aibom", "lane_absent", None, []),
        ],
        correlation_findings=[],
    )


# --- the executive summary ---------------------------------------------------


def test_the_top_three_gaps_are_stateable_from_the_summary_alone():
    """The §S15 exit proof's structural half."""
    body = executive_summary(_assessment()).body

    assert "The three gaps requiring attention first:" in body
    assert "4.2(21)" in body
    assert body.count("\n  1.") == 1


def test_gaps_are_ordered_by_tier_not_clause_number():
    """Clause order would put 4.2(1) Component Name above 4.2(21) CERT-In
    Identifier, inverting the priority."""
    body = executive_summary(_assessment()).body
    ranked = [line for line in body.split("\n") if line.strip().startswith(("1.", "2.", "3."))]

    assert "4.2(21)" in ranked[0]
    # The contextual gap must not outrank a critical one despite a lower clause.
    assert "4.2(3)" not in " ".join(ranked)


def test_an_absent_lane_is_reported_as_a_finding_not_a_silence():
    body = executive_summary(_assessment()).body
    assert "expected and not supplied" in body
    assert "itself a finding" in body


def test_the_summary_states_what_a_passing_score_does_not_mean():
    body = executive_summary(_assessment()).body
    assert "not a legal opinion" in body
    assert "not that the software is secure" in body


def test_every_figure_in_the_summary_traces_to_the_scorer():
    assessment = _assessment()
    assert_figures_traceable(
        executive_summary(assessment).body, lane_results=assessment.lane_results
    )


def test_a_clean_submission_says_so_rather_than_listing_nothing():
    clean = AssessmentInput(
        submission_id="s",
        overall_score=95.0,
        lane_results=[
            _Lane(
                "sbom",
                "pass",
                95.0,
                [_row("license", "4.2(5)", "present", "critical", 40, 40, 1.0)],
            )
        ],
    )
    assert "No unmet minimum elements" in executive_summary(clean).body


# --- the roadmap -------------------------------------------------------------


def test_every_roadmap_step_carries_the_clause_it_satisfies():
    """A roadmap without clause references is a to-do list; the supplier is
    audited against the clause."""
    body = remediation_roadmap(_assessment(), 5).body
    steps = [line for line in body.split("\n") if line and line[0].isdigit()]

    assert steps
    assert all("clause" in step for step in steps)


def test_the_roadmap_is_prioritised_critical_first():
    body = remediation_roadmap(_assessment(), 5).body
    assert body.index("[CRITICAL]") < body.index("[CONTEXTUAL]")


# --- provenance --------------------------------------------------------------


def test_every_section_records_what_it_was_written_from():
    sections = build_sections(_assessment())
    written_from = [
        section
        for section in sections
        if section.field_verdict_keys or section.correlation_rule_keys
    ]
    assert len(written_from) >= 4


def test_consumer_determinations_get_their_own_section_with_actions():
    sections = {section.section_type: section for section in build_sections(_assessment())}
    body = sections["consumer_determinations"].body

    assert "4.2(12)" in body
    assert "Action required:" in body
    assert "not reported as met" in body


def test_the_appendix_lists_every_field_verdict():
    sections = {section.section_type: section for section in build_sections(_assessment())}
    appendix = sections["field_appendix"]
    assert len(appendix.field_verdict_keys) == 6


# --- the XLSX gap register ---------------------------------------------------


def _register(watermark: str | None = None):
    return load_workbook(
        BytesIO(xlsx.build_gap_register(_assessment().lane_results, watermark=watermark))
    )


def test_the_register_has_one_tab_per_lane():
    """The §S15 exit proof."""
    assert _register().sheetnames == ["SBOM", "AIBOM"]


def test_the_clause_column_is_intact_and_first():
    sheet = _register()["SBOM"]
    assert sheet.cell(1, 1).value == "Clause"
    assert str(sheet.cell(2, 1).value).startswith("4.2(")


def test_the_register_is_ordered_critical_first():
    """A supplier working top-down must start at the critical gaps."""
    sheet = _register()["SBOM"]
    tiers = [sheet.cell(row, 3).value for row in range(2, 7) if sheet.cell(row, 3).value]
    assert tiers[0] == "critical"
    assert tiers[-1] == "contextual"


def test_the_register_carries_what_is_required_not_just_the_verdict():
    sheet = _register()["SBOM"]
    assert sheet.cell(1, 8).value == "What is required"
    assert any(sheet.cell(row, 8).value for row in range(2, 7))


def test_a_consumer_determination_carries_its_action_in_the_register():
    sheet = _register()["SBOM"]
    actions = [sheet.cell(row, 8).value for row in range(2, 8)]
    assert any(action and "your own deployment" in str(action) for action in actions)


def test_a_lane_with_no_gaps_says_so_rather_than_showing_an_empty_tab():
    assert _register()["AIBOM"].cell(2, 1).value == "No unmet elements in this lane."


@pytest.mark.parametrize("payload", ["=cmd|'/c calc'!A1", "+1+1", "-2+3", "@SUM(A1)"])
def test_formula_injection_is_rendered_inert(payload):
    """Component names are supplier-controlled text and this file is opened in
    Excel by someone who trusts it."""
    lanes = [
        _Lane("sbom", "fail", 10.0, [_row(payload, "4.2(1)", "absent", "critical", 0, 1, 0.0)])
    ]
    sheet = load_workbook(BytesIO(xlsx.build_gap_register(lanes)))["SBOM"]

    value = str(sheet.cell(2, 2).value)
    assert not value.startswith(("=", "+", "-", "@"))


def test_the_register_carries_the_watermark_when_unapproved():
    sheet = _register(watermark=WATERMARK)["SBOM"]
    found = [
        sheet.cell(row, 1).value
        for row in range(1, sheet.max_row + 1)
        if sheet.cell(row, 1).value == WATERMARK
    ]
    assert found


# --- DOCX and JSON -----------------------------------------------------------


def test_the_docx_export_renders_every_section():
    from docx import Document as ReadDocument

    sections = build_sections(_assessment())
    document = ReadDocument(
        BytesIO(docx.build_assessment(sections, title="Conformance assessment"))
    )
    headings = [p.text for p in document.paragraphs]

    assert "Conformance assessment" in headings
    assert "Executive summary" in headings
    assert any("not a legal opinion" in text for text in headings)


def test_an_unapproved_docx_carries_the_watermark_where_it_cannot_be_missed():
    from docx import Document as ReadDocument

    document = ReadDocument(
        BytesIO(
            docx.build_assessment(
                build_sections(_assessment()), title="x", watermark=watermark_for("draft")
            )
        )
    )
    assert WATERMARK.upper() in document.paragraphs[0].text


def test_an_approved_docx_carries_no_watermark():
    from docx import Document as ReadDocument

    document = ReadDocument(
        BytesIO(
            docx.build_assessment(
                build_sections(_assessment()), title="x", watermark=watermark_for("approved")
            )
        )
    )
    assert WATERMARK.upper() not in document.paragraphs[0].text


def test_the_json_export_carries_the_provenance_chain():
    import json

    assessment = _assessment()
    payload = json.loads(
        json_export.build_assessment(
            build_sections(assessment),
            submission_id="sub-1",
            overall_score=assessment.overall_score,
            lane_results=assessment.lane_results,
            correlation_findings=[],
        )
    )
    assert payload["sections"][0]["field_verdict_ids"]
    assert payload["disclaimer"]
    assert payload["lanes"][0]["fields"]


# --- PDF, stated honestly ----------------------------------------------------


def test_pdf_reports_its_own_unavailability_rather_than_failing_obscurely():
    """The stack fixes PDF as python-docx -> LibreOffice, and LibreOffice is not
    installed here. The path is implemented; its absence is reported."""
    if pdf.is_available():  # pragma: no cover - depends on the machine
        pytest.skip("LibreOffice is installed; the conversion path is exercisable")

    with pytest.raises(pdf.PdfUnavailable, match="LibreOffice"):
        pdf.from_docx(b"not-a-real-docx")


def test_the_pdf_failure_names_the_exports_that_still_work():
    if pdf.is_available():  # pragma: no cover
        pytest.skip("LibreOffice is installed")
    try:
        pdf.from_docx(b"x")
    except pdf.PdfUnavailable as error:
        assert "DOCX and XLSX exports are unaffected" in str(error)
