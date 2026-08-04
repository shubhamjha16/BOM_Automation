"""S8: the conformance gate and the determinability rule. No bypass flag.

The gate's job is to refuse. Every test here injects something that must never
reach a client and asserts that nothing rendered.
"""

from __future__ import annotations

import ast
from pathlib import Path

import pytest

from app.configs.jobTypes import JobStatus
from app.services.assessmentService import run_assessment
from app.services.graph.nodes.conformanceGate import conformance_gate
from app.services.graph.state import (
    CorrelationFinding,
    GraphState,
    LaneResult,
    SubmissionDocument,
)
from app.validators.conformanceValidator import (
    Citation,
    ClauseNotTraceable,
    assert_all_traceable,
    citations_from,
    correlation_clauses,
    known_clauses,
)
from app.validators.determinabilityValidator import (
    DeterminabilityViolation,
    assert_rows_not_scored,
)
from tests.conftest import component, cyclonedx_document

BACKEND = Path(__file__).resolve().parent.parent


def _field(**overrides) -> dict:
    row = {
        "element_key": "license",
        "label": "Licence",
        "clause": "4.2(5)",
        "tier": "critical",
        "determinability": "auto",
        "verdict": "absent",
        "populated": 0,
        "total": 10,
        "coverage": 0.0,
        "weight": 3.0,
        "detail": "absent across all 10 entities",
        "consumer_action": None,
    }
    row.update(overrides)
    return row


def _state(fields: list[dict], findings: list[CorrelationFinding] | None = None) -> GraphState:
    return GraphState(
        job_id="j",
        lane_results=[
            LaneResult(lane="sbom", verdict="fail", score=10.0, field_results=fields)  # type: ignore[arg-type]
        ],
        correlation_findings=findings or [],
        node_runs=[],
    )


# --- a fabricated clause blocks the job -------------------------------------


async def test_a_fabricated_clause_blocks_the_job_and_names_the_field():
    """The §S8 exit proof. Nothing renders."""
    state = _state([_field(clause="4.2(99)", element_key="invented")])
    result = await conformance_gate(state)

    assert result["status"] is JobStatus.BLOCKED_CONFORMANCE
    assert result["gate_verdict"] == "blocked"
    assert "4.2(99)" in result["gate_reason"]
    assert "sbom.invented" in result["gate_reason"]
    # Nothing rendered: the gate produced a refusal, not an assessment.
    assert "sections" not in result


async def test_a_fabricated_clause_in_a_correlation_finding_blocks_too():
    """Correlation findings cite the guideline exactly as field verdicts do, so
    they pass the same gate — otherwise the one class of finding no single-lane
    tool can produce would be the one class nobody verified."""
    finding = CorrelationFinding(
        rule_key="invented", severity="high", clause="99.9.9", detail="made up"
    )
    result = await conformance_gate(_state([_field()], [finding]))

    assert result["status"] is JobStatus.BLOCKED_CONFORMANCE
    assert "99.9.9" in result["gate_reason"]
    assert "correlation.invented" in result["gate_reason"]


async def test_every_untraceable_clause_is_reported_at_once():
    """One at a time means an analyst fixes, re-runs, and finds the next."""
    state = _state(
        [
            _field(clause="4.2(98)", element_key="a"),
            _field(clause="4.2(99)", element_key="b"),
        ]
    )
    reason = (await conformance_gate(state))["gate_reason"]

    assert "2 untraceable" in reason
    assert "4.2(98)" in reason
    assert "4.2(99)" in reason


async def test_a_clean_assessment_passes_the_gate():
    result = await conformance_gate(_state([_field()]))
    assert result["gate_verdict"] == "passed"
    assert result["gate_reason"] is None
    assert "status" not in result


# --- determinability --------------------------------------------------------


def test_scoring_a_not_determinable_field_is_refused_at_the_validator():
    """The §S8 exit proof: an attempt to score one is refused."""
    scored = _field(
        element_key="criticality",
        clause="4.2(12)",
        determinability="human",
        verdict="not_determinable",
        total=400,          # coverage means it was scored
        populated=0,
        consumer_action="rate each component",
    )
    with pytest.raises(DeterminabilityViolation, match="entered the supplier score"):
        assert_rows_not_scored([scored])


def test_marking_a_consumer_determination_as_present_is_refused():
    """The direction a probe bug takes: a green tick on a field nobody checked."""
    forged = _field(
        element_key="criticality",
        clause="4.2(12)",
        determinability="human",
        verdict="present",
        total=0,
    )
    with pytest.raises(DeterminabilityViolation, match="mishandled"):
        assert_rows_not_scored([forged])


def test_a_not_determinable_field_without_an_action_is_refused():
    """Without one it reads as a shrug, and the reader assumes it passed."""
    naked = _field(
        element_key="criticality",
        clause="4.2(12)",
        determinability="human",
        verdict="not_determinable",
        total=0,
        consumer_action=None,
    )
    with pytest.raises(DeterminabilityViolation, match="names no action"):
        assert_rows_not_scored([naked])


async def test_the_gate_blocks_a_determinability_violation():
    forged = _field(
        element_key="usage_restrictions",
        clause="4.2(13)",
        determinability="human",
        verdict="present",
        total=0,
    )
    result = await conformance_gate(_state([_field(), forged]))

    assert result["status"] is JobStatus.BLOCKED_CONFORMANCE
    assert "4.2(13)" in result["gate_reason"]


# --- the real assessment path -----------------------------------------------


async def test_a_real_assessment_carries_only_traceable_clauses():
    summary = await run_assessment(
        org_id="org",
        submission_id="sub",
        documents=[
            SubmissionDocument(
                lane="sbom",
                format="CycloneDX",
                payload=cyclonedx_document([component("tomcat-catalina")]),
            )
        ],
        requested_lanes=["sbom"],
    )
    assert summary.status is JobStatus.SUCCEEDED
    assert summary.gate_reason is None

    citations = citations_from(summary.lane_results, summary.correlation_findings)
    assert citations, "an assessment with no citations has nothing to gate"
    assert_all_traceable(citations)


async def test_the_four_consumer_determinations_render_in_their_own_section():
    """4.2(12), 4.2(13) for SBOM and 9.3(15)-(16) for AIBOM, with rationale."""
    from app.services.catalogue.loader import get_catalogue

    sbom = {
        element.clause: element for element in get_catalogue("sbom").consumer_determined
    }
    aibom = {
        element.clause: element for element in get_catalogue("aibom").consumer_determined
    }

    assert set(sbom) == {"4.2(12)", "4.2(13)"}
    assert set(aibom) == {"9.3(15)", "9.3(16)"}
    for element in list(sbom.values()) + list(aibom.values()):
        assert element.rationale, f"{element.key} renders with no rationale"
        assert element.consumer_action, f"{element.key} renders with no action"
        assert not element.scores_against_supplier


# --- no bypass --------------------------------------------------------------


def test_the_gate_has_no_bypass_parameter():
    """A flag would be used, eventually, by someone under deadline."""
    source = (
        BACKEND / "app" / "services" / "graph" / "nodes" / "conformanceGate.py"
    ).read_text()
    tree = ast.parse(source)

    for node in ast.walk(tree):
        if isinstance(node, ast.AsyncFunctionDef) and node.name == "conformance_gate":
            arguments = [argument.arg for argument in node.args.args]
            assert arguments == ["state"], f"the gate takes {arguments}; it takes state only"
            assert not node.args.kwonlyargs, "the gate accepts keyword arguments"
            assert not node.args.defaults, "the gate has a default that could disable it"
            break
    else:  # pragma: no cover
        pytest.fail("conformance_gate not found")

    # Identifiers, not prose. The first version of this test failed on the
    # module docstring that says "No bypass flag" — the same false positive as
    # the layering check in test_http.py, and worth not repeating.
    identifiers: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Name):
            identifiers.add(node.id.lower())
        elif isinstance(node, ast.Attribute):
            identifiers.add(node.attr.lower())
        elif isinstance(node, ast.arg):
            identifiers.add(node.arg.lower())
        elif isinstance(node, ast.keyword) and node.arg:
            identifiers.add(node.arg.lower())

    for banned in ("skip", "bypass", "force", "override", "disable"):
        offenders = {name for name in identifiers if banned in name}
        assert not offenders, f"the gate defines or reads {sorted(offenders)}"


def test_the_gate_reads_no_configuration():
    """A settings-driven gate is a gate with an off switch in the environment."""
    source = (
        BACKEND / "app" / "services" / "graph" / "nodes" / "conformanceGate.py"
    ).read_text()
    imported = {
        alias.name
        for node in ast.walk(ast.parse(source))
        if isinstance(node, ast.ImportFrom)
        for alias in node.names
    }
    assert "settings" not in imported, "the gate reads settings; that is an off switch"
    assert "os" not in imported


def test_the_gate_runs_before_anything_renders():
    """Wiring check: the gate sits between correlate and the end of the graph."""
    builder = (BACKEND / "app" / "services" / "graph" / "builder.py").read_text()
    assert '"correlate", "conformanceGate"' in builder
    assert '"conformanceGate", END' in builder


# --- clause sources ---------------------------------------------------------


def test_known_clauses_covers_every_lane():
    clauses = known_clauses()
    assert "4.2(21)" in clauses
    assert "9.3(16)" in clauses


def test_correlation_clauses_come_from_the_rules_themselves():
    """Held beside the rules, not hardcoded in the validator."""
    assert {"8.4.1.2", "9.3(6)", "8.5.1"} <= correlation_clauses()


def test_a_lane_clause_used_by_the_wrong_lane_is_refused():
    """9.3(6) is an AIBOM clause; an SBOM field verdict citing it is a bug."""
    with pytest.raises(ClauseNotTraceable):
        assert_all_traceable([Citation(clause="9.3(6)", lane="sbom", source="sbom.x")])
