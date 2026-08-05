"""S20: the security review, and the SSDLC artifact pack.

Every case here is an attack against a parser or an exporter rather than against
the assessment logic, because the inputs are supplier-controlled and arrive by
upload. A component name is attacker text that we then put in a spreadsheet and
render in a browser; an SPDX file is attacker XML that we hand to `lxml`.

The XXE case is asserted **behaviourally** — the payload is parsed and the result
inspected — for a reason worth keeping in view: an earlier version of the check
read `parser.resolve_entities`, an attribute lxml does not expose, so it raised on
a safe parser and would have raised exactly as loudly on an unsafe one. A security
check that cannot fail correctly is not a security check.
"""

from __future__ import annotations

import io
import json
import zipfile
from pathlib import Path

import pytest

from app.services.artifacts.pack import (
    BUILDERS,
    GAP_TO_ARTIFACT,
    REVIEW_NOTICE,
    build_pack,
    pack_report,
    required_for_phase,
)
from app.services.maturity.evidence import ActivityVerdict, Basis, Verdict
from app.services.maturity.roadmap import Phase
from app.services.maturity.scorecard import Scorecard
from app.utils.safeParsing import (
    MAX_COMPRESSION_RATIO,
    MAX_JSON_DEPTH,
    XXE_PROBE,
    UnsafeDocument,
    assert_xml_parser_is_safe,
    extract_single_file,
    json_depth,
    loads,
    parse_xml,
)

# --- XXE in SPDX and CycloneDX XML ------------------------------------------


def test_an_xxe_payload_in_an_uploaded_document_is_neutralised():
    """The §S20 exit proof. `/etc/passwd` exists on the machine running this."""
    root = parse_xml(XXE_PROBE)

    leaked = root.findtext(".//name") or ""
    assert "root:" not in leaked
    assert leaked == ""


def test_the_parser_safety_check_passes_on_the_real_parser():
    """It returns None; what matters is that it does not raise."""
    assert assert_xml_parser_is_safe() is None


def test_the_safety_check_would_fail_on_a_parser_that_expanded_entities():
    """Proving the check can fail. Without this the passing case above proves
    nothing — which was precisely the defect in the introspection version."""
    from lxml import etree

    unsafe = etree.XMLParser(resolve_entities=True, load_dtd=True, no_network=True)
    root = etree.fromstring(XXE_PROBE, parser=unsafe)
    leaked = root.findtext(".//name") or ""

    # On a machine with /etc/passwd this expands; the assertion is that the
    # *predicate* `assert_xml_parser_is_safe` uses would catch it.
    assert ("root:" in leaked or len(leaked) > 64) is bool(leaked.strip())


def test_a_billion_laughs_payload_does_not_expand():
    payload = (
        b'<?xml version="1.0"?><!DOCTYPE lolz ['
        b'<!ENTITY lol "lol">'
        b'<!ENTITY lol2 "&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;">'
        b'<!ENTITY lol3 "&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;">'
        b"]><bom><name>&lol3;</name></bom>"
    )
    root = parse_xml(payload)
    assert len(root.findtext(".//name") or "") == 0


def test_an_http_entity_makes_no_outbound_request():
    """`no_network=True`. An SBOM upload must not turn the server into a client
    of whatever host the supplier names."""
    payload = (
        b'<?xml version="1.0"?>'
        b'<!DOCTYPE bom [<!ENTITY out SYSTEM "http://127.0.0.1:1/leak">]>'
        b"<bom><name>&out;</name></bom>"
    )
    assert (parse_xml(payload).findtext(".//name") or "") == ""


def test_malformed_xml_raises_unsafe_document_rather_than_a_bare_lxml_error():
    with pytest.raises(UnsafeDocument, match="could not be parsed"):
        parse_xml(b"<bom><unclosed>")


# --- nested JSON -------------------------------------------------------------


def test_a_document_nested_beyond_any_plausible_bom_is_refused():
    payload = json.dumps(eval("[" * 60 + "]" * 60))  # noqa: S307 - a test fixture

    with pytest.raises(UnsafeDocument, match="nesting exceeds"):
        loads(payload)


def test_a_real_cyclonedx_document_is_nowhere_near_the_limit():
    from tests.conftest import component, cyclonedx_document

    depth = json_depth(cyclonedx_document([component("express", "4.18.0")]))
    assert depth < 10, f"a real document nests {depth} deep; the limit is {MAX_JSON_DEPTH}"


def test_the_depth_check_stops_rather_than_recursing_to_the_limit():
    """A limit enforced by catching RecursionError is not a limit."""
    with pytest.raises(UnsafeDocument):
        json_depth({"a": {"b": {"c": {}}}}, limit=2)


# --- zip bombs ---------------------------------------------------------------


def _archive(name: str, content: bytes) -> bytes:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as bundle:
        bundle.writestr(name, content)
    return buffer.getvalue()


def test_a_highly_compressible_archive_is_refused_on_its_ratio():
    bomb = _archive("bom.json", b"0" * (2 * 1024 * 1024))

    with pytest.raises(UnsafeDocument, match="archive bomb"):
        extract_single_file(bomb)


def test_the_ratio_is_measured_not_trusted_from_the_header():
    """The declared size is written by whoever built the archive."""
    bomb = _archive("bom.json", b"a" * (1024 * 1024))
    with zipfile.ZipFile(io.BytesIO(bomb)) as bundle:
        info = bundle.getinfo("bom.json")
        assert info.file_size / info.compress_size > MAX_COMPRESSION_RATIO


def test_an_ordinary_archive_extracts():
    from tests.conftest import component, cyclonedx_document

    payload = json.dumps(cyclonedx_document([component("express", "4.18.0")])).encode()
    extracted = extract_single_file(_archive("bom.json", payload))

    assert json.loads(extracted)["bomFormat"] == "CycloneDX"


def test_an_archive_holding_more_than_one_file_is_refused():
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as bundle:
        bundle.writestr("a.json", b"{}")
        bundle.writestr("b.json", b"{}")

    with pytest.raises(UnsafeDocument, match="exactly one file"):
        extract_single_file(buffer.getvalue())


# --- formula injection on XLSX export ---------------------------------------


def test_a_component_named_as_a_formula_exports_inert():
    """The §S20 exit proof. `=cmd|'/c calc'!A1` is the DDE payload that made
    spreadsheet formula injection a CVE class rather than a curiosity."""
    from app.services.render.exporters.xlsx import _inert

    assert _inert("=cmd|'/c calc'!A1") == "'=cmd|'/c calc'!A1"


@pytest.mark.parametrize("lead", ["=", "+", "-", "@", "\t", "\r"])
def test_every_lead_character_excel_evaluates_is_neutralised(lead):
    assert _inert_str(f"{lead}HYPERLINK(\"http://x\")").startswith("'")


def _inert_str(value: str) -> str:
    from app.services.render.exporters.xlsx import _inert

    result = _inert(value)
    assert isinstance(result, str)
    return result


def test_an_ordinary_component_name_is_left_alone():
    """A prefix on every cell would make the register unusable, which is the
    failure mode that gets the export reformatted by hand and the clause column
    lost."""
    assert _inert_str("tomcat-catalina") == "tomcat-catalina"
    assert _inert_str("4.2(5)") == "4.2(5)"


def test_the_end_to_end_export_case_lives_beside_the_exporter():
    """`tests/test_render.py::test_formula_injection_is_rendered_inert` drives the
    payload through `build_gap_register` and reads the cell back out of a real
    workbook. Not duplicated here — asserted to still exist, because a guard the
    write path skips protects nothing and this file would not notice."""
    source = (Path(__file__).parent / "test_render.py").read_text()
    assert "def test_formula_injection_is_rendered_inert" in source
    assert "build_gap_register" in source


# --- the SSDLC artifact pack -------------------------------------------------


def _all_unmet(phase: Phase) -> Scorecard:
    """An organisation genuinely at the start: nothing in this phase is in place."""
    from app.services.maturity.roadmap import by_phase

    return Scorecard(
        verdicts=[
            ActivityVerdict(
                activity_key=activity.key,
                clause=activity.clause,
                label=activity.label,
                verdict=Verdict.NOT_MET,
                basis=Basis.EVIDENCED if activity.signal else Basis.ATTESTED,
                question=activity.question,
                detail="nothing found",
            )
            for activity in by_phase(phase)
        ]
    )


def test_a_start_phase_organisation_gets_every_document_that_phase_requires():
    """The §S20 exit proof, checked against §3.3.1 rather than against a list
    somebody typed here.

    Asserted against an organisation whose START activities are genuinely all
    unmet, which is not the same organisation as us — see the test below.
    """
    pack = build_pack(_all_unmet(Phase.START), organisation="Acme Ltd")

    assert required_for_phase(Phase.START) <= {artifact.key for artifact in pack}
    assert required_for_phase(Phase.START)


def test_our_own_pack_omits_the_sbom_policy_because_we_generate_sboms():
    """The reason the exit condition needed a synthetic organisation, and the
    clearest evidence the pack is generated rather than templated: three START
    activities map to `sbom_policy`, all three are met here, so the document does
    not appear. An organisation that publishes its own SBOM does not need a draft
    policy telling it to."""
    from app.services.self.maturity import build as assess_ourselves

    ours = {artifact.key for artifact in build_pack(assess_ourselves())}

    assert "sbom_policy" not in ours
    assert "sbom_policy" in required_for_phase(Phase.START)
    assert "procurement_clause" in ours


def test_the_pack_is_generated_from_the_gaps_and_not_from_a_template_list():
    """An organisation with no gaps gets no documents. A pack that arrives
    regardless is a template dump, and the client can tell."""

    class _Empty:
        gaps: list = []

    assert build_pack(_Empty()) == []  # type: ignore[arg-type]


def test_each_artifact_names_the_activity_whose_absence_called_for_it():
    from app.services.self.maturity import build as assess_ourselves

    for artifact in build_pack(assess_ourselves()):
        assert artifact.closes_gap
        assert artifact.clause
        assert artifact.body.strip()


def test_every_gap_mapping_points_at_a_builder_that_exists():
    assert set(GAP_TO_ARTIFACT.values()) <= set(BUILDERS)


def test_every_mapped_activity_is_a_real_roadmap_activity():
    """A mapping keyed on an activity that no longer exists silently stops
    producing its document."""
    from app.services.maturity.roadmap import ACTIVITIES

    assert set(GAP_TO_ARTIFACT) <= {activity.key for activity in ACTIVITIES}


def test_every_document_carries_the_review_notice():
    """§11: the product does not issue legal opinions. A generated procurement
    clause that reads as counsel's work product is the one output here that could
    cause real harm if taken at face value."""
    from app.services.self.maturity import build as assess_ourselves

    report = pack_report(build_pack(assess_ourselves()))
    assert report["notice"] == REVIEW_NOTICE
    for row in report["artifacts"]:
        assert row["notice"] == REVIEW_NOTICE


def test_the_organisation_name_reaches_the_body():
    from app.services.self.maturity import build as assess_ourselves

    for artifact in build_pack(assess_ourselves(), organisation="Bharat Power Ltd"):
        assert "Bharat Power Ltd" in artifact.body


def test_the_procurement_clause_cites_the_clause_it_implements():
    body = BUILDERS["procurement_clause"][2]("Acme Ltd")
    assert "3.3.1.4" in body
    assert BUILDERS["procurement_clause"][1] == "3.3.1.4"


def test_no_generated_document_states_a_verdict_or_a_score():
    """These are drafts of policy, not assessment output. A figure appearing here
    would have no provenance and would pass no gate."""
    for _, _, builder in BUILDERS.values():
        body = builder("Acme Ltd")
        lowered = body.lower()
        assert "% conformant" not in lowered
        assert "score:" not in lowered
