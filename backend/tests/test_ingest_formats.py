"""S6: the format matrix, and entry conservation across every fixture.

`fixtures/boms/README.md` records which fixtures are captured tool output and
which are authored to the specification. The cdxgen ones are real.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from app.services.ingest.detect import (
    Format,
    FormatMismatch,
    UnrecognisedFormat,
    detect,
)
from app.services.ingest.normalize import ingest_document, supported_formats
from app.services.ingest.parsers import spdxJson, spdxTagValue
from app.services.ingest.parsers.spdxTagValue import TruncatedDocument
from app.services.ingest.result import EntryConservationError

FIXTURES = Path(__file__).resolve().parent / "fixtures" / "boms"
CYCLONEDX = sorted((FIXTURES / "cyclonedx").glob("*.json"))
SPDX_JSON = sorted((FIXTURES / "spdx").glob("*.json"))
SPDX_TAG = sorted(p for p in (FIXTURES / "spdx").glob("*.spdx") if "truncated" not in p.name)


def test_the_fixture_set_is_actually_present():
    """A silently empty fixture directory would make every matrix test vacuous."""
    assert len(CYCLONEDX) == 3, "expected cdxgen output at 1.4, 1.5 and 1.6"
    assert len(SPDX_JSON) == 2, "expected SPDX 2.2 and 2.3 JSON"
    assert len(SPDX_TAG) == 2, "expected SPDX 2.2 and 2.3 tag-value"


# --- entry conservation, every fixture, every lane --------------------------


@pytest.mark.parametrize("path", CYCLONEDX + SPDX_JSON, ids=lambda p: p.name)
@pytest.mark.parametrize("lane", ["sbom", "aibom"])
def test_parsed_plus_rejected_equals_entry_count_for_every_json_fixture(path, lane):
    """The S6 contract. A silent drop shrinks the denominator and *raises* every
    coverage percentage in the assessment."""
    payload = json.loads(path.read_text())
    result = ingest_document(payload, lane=lane)

    declared = len(payload.get("components") or payload.get("packages") or [])
    assert result.parsed_count + result.rejected_count == declared
    result.assert_conserved(declared)


@pytest.mark.parametrize("path", SPDX_TAG, ids=lambda p: p.name)
def test_parsed_plus_rejected_equals_entry_count_for_tag_value(path):
    result = ingest_document(path.read_text(), lane="sbom")
    assert result.parsed_count + result.rejected_count == result.declared_entries
    assert result.parsed_count > 0, "the tag-value fixture parsed nothing at all"


def test_conservation_failure_is_loud_and_says_what_it_means():
    payload = json.loads(CYCLONEDX[0].read_text())
    result = ingest_document(payload, lane="sbom")
    with pytest.raises(EntryConservationError, match="inflates every coverage"):
        result.assert_conserved(result.entry_count + 1)


# --- real cdxgen output -----------------------------------------------------


@pytest.mark.parametrize("path", CYCLONEDX, ids=lambda p: p.name)
def test_real_cdxgen_output_parses_at_every_spec_version(path):
    payload = json.loads(path.read_text())
    result = ingest_document(payload, lane="sbom")

    assert result.spec_version == path.stem.rsplit("-", 1)[1]
    assert result.parsed_count > 50, "cdxgen output should carry the backend's deps"
    assert all(entity["name"] for entity in result.entities)


# --- SPDX JSON --------------------------------------------------------------


@pytest.mark.parametrize("path", SPDX_JSON, ids=lambda p: p.name)
def test_spdx_json_parses_with_its_dependency_graph(path):
    result = ingest_document(json.loads(path.read_text()), lane="sbom")
    entities = {entity["name"]: entity for entity in result.entities}

    assert result.format == "SPDX"
    # Dependencies are stored as SPDXIDs, mirroring how CycloneDX stores bom-refs:
    # the reference is what the document uses to identify an element, and names
    # are not unique.
    depends_on = entities["tomcat-catalina"]["dependencies"]
    # SPDX carries the graph in `relationships`, not on the package. A parser that
    # ignores them reports a critical gap it manufactured itself.
    assert "SPDXRef-Package-commons-io" in depends_on
    # DEPENDENCY_OF states the same fact in the other direction, and producers
    # emit both, so both must fold into one graph.
    assert "SPDXRef-Package-log4j-core" in depends_on


@pytest.mark.parametrize("path", SPDX_JSON, ids=lambda p: p.name)
def test_noassertion_is_an_absence_not_a_value(path):
    """SPDX mandates NOASSERTION where a producer has no data."""
    result = ingest_document(json.loads(path.read_text()), lane="sbom")
    shim = next(e for e in result.entities if e["name"] == "internal-shim")

    assert shim["license_expr"] is None
    assert shim["supplier_raw"] is None


@pytest.mark.parametrize("path", SPDX_JSON, ids=lambda p: p.name)
def test_spdx_document_metadata_is_captured(path):
    result = ingest_document(json.loads(path.read_text()), lane="sbom")
    assert result.doc_author
    assert result.doc_timestamp == "2026-01-15T09:00:00Z"


def test_spdx_packages_are_rejected_with_a_reason_by_a_non_sbom_lane():
    """Never silently dropped: guideline v2.0 has no SPDX mapping for AIBOM."""
    payload = json.loads(SPDX_JSON[0].read_text())
    result = ingest_document(payload, lane="aibom")

    assert result.parsed_count == 0
    assert result.rejected_count == len(payload["packages"])
    assert all("no SPDX element mapping" in entry.reason for entry in result.rejected)


def test_a_package_without_a_name_is_rejected_not_dropped():
    document = {
        "spdxVersion": "SPDX-2.3",
        "creationInfo": {"created": "2026-01-15T09:00:00Z", "creators": ["Tool: x"]},
        "packages": [
            {"SPDXID": "SPDXRef-a", "name": "good", "versionInfo": "1.0"},
            {"SPDXID": "SPDXRef-b", "versionInfo": "2.0"},
            {"name": "no-id", "versionInfo": "3.0"},
        ],
    }
    result = spdxJson.parse(document, lane="sbom")

    assert result.parsed_count == 1
    assert result.rejected_count == 2
    reasons = " ".join(entry.reason for entry in result.rejected)
    assert "no name" in reasons
    assert "no SPDXID" in reasons


# --- SPDX tag-value ---------------------------------------------------------


@pytest.mark.parametrize("path", SPDX_TAG, ids=lambda p: p.name)
def test_tag_value_parses_multiline_text_blocks(path):
    result = ingest_document(path.read_text(), lane="sbom")
    entities = {entity["name"]: entity for entity in result.entities}
    assert "library, used by the sample" in entities["tomcat-catalina"]["description"]


@pytest.mark.parametrize("path", SPDX_TAG, ids=lambda p: p.name)
def test_tag_value_relationships_and_null_tokens(path):
    result = ingest_document(path.read_text(), lane="sbom")
    entities = {entity["name"]: entity for entity in result.entities}

    assert "SPDXRef-Package-commons-io" in entities["tomcat-catalina"]["dependencies"]
    assert entities["internal-shim"]["license_expr"] is None


def test_a_truncated_document_fails_loudly_naming_the_byte_offset():
    """The §S6 exit proof.

    Tag-value has no closing delimiter, so a file cut off mid-transfer stays
    syntactically valid — it simply contains fewer packages than were sent.
    Reporting "180 components" for a 400-component document scores as a complete
    assessment of an incomplete one.
    """
    truncated = (FIXTURES / "spdx" / "truncated-mid-text.spdx").read_text()

    with pytest.raises(TruncatedDocument) as raised:
        spdxTagValue.parse(truncated, lane="sbom")

    assert raised.value.offset > 0
    assert raised.value.line > 0
    assert str(raised.value.offset) in str(raised.value)
    assert "truncated" in str(raised.value)
    assert "refusing to score a partial document" in str(raised.value)


def test_the_truncation_offset_points_into_the_document():
    truncated = (FIXTURES / "spdx" / "truncated-mid-text.spdx").read_text()
    with pytest.raises(TruncatedDocument) as raised:
        spdxTagValue.parse(truncated, lane="sbom")

    assert raised.value.offset < len(truncated.encode())
    # The offset should land on the line that opened the unterminated <text>.
    line = truncated.encode()[raised.value.offset :].decode(errors="replace").splitlines()[0]
    assert "<text>" in line


# --- detection: explicit, never guessed -------------------------------------


def test_detection_reads_the_document_s_own_declaration():
    assert detect({"bomFormat": "CycloneDX", "specVersion": "1.6"}).format is Format.CYCLONEDX_JSON
    assert detect({"spdxVersion": "SPDX-2.3"}).format is Format.SPDX_JSON
    assert detect("SPDXVersion: SPDX-2.3\n").format is Format.SPDX_TAG_VALUE


def test_a_payload_that_is_neither_format_is_refused_citing_the_recommendation():
    """The §S6 exit proof."""
    with pytest.raises(UnrecognisedFormat, match="7.1.5"):
        detect({"components": [{"name": "looks-like-a-bom"}]})

    with pytest.raises(UnrecognisedFormat, match="7.1.5"):
        detect("just some text")

    with pytest.raises(UnrecognisedFormat, match="7.1.5"):
        detect([1, 2, 3])


def test_a_declaration_contradicted_by_the_document_is_refused():
    """Both sides are claims; disagreement means one is wrong."""
    with pytest.raises(FormatMismatch, match="disputed"):
        detect({"bomFormat": "CycloneDX", "specVersion": "1.6"}, declared="SPDX")


def test_a_matching_declaration_is_accepted():
    detection = detect({"bomFormat": "CycloneDX", "specVersion": "1.6"}, declared="CycloneDX")
    assert detection.spec_version == "1.6"


def test_detection_records_what_proved_it():
    """A rejection has to be able to say why."""
    assert "bomFormat" in detect({"bomFormat": "CycloneDX", "specVersion": "1.6"}).evidence
    assert "spdxVersion" in detect({"spdxVersion": "SPDX-2.3"}).evidence


def test_the_dispatcher_refuses_an_unreadable_document(tmp_path):
    with pytest.raises(UnrecognisedFormat):
        ingest_document({"not": "a bom"}, lane="sbom")


def test_supported_formats_is_advertised():
    formats = supported_formats()
    assert formats["CycloneDX"] == ["1.4", "1.5", "1.6"]
    assert formats["SPDX"] == ["SPDX-2.2", "SPDX-2.3"]
