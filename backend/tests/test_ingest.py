"""Ingestion integrity: nothing is dropped silently, nothing empty is green.

The full format matrix — Syft, Trivy and cdxgen across CycloneDX 1.4/1.5/1.6 and
SPDX 2.2/2.3 — lands in S6. The two invariants are asserted from S1 because every
parser written afterwards has to satisfy them.
"""

from __future__ import annotations

import pytest

from app.services.ingest.parsers import cyclonedx, spdxJson
from app.services.ingest.parsers.cyclonedx import UnrecognisedDocument
from tests.conftest import component, cyclonedx_document, model_component


def test_parsed_plus_rejected_equals_the_input_entry_count():
    """The S6 contract, asserted from S1."""
    payload = cyclonedx_document(
        [component("a"), {"type": "library"}, "not-an-object", component("b")]
    )
    result = cyclonedx.parse(payload, lane="sbom")

    assert len(result.entities) == 2
    assert len(result.rejected) == 2
    result.assert_conserved(4)


def test_every_rejection_carries_an_actionable_reason():
    payload = cyclonedx_document([{"type": "library", "version": "1.0"}, "junk"])
    result = cyclonedx.parse(payload, lane="sbom")

    reasons = [entry.reason for entry in result.rejected]
    assert any("component has no name" in reason for reason in reasons)
    assert "entry is not an object" in reasons
    assert all(entry.reason for entry in result.rejected)


def test_conservation_violation_is_loud():
    result = cyclonedx.parse(cyclonedx_document([component("a")]), lane="sbom")
    with pytest.raises(AssertionError, match="entry conservation violated"):
        result.assert_conserved(99)


def test_a_non_cyclonedx_payload_raises_rather_than_returning_nothing():
    """An empty component list renders a green assessment."""
    with pytest.raises(UnrecognisedDocument, match="rec. 7.1.5"):
        cyclonedx.parse({"spdxVersion": "SPDX-2.3", "packages": []}, lane="sbom")


def test_an_unsupported_spec_version_raises():
    with pytest.raises(UnrecognisedDocument, match="specVersion"):
        cyclonedx.parse(cyclonedx_document([], spec_version="1.2"), lane="sbom")


@pytest.mark.parametrize("spec_version", ["1.4", "1.5", "1.6"])
def test_supported_spec_versions_parse(spec_version):
    result = cyclonedx.parse(
        cyclonedx_document([component("a")], spec_version=spec_version), lane="sbom"
    )
    assert result.spec_version == spec_version
    assert len(result.entities) == 1


def test_an_unsupported_spdx_version_raises():
    """Never a silent empty result for a format we cannot read."""
    from app.services.ingest.parsers.spdxJson import UnsupportedSpdxVersion

    with pytest.raises(UnsupportedSpdxVersion, match="SPDX-1.2"):
        spdxJson.parse({"spdxVersion": "SPDX-1.2", "packages": []}, lane="sbom")


def test_licence_expressions_are_flattened():
    payload = cyclonedx_document([component("a", licence="Apache-2.0")])
    entity = cyclonedx.parse(payload, lane="sbom").entities[0]
    assert entity["license_expr"] == "Apache-2.0"


def test_dependency_graph_is_attached_to_its_component():
    payload = cyclonedx_document([component("a"), component("b")])
    payload["dependencies"] = [{"ref": "a@1.0.0", "dependsOn": ["b@1.0.0"]}]
    entities = {e["name"]: e for e in cyclonedx.parse(payload, lane="sbom").entities}
    assert entities["a"]["dependencies"] == ["b@1.0.0"]
    assert entities["b"]["dependencies"] == []


def test_document_metadata_is_captured():
    result = cyclonedx.parse(cyclonedx_document([component("a")]), lane="sbom")
    assert result.doc_author == "Test Supplier Ltd"
    assert result.doc_timestamp == "2026-01-15T09:00:00Z"


def test_model_components_normalise_to_the_aibom_shape():
    result = cyclonedx.parse(cyclonedx_document([model_component()]), lane="aibom")
    entity = result.entities[0]
    assert entity["model_name"] == "claude-sonnet-4-5"
    assert entity["developer"] == "Anthropic"
    assert entity["model_type"] == "transformer"
    # 9.3(15)-(16) are governance declarations; no artifact carries them.
    assert entity["intended_usage"] is None
    assert entity["out_of_scope_usage"] is None


def test_a_lane_rejects_the_other_lanes_entities_with_a_reason():
    payload = cyclonedx_document([component("numpy"), model_component()])
    sbom_result = cyclonedx.parse(payload, lane="sbom")

    assert len(sbom_result.entities) == 1
    assert "not scored by the sbom lane" in sbom_result.rejected[0].reason
    sbom_result.assert_conserved(2)
