"""Comments or Notes (s.4.2(15)) must be read from all three SBOM formats.

If the parsers did not extract it, every supplier would be reported as missing
4.2(15) however well they had annotated their components: a false negative against
the supplier.
"""

from __future__ import annotations

from app.services.catalogue.loader import get_catalogue
from app.services.ingest.parsers import cyclonedx, spdxJson, spdxTagValue


def test_cyclonedx_annotations_about_a_component_become_its_comment():
    document = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "version": 1,
        "metadata": {"timestamp": "2026-01-15T09:00:00Z"},
        "components": [
            {"type": "library", "bom-ref": "a@1", "name": "a", "version": "1"},
            {"type": "library", "bom-ref": "b@1", "name": "b", "version": "1"},
        ],
        "annotations": [
            {"subjects": ["a@1"], "text": "Patched locally for CVE-2025-0001."},
            {"subjects": ["a@1"], "text": "Included at the customer's request."},
        ],
    }
    entities = {e["name"]: e for e in cyclonedx.parse(document).entities}
    assert entities["a"]["comment"] == (
        "Patched locally for CVE-2025-0001. Included at the customer's request."
    )
    assert entities["b"]["comment"] is None


def test_spdx_json_package_comment_and_annotations_become_the_comment():
    document = {
        "spdxVersion": "SPDX-2.3",
        "SPDXID": "SPDXRef-DOCUMENT",
        "name": "doc",
        "dataLicense": "CC0-1.0",
        "documentNamespace": "https://example.test/doc",
        "creationInfo": {"created": "2026-01-15T09:00:00Z", "creators": ["Tool: t"]},
        "packages": [
            {"SPDXID": "SPDXRef-a", "name": "a", "versionInfo": "1", "comment": "Vendored copy."},
            {"SPDXID": "SPDXRef-b", "name": "b", "versionInfo": "1"},
        ],
        "annotations": [
            {"spdxElementId": "SPDXRef-b", "comment": "Reviewed 2026-01.", "annotator": "Person: x"}
        ],
    }
    entities = {e["name"]: e for e in spdxJson.parse(document).entities}
    assert entities["a"]["comment"] == "Vendored copy."
    assert entities["b"]["comment"] == "Reviewed 2026-01."


def test_spdx_tag_value_package_comment_becomes_the_comment():
    text = (
        "SPDXVersion: SPDX-2.3\nDataLicense: CC0-1.0\nSPDXID: SPDXRef-DOCUMENT\n"
        "DocumentName: doc\nDocumentNamespace: https://example.test/doc\n"
        "Creator: Tool: t\nCreated: 2026-01-15T09:00:00Z\n\n"
        "PackageName: a\nSPDXID: SPDXRef-a\nPackageVersion: 1\n"
        "PackageDownloadLocation: NOASSERTION\n"
        "PackageComment: <text>Vendored copy.</text>\n"
    )
    entities = spdxTagValue.parse(text).entities
    assert entities[0]["comment"] == "Vendored copy."


def test_a_component_with_a_comment_meets_4_2_15_and_one_without_does_not():
    element = get_catalogue("sbom").by_key("comments_notes")
    assert element.clause == "4.2(15)"
    assert element.probe({"name": "a", "comment": "A note."}) is True
    assert element.probe({"name": "a", "comment": None}) is False
