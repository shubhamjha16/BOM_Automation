"""The catalogue must equal the CERT-In guideline, element for element.

``fixtures/certin_v2_elements.json`` lists every minimum element in the order the
published guideline gives them (CERT-In Technical Guidelines on SBOM, QBOM & CBOM,
AIBOM and HBOM, v2.0, 09.07.2025), read from the PDF's tables and checked against
page images. A lane is listed in ``ALIGNED`` once its catalogue matches; the rest
are strict xfails, so the remaining work is visible and fixing a lane forces it to
move here (a strict xfail that starts passing fails the build).
"""

from __future__ import annotations

import json
from pathlib import Path

from app.services.catalogue.loader import get_catalogue

FIXTURE = json.loads((Path(__file__).parent / "fixtures" / "certin_v2_elements.json").read_text())

#: Lanes whose catalogue has been brought into line with the guideline.
ALIGNED = {"sbom", "aibom", "hbom", "qbom", "cbom"}

#: The guideline's name for each s.4.2 field -> the catalogue key that encodes it.
SBOM_KEY_FOR_NAME = {
    "Component Name": "component_name",
    "Component Version": "version",
    "Component Description": "description",
    "Component Supplier": "supplier_name",
    "Component License": "license",
    "Component Origin": "origin",
    "Component Dependencies": "dependencies",
    "Vulnerabilities": "vulnerabilities",
    "Patch Status": "patch_status",
    "Release Date": "release_date",
    "End-of-Life (EOL) Date": "end_of_life",
    "Criticality": "criticality",
    "Usage Restrictions": "usage_restrictions",
    "Checksums or Hashes": "checksums",
    "Comments or Notes": "comments_notes",
    "Author of SBOM Data": "author_name",
    "Timestamp": "timestamp",
    "Executable Property": "executable_property",
    "Archive Property": "archive_property",
    "Structured Property": "structured_property",
    "Unique Identifier": "certin_identifier",
}

#: The guideline's name for each Table 10 row -> the catalogue key that encodes it.
AIBOM_KEY_FOR_NAME = {
    "Model Name": "model_name",
    "Model Version": "model_version",
    "Model Type": "model_type",
    "Model Developer": "developer",
    "Model Licensing Information": "license",
    "Software Dependencies": "software_dependencies",
    "ML Models and Algorithms": "ml_models_algorithms",
    "Model Performance Metrics": "performance_metrics",
    "Data Source": "training_data_source",
    "Data Sets": "data_sets",
    "Hardware": "hardware_requirements",
    "Security Requirements": "security_requirements",
    "Input": "model_inputs",
    "Output": "model_outputs",
    "Intended Usage": "intended_usage",
    "Out of Scope Usage": "out_of_scope_usage",
    "Environmental Impact": "environmental_impact",
    "Vulnerabilities": "vulnerabilities",
    "Attestations": "attestations",
}

#: Table 8's rows in order -> the catalogue key that encodes each.
QBOM_KEYS_IN_ORDER = [
    "model_name",
    "version",
    "vendor_origin",
    "license_info",
    "cryptographic_asset",
    "communication_protocol",
    "hardware",
    "software_dependencies",
    "environmental_impact",
    "vulnerabilities",
    "attestations",
]

#: Table 9's rows in order, grouped by asset type -> the catalogue key that encodes each.
CBOM_KEYS_IN_ORDER = [
    "algorithm_name",
    "algorithm_asset_type",
    "primitive",
    "mode",
    "crypto_functions",
    "classical_security_level",
    "oid",
    "algorithm_list",
    "key_name",
    "key_asset_type",
    "key_id",
    "key_state",
    "key_size",
    "key_creation_date",
    "key_activation_date",
    "protocol_name",
    "protocol_asset_type",
    "protocol_version",
    "cipher_suites",
    "protocol_oid",
    "certificate_name",
    "certificate_asset_type",
    "cert_subject",
    "cert_issuer",
    "cert_not_valid_before",
    "cert_not_valid_after",
    "cert_signature_algorithm",
    "cert_subject_public_key",
    "cert_format",
    "cert_extension",
]

#: Table 11's rows in order -> the catalogue key that encodes each. "Supplier Information"
#: and "Supplier Location" occur twice (product, then component), so they are keyed by group.
HBOM_KEYS_IN_ORDER = [
    "product_name",
    "product_version",
    "product_details",
    "warranty_ref",
    "manufacturer",
    "manufacturing_location",
    "manufacturing_date",
    "supplier_name",
    "supplier_location",
    "model_number",
    "serial_number",
    "technical_specification",
    "component_supplier",
    "component_supplier_location",
    "technology_node",
    "compliance_declarations",
    "power_supply",
    "license_info",
    "test_results",
    "subcomponents",
]


def test_the_fixture_holds_the_guidelines_101_rows():
    counts = {lane: len(data["elements"]) for lane, data in FIXTURE["lanes"].items()}
    assert counts == {"sbom": 21, "qbom": 11, "cbom": 30, "aibom": 19, "hbom": 20}


def test_sbom_matches_the_guideline_in_order_and_numbering():
    expected = [SBOM_KEY_FOR_NAME[row["name"]] for row in FIXTURE["lanes"]["sbom"]["elements"]]
    catalogue = get_catalogue("sbom")
    assert [element.key for element in catalogue.elements] == expected
    # s.4.2 numbers its fields 1-21, and the catalogue cites that number.
    assert [element.clause for element in catalogue.elements] == [
        f"4.2({position})" for position in range(1, len(expected) + 1)
    ]


def test_aibom_matches_table_10_in_order_and_cites_by_name():
    expected = [AIBOM_KEY_FOR_NAME[row["name"]] for row in FIXTURE["lanes"]["aibom"]["elements"]]
    catalogue = get_catalogue("aibom")
    assert [element.key for element in catalogue.elements] == expected
    # Table 10 numbers nothing, so each element is cited by section, table and name.
    assert [element.clause for element in catalogue.elements] == [
        f"9.3 Table 10: {row['name']}" for row in FIXTURE["lanes"]["aibom"]["elements"]
    ]
    assert catalogue.clause_root == FIXTURE["lanes"]["aibom"]["section"]


def test_hbom_matches_table_11_in_order_and_cites_by_name():
    rows = FIXTURE["lanes"]["hbom"]["elements"]
    catalogue = get_catalogue("hbom")
    assert [element.key for element in catalogue.elements] == HBOM_KEYS_IN_ORDER
    # Table 11 numbers nothing, so each element is cited by section, table and name; the two
    # names the table uses twice carry the group that tells them apart.
    names = [row["name"] for row in rows]
    expected = [
        f"10.3 Table 11: {row['group']} - {row['name']}"
        if names.count(row["name"]) > 1
        else f"10.3 Table 11: {row['name']}"
        for row in rows
    ]
    assert [element.clause for element in catalogue.elements] == expected
    assert len(set(expected)) == len(expected)
    assert catalogue.clause_root == FIXTURE["lanes"]["hbom"]["section"]


def test_qbom_matches_table_8_in_order_and_cites_by_name():
    rows = FIXTURE["lanes"]["qbom"]["elements"]
    catalogue = get_catalogue("qbom")
    assert [element.key for element in catalogue.elements] == QBOM_KEYS_IN_ORDER
    assert [element.clause for element in catalogue.elements] == [
        f"8.3 Table 8: {row['name']}" for row in rows
    ]
    assert catalogue.clause_root == FIXTURE["lanes"]["qbom"]["section"]


def test_cbom_matches_table_9_in_order_and_cites_by_group_and_name():
    rows = FIXTURE["lanes"]["cbom"]["elements"]
    catalogue = get_catalogue("cbom")
    assert [element.key for element in catalogue.elements] == CBOM_KEYS_IN_ORDER
    # Name, Asset Type and OID recur in several groups, so every citation carries its group.
    expected = [f"8.3 Table 9: {row['group']} - {row['name']}" for row in rows]
    assert [element.clause for element in catalogue.elements] == expected
    assert len(set(expected)) == len(expected)
    assert catalogue.clause_root == FIXTURE["lanes"]["cbom"]["section"]


def test_every_lane_in_the_fixture_is_aligned():
    assert ALIGNED == set(FIXTURE["lanes"])
