"""Every Table 8 and Table 9 element must be readable from a CycloneDX document.

A catalogue element that no parser fills would report every supplier absent on it however well they
had documented their assets. These tests build one fully documented asset of each type (and one
quantum system), check that every element reads present for the assets it governs, then strip the
new fields in turn and check that each reads absent.
"""

from __future__ import annotations

import copy

import pytest

from app.services.catalogue.loader import get_catalogue
from app.services.ingest.parsers import cyclonedx
from app.services.score.fieldCheck import check
from tests.conftest import cyclonedx_document

NEW_CBOM = {
    "algorithm_list": "algorithm",
    "key_name": "key",
    "key_asset_type": "key",
    "protocol_name": "protocol",
    "protocol_asset_type": "protocol",
    "protocol_oid": "protocol",
    "certificate_name": "certificate",
    "certificate_asset_type": "certificate",
    "cert_not_valid_before": "certificate",
    "cert_subject_public_key": "certificate",
    "cert_extension": "certificate",
}


def _assets() -> list[dict]:
    return [
        {
            "type": "cryptographic-asset", "bom-ref": "alg", "name": "AES-256-GCM",
            "cryptoProperties": {
                "assetType": "algorithm", "oid": "2.16.840.1.101.3.4.1.46",
                "algorithmProperties": {
                    "primitive": "ae", "mode": "gcm", "cryptoFunctions": ["encrypt"],
                    "classicalSecurityLevel": 256,
                },
            },
        },
        {
            "type": "cryptographic-asset", "bom-ref": "key", "name": "signing-key",
            "cryptoProperties": {
                "assetType": "related-crypto-material",
                "relatedCryptoMaterialProperties": {
                    "id": "k1", "state": "active", "size": 2048,
                    "creationDate": "2026-01-01", "activationDate": "2026-01-02",
                },
            },
        },
        {
            "type": "cryptographic-asset", "bom-ref": "tls", "name": "TLS",
            "cryptoProperties": {
                "assetType": "protocol", "oid": "1.3.6.1.5.5.7",
                "protocolProperties": {
                    "version": "1.3",
                    "cipherSuites": [{"name": "TLS_AES_256_GCM_SHA384"}],
                },
            },
        },
        {
            "type": "cryptographic-asset", "bom-ref": "cert", "name": "api-cert",
            "cryptoProperties": {
                "assetType": "certificate",
                "certificateProperties": {
                    "subjectName": "CN=api", "issuerName": "CN=ca",
                    "notValidBefore": "2026-01-01", "notValidAfter": "2027-01-01",
                    "signatureAlgorithmRef": "alg", "subjectPublicKeyRef": "key",
                    "certificateFormat": "X.509", "certificateFileExtension": "crt",
                },
            },
        },
    ]


def _entities(assets: list[dict]) -> list[dict]:
    return cyclonedx.parse(cyclonedx_document(assets), lane="cbom").entities


def test_every_cbom_element_reads_present_for_the_assets_it_governs():
    entities = _entities(_assets())
    for element in get_catalogue("cbom").elements:
        result = check(element, entities)
        assert result.coverage.total >= 1, f"{element.key} governs no asset in a full document"
        assert result.coverage.populated == result.coverage.total, (
            f"{element.key} reads absent on a documented asset"
        )


@pytest.mark.parametrize(
    "key", ["algorithm_list", "key_name", "protocol_name", "certificate_name"]
)
def test_a_name_row_reads_absent_for_an_asset_with_no_name(key):
    """The parser rejects a nameless component outright, so test the row's probe directly."""
    element = get_catalogue("cbom").by_key(key)
    asset_type = {"algorithm_list": "algorithm", "key_name": "key"}.get(key, key.split("_")[0])
    assert element.probe({"asset_type": asset_type, "name": "x"}) is True
    assert element.probe({"asset_type": asset_type, "name": None}) is False


STRIPPABLE = {"protocol_oid", "cert_not_valid_before", "cert_subject_public_key", "cert_extension"}


@pytest.mark.parametrize(
    ("key", "asset"), sorted((k, a) for k, a in NEW_CBOM.items() if k in STRIPPABLE)
)
def test_each_new_cbom_element_reads_absent_when_the_asset_does_not_declare_it(key, asset):
    """Strip exactly what this element reads and check it goes absent."""
    removes = {
        "protocol_oid": ("oid", None),
        "cert_not_valid_before": ("notValidBefore", "certificateProperties"),
        "cert_subject_public_key": ("subjectPublicKeyRef", "certificateProperties"),
        "cert_extension": ("certificateFileExtension", "certificateProperties"),
    }
    field, parent = removes[key]
    assets = copy.deepcopy(_assets())
    target = next(c for c in assets if c["cryptoProperties"]["assetType"] == asset)
    holder = target["cryptoProperties"][parent] if parent else target["cryptoProperties"]
    holder.pop(field)
    result = check(get_catalogue("cbom").by_key(key), _entities(assets))
    assert result.coverage.populated < result.coverage.total


def test_an_untyped_asset_is_a_gap_in_exactly_one_asset_type_row():
    assets = _assets() + [{"type": "cryptographic-asset", "bom-ref": "x", "name": "mystery"}]
    entities = _entities(assets)
    catalogue = get_catalogue("cbom")
    gaps = [
        element.key for element in catalogue.elements
        if element.key.endswith("asset_type")
        and check(element, entities).coverage.populated < check(element, entities).coverage.total
    ]
    assert gaps == ["algorithm_asset_type"]


def test_the_certificate_public_key_and_extension_are_read_from_the_certificate():
    certificate = next(e for e in _entities(_assets()) if e["name"] == "api-cert")
    assert certificate["subject_public_key"] == "key"
    assert certificate["certificate_extension"] == "crt"


def _quantum_system() -> dict:
    return {
        "type": "cryptographic-asset", "bom-ref": "qs", "name": "QPU-1", "version": "3.2",
        "supplier": {"name": "Quantum Co"},
        "licenses": [{"license": {"name": "Commercial"}}],
        "signature": {"algorithm": "ES256", "value": "abc"},
        "cryptoProperties": {"assetType": "algorithm"},
        "properties": [
            {"name": "certin:origin", "value": "IN"},
            {"name": "certin:communication_protocol", "value": "QKD"},
            {"name": "certin:hardware", "value": "superconducting qubits"},
            {"name": "certin:software_dependencies", "value": "qiskit"},
            {"name": "certin:environmental_impact", "value": "12 kW"},
        ],
    }


def _qbom_entity(system: dict, **document_fields) -> dict:
    document = cyclonedx_document([system])
    document["vulnerabilities"] = [{"id": "CVE-2026-1", "affects": [{"ref": "qs"}]}]
    document.update(document_fields)
    return cyclonedx.parse(document, lane="qbom").entities[0]


def test_every_qbom_element_reads_present_on_a_fully_documented_system():
    entity = _qbom_entity(_quantum_system())
    for element in get_catalogue("qbom").elements:
        assert element.probe(entity), f"{element.key} reads absent on a documented system"


@pytest.mark.parametrize(
    ("key", "strip"),
    [
        ("version", lambda s: s.pop("version")),
        ("license_info", lambda s: s.pop("licenses")),
        ("vulnerabilities", None),
        ("attestations", lambda s: s.pop("signature")),
        ("vendor_origin", lambda s: s.pop("supplier")),
        ("communication_protocol", lambda s: s.update(properties=[])),
    ],
)
def test_each_new_or_merged_qbom_element_reads_absent_when_undeclared(key, strip):
    system = _quantum_system()
    if strip is not None:
        strip(system)
    document = {}
    if key == "vulnerabilities":
        document["vulnerabilities"] = []
    entity = _qbom_entity(system, **document)
    assert not get_catalogue("qbom").by_key(key).probe(entity)


def test_vendor_and_origin_are_one_row_and_both_must_be_declared():
    system = _quantum_system()
    system["properties"] = [p for p in system["properties"] if p["name"] != "certin:origin"]
    assert not get_catalogue("qbom").by_key("vendor_origin").probe(_qbom_entity(system))
