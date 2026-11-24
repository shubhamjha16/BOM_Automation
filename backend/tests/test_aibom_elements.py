"""Each of Table 10's 19 elements must be readable from a CycloneDX model.

A new catalogue element that no parser fills would report every supplier absent on it
however well they had documented their model: a false negative against the supplier.
These tests build one fully documented model and check that every automatically
determined element reads as present, then strip each new element in turn and check that
it reads as absent.
"""

from __future__ import annotations

import pytest

from app.configs.jobTypes import Determinability
from app.services.catalogue.loader import get_catalogue
from app.services.ingest.parsers import cyclonedx
from tests.conftest import cyclonedx_document, model_component

NEW_ELEMENTS = (
    "ml_models_algorithms",
    "data_sets",
    "security_requirements",
    "environmental_impact",
    "vulnerabilities",
    "attestations",
)


def _documented_model() -> dict:
    model = model_component()
    model["modelCard"]["modelParameters"].update(
        {
            "architectureFamily": "transformer",
            "approach": {"type": "supervised"},
            "computeRequirements": "8 x A100",
        }
    )
    model["modelCard"]["considerations"]["environmentalConsiderations"] = {
        "energyConsumptions": [{"activity": "training", "energyProviders": []}]
    }
    model["properties"] = [
        {"name": "certin:security_requirements", "value": "AES-256 at rest; role-based access"}
    ]
    model["signature"] = {"algorithm": "ES256", "value": "abc123"}
    # The existing convention for a model's software dependencies (a list on the model).
    model["dependencies"] = ["torch", "transformers"]
    return model


def _parse(model: dict, **document_fields) -> dict:
    document = cyclonedx_document([model])
    document["vulnerabilities"] = document_fields.pop(
        "vulnerabilities",
        [{"id": "CVE-2026-0001", "affects": [{"ref": model["bom-ref"]}]}],
    )
    document.update(document_fields)
    return cyclonedx.parse(document, lane="aibom").entities[0]


def test_every_automatic_element_reads_present_on_a_fully_documented_model():
    entity = _parse(_documented_model())
    for element in get_catalogue("aibom").elements:
        if element.determinability is Determinability.AUTO:
            assert element.probe(entity), f"{element.key} reads absent on a documented model"


@pytest.mark.parametrize(
    ("key", "strip"),
    [
        ("ml_models_algorithms", lambda m: m["modelCard"]["modelParameters"].update(
            {"architectureFamily": None, "modelArchitecture": None, "approach": None})),
        ("data_sets", lambda m: m["modelCard"]["modelParameters"].update({"datasets": []})),
        ("security_requirements", lambda m: m.update({"properties": []})),
        ("environmental_impact", lambda m: m["modelCard"]["considerations"].pop(
            "environmentalConsiderations")),
        ("attestations", lambda m: m.pop("signature")),
    ],
)
def test_each_new_element_reads_absent_when_the_model_does_not_declare_it(key, strip):
    model = _documented_model()
    strip(model)
    entity = _parse(model)
    assert not get_catalogue("aibom").by_key(key).probe(entity)


def test_vulnerabilities_are_read_only_for_the_model_they_affect():
    model = _documented_model()
    elsewhere = [{"id": "CVE-2026-0002", "affects": [{"ref": "other@1"}]}]
    other = _parse(model, vulnerabilities=elsewhere)
    assert not get_catalogue("aibom").by_key("vulnerabilities").probe(other)
    own = _parse(model)
    assert own["vulnerabilities"] == ["CVE-2026-0001"]


def test_a_signature_on_the_whole_document_counts_for_the_model():
    model = _documented_model()
    model.pop("signature")
    entity = _parse(model, signature={"algorithm": "ES256", "value": "doc-signature"})
    assert get_catalogue("aibom").by_key("attestations").probe(entity)


def test_the_three_old_extras_are_gone():
    keys = {element.key for element in get_catalogue("aibom").elements}
    assert not keys & {"data_preprocessing", "evaluation_results", "known_limitations"}
    assert set(NEW_ELEMENTS) <= keys and len(keys) == 19
