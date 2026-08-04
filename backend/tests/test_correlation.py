"""S9: cross-BOM correlation — the findings no single-lane tool can produce.

The rule that matters most is the negative one, and it is asserted first: **a
single-lane submission produces zero correlation findings rather than false
positives.** Correlation with nothing to correlate against is invention.
"""

from __future__ import annotations

import pytest

from app.services.assessmentService import run_assessment
from app.services.correlate.engine import RULES, correlate, rule_catalogue
from app.services.correlate.rules import Severity
from app.services.graph.state import SubmissionDocument
from app.validators.conformanceValidator import Citation, assert_all_traceable
from tests.conftest import component, cyclonedx_document, model_component


def _sbom(*names: str) -> list[dict]:
    return [{"name": name, "purl": f"pkg:generic/{name}@1.0"} for name in names]


# --- the negative rule, first -----------------------------------------------


def test_a_single_lane_submission_produces_zero_findings():
    """The §S9 exit proof. A client with only an SBOM has not failed to declare
    their cryptography — they were never asked to."""
    report = correlate({"sbom": _sbom("express", "lodash", "react")})
    assert report.findings == []
    assert report.is_clean


def test_a_rule_whose_lanes_are_absent_is_skipped_not_silently_passed():
    """"Did not run" and "found nothing" are different answers."""
    report = correlate({"sbom": _sbom("express")})

    assert "modelDepsInSbom" in report.skipped
    assert "aibom" in report.skipped["modelDepsInSbom"]
    assert "modelDepsInSbom" not in report.evaluated


def test_an_empty_submission_correlates_nothing():
    report = correlate({})
    assert report.findings == []
    assert report.evaluated == []


async def test_a_single_lane_assessment_end_to_end_has_no_findings():
    summary = await run_assessment(
        org_id="org",
        submission_id="sub",
        documents=[
            SubmissionDocument(
                lane="sbom",
                format="CycloneDX",
                payload=cyclonedx_document([component("express", "4.18.0")]),
            )
        ],
        requested_lanes=["sbom"],
    )
    assert summary.correlation_findings == []


# --- cryptoInSbom -----------------------------------------------------------


def test_openssl_in_the_sbom_with_no_cbom_raises_crypto_in_sbom():
    """The §S9 exit proof, citing s.8.4.1.2."""
    report = correlate({"sbom": _sbom("openssl", "express")})

    assert len(report.findings) == 1
    finding = report.findings[0]
    assert finding.rule_key == "cryptoInSbom"
    assert finding.clause == "8.4.1.2"
    assert finding.severity is Severity.HIGH
    assert "OpenSSL" in finding.detail
    assert "undeclared" in finding.detail


@pytest.mark.parametrize(
    "name", ["openssl", "libssl3", "libcrypto1.1", "bcprov-jdk18on", "libsodium", "wolfssl"]
)
def test_crypto_libraries_are_matched_across_real_naming_variants(name):
    """Supplier naming varies; a whole-string match would miss most real BOMs."""
    report = correlate({"sbom": _sbom(name)})
    assert [finding.rule_key for finding in report.findings] == ["cryptoInSbom"]


def test_a_submission_with_no_crypto_libraries_raises_nothing():
    report = correlate({"sbom": _sbom("express", "lodash", "react", "moment")})
    assert report.findings == []


def test_a_cbom_that_carried_assets_suppresses_the_finding():
    """Whether the CBOM covers *these* libraries is a CBOM-lane scoring question
    (S14), not a correlation one."""
    report = correlate(
        {
            "sbom": _sbom("openssl"),
            "cbom": [{"name": "RSA-2048", "primitive": "signature", "asset_type": "algorithm"}],
        }
    )
    assert "cryptoInSbom" not in [finding.rule_key for finding in report.findings]


async def test_crypto_in_sbom_appears_in_a_real_assessment():
    summary = await run_assessment(
        org_id="org",
        submission_id="sub",
        documents=[
            SubmissionDocument(
                lane="sbom",
                format="CycloneDX",
                payload=cyclonedx_document(
                    [component("openssl", "3.0.0"), component("express", "4.18.0")]
                ),
            )
        ],
        requested_lanes=["sbom"],
    )
    findings = {finding.rule_key: finding for finding in summary.correlation_findings}
    assert "cryptoInSbom" in findings
    assert findings["cryptoInSbom"].clause == "8.4.1.2"


# --- modelDepsInSbom --------------------------------------------------------


def test_aibom_dependencies_absent_from_the_sbom_raise_a_finding():
    """The §S9 exit proof, citing s.9.3(6): the SBOM is incomplete."""
    report = correlate(
        {
            "sbom": _sbom("numpy", "requests"),
            "aibom": [
                {
                    "model_name": "classifier",
                    "software_dependencies": ["torch", "transformers", "numpy"],
                }
            ],
        }
    )
    findings = {finding.rule_key: finding for finding in report.findings}

    assert "modelDepsInSbom" in findings
    assert findings["modelDepsInSbom"].clause == "9.3(6)"
    assert "torch" in findings["modelDepsInSbom"].detail
    assert "transformers" in findings["modelDepsInSbom"].detail
    # numpy is present in the SBOM, so it is not reported.
    assert "numpy" not in findings["modelDepsInSbom"].detail


def test_dependencies_all_present_raise_nothing():
    report = correlate(
        {
            "sbom": _sbom("torch", "transformers"),
            "aibom": [{"model_name": "m", "software_dependencies": ["torch", "transformers"]}],
        }
    )
    assert "modelDepsInSbom" not in [finding.rule_key for finding in report.findings]


def test_a_version_suffix_does_not_create_a_false_absence():
    """A version mismatch is a separate finding from an absence."""
    report = correlate(
        {
            "sbom": _sbom("torch"),
            "aibom": [{"model_name": "m", "software_dependencies": ["torch@2.1.0"]}],
        }
    )
    assert "modelDepsInSbom" not in [finding.rule_key for finding in report.findings]


def test_a_purl_named_component_counts_as_present():
    report = correlate(
        {
            "sbom": [{"name": "torch", "purl": "pkg:pypi/torch@2.1.0"}],
            "aibom": [{"model_name": "m", "software_dependencies": ["torch"]}],
        }
    )
    assert report.findings == []


def test_an_aibom_declaring_no_dependencies_raises_nothing_here():
    """That is a 9.3(6) field verdict, not a correlation finding."""
    report = correlate({"sbom": _sbom("numpy"), "aibom": [{"model_name": "m"}]})
    assert "modelDepsInSbom" not in [finding.rule_key for finding in report.findings]


async def test_model_deps_in_sbom_appears_in_a_real_two_lane_assessment():
    model = model_component()
    model["dependencies"] = ["torch", "transformers"]
    summary = await run_assessment(
        org_id="org",
        submission_id="sub",
        documents=[
            SubmissionDocument(
                lane="sbom",
                format="CycloneDX",
                payload=cyclonedx_document([component("numpy", "1.26.0")]),
            ),
            SubmissionDocument(
                lane="aibom", format="CycloneDX", payload=cyclonedx_document([model])
            ),
        ],
        requested_lanes=["sbom", "aibom"],
    )
    findings = {finding.rule_key for finding in summary.correlation_findings}
    assert "modelDepsInSbom" in findings


# --- algorithmQuantumExposure -----------------------------------------------


def test_rsa_with_no_migration_entry_raises_quantum_exposure():
    """The §S9 exit proof, citing s.8.5.1."""
    report = correlate(
        {"cbom": [{"name": "RSA-2048", "primitive": "signature", "asset_type": "algorithm"}]}
    )
    findings = {finding.rule_key: finding for finding in report.findings}

    assert "algorithmQuantumExposure" in findings
    assert findings["algorithmQuantumExposure"].clause == "8.5.1"
    assert "RSA" in findings["algorithmQuantumExposure"].detail


@pytest.mark.parametrize(
    ("name", "family"),
    [
        ("RSA-4096", "RSA"),
        ("ECDSA-P256", "ECDSA"),
        ("ecdh-secp384r1", "ECDH"),
        ("DSA-2048", "DSA"),
        ("diffie-hellman-group14", "Diffie-Hellman"),
    ],
)
def test_every_vulnerable_family_named_in_s851_is_detected(name, family):
    report = correlate({"cbom": [{"name": name, "asset_type": "algorithm"}]})
    assert [finding.rule_key for finding in report.findings] == ["algorithmQuantumExposure"]
    assert family in report.findings[0].detail


def test_a_declared_pqc_migration_path_suppresses_the_finding():
    report = correlate(
        {
            "cbom": [{"name": "RSA-2048", "asset_type": "algorithm"}],
            "qbom": [{"name": "ML-KEM-768", "asset_type": "algorithm"}],
        }
    )
    assert report.findings == []


def test_post_quantum_only_cryptography_raises_nothing():
    report = correlate({"cbom": [{"name": "ML-DSA-65", "asset_type": "algorithm"}]})
    assert report.findings == []


def test_symmetric_cryptography_is_not_quantum_exposed_under_s851():
    """s.8.5.1 names public-key systems; AES is not one of them."""
    report = correlate({"cbom": [{"name": "AES-256-GCM", "asset_type": "algorithm"}]})
    assert report.findings == []


# --- rules pending their lanes ----------------------------------------------


def test_unimplemented_rules_are_reported_as_pending_not_omitted():
    """Their absence is visible rather than silently missing.

    firmwareInHbom activated with the HBOM lane at S16; vexCoverage still waits
    for the enrichment feeds (S10) and the VEX store (S12) to populate the KEV
    and statement data it reads.
    """
    report = correlate({"sbom": _sbom("express")})

    assert "vexCoverage" in report.skipped
    assert "not yet implemented" in report.skipped["vexCoverage"]


def test_firmware_in_hbom_is_now_live():
    report = correlate(
        {
            "sbom": _sbom("express"),
            "hbom": [{"product_name": "router", "firmware_version": "1.0"}],
        }
    )
    assert "firmwareInHbom" in report.evaluated
    assert [item.rule_key for item in report.findings] == ["firmwareInHbom"]


def test_the_rule_catalogue_is_inspectable():
    """The rules are readable, as the minimum elements are."""
    catalogue = rule_catalogue()
    assert len(catalogue) == len(RULES)

    by_key = {rule["key"]: rule for rule in catalogue}
    assert by_key["cryptoInSbom"]["clause"] == "8.4.1.2"
    assert by_key["modelDepsInSbom"]["clause"] == "9.3(6)"
    assert by_key["algorithmQuantumExposure"]["clause"] == "8.5.1"
    assert by_key["firmwareInHbom"]["implemented"] is True
    assert by_key["vexCoverage"]["implemented"] is False
    assert all(rule["rationale"] for rule in catalogue)


# --- findings pass the same gate as field verdicts --------------------------


def test_every_rule_cites_a_clause_the_gate_accepts():
    """Otherwise the one class of finding no single-lane tool can produce would
    be the one class nobody verified."""
    citations = [
        Citation(clause=rule.clause, lane=None, source=f"correlation.{rule.key}")
        for rule in RULES
    ]
    assert_all_traceable(citations)


def test_findings_carry_a_reference_a_reader_can_check():
    report = correlate({"sbom": _sbom("openssl")})
    assert report.findings[0].left_ref
