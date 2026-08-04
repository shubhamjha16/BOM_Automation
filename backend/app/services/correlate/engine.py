"""The correlation registry and the runner.

**One rule governs all of this: a rule whose inputs are not present does not
fire.** A submission carrying only an SBOM has not failed to declare its
cryptography — it was never asked to. Firing anyway would manufacture findings
about documents nobody submitted, which is the correlation equivalent of scoring
an empty component list as compliant.

So a rule declares the lanes whose *content* it reads, and the runner skips it
unless every one of them carried entities. The skips are reported rather than
silent, because "this rule did not run" and "this rule found nothing" are
different answers and a reader is entitled to know which they are looking at.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Any

from app.services.correlate import (
    cryptoInSbom,
    firmwareInHbom,
    modelDepsInSbom,
    quantumExposure,
    vexCoverage,
)
from app.services.correlate.rules import Finding, Rule, Severity
from app.utils.logger import get_logger

logger = get_logger(__name__)

RULES: tuple[Rule, ...] = (
    Rule(
        key="cryptoInSbom",
        label="Cryptographic libraries undeclared in a CBOM",
        clause="8.4.1.2",
        severity=Severity.HIGH,
        requires=("sbom",),
        body=cryptoInSbom.check,
        rationale=(
            "A supplier shipping OpenSSL and declaring no cryptographic assets has "
            "not declared their cryptography. The SBOM proves a CBOM should exist."
        ),
    ),
    Rule(
        key="modelDepsInSbom",
        label="AIBOM dependencies absent from the SBOM",
        clause="9.3(6)",
        severity=Severity.HIGH,
        requires=("aibom", "sbom"),
        body=modelDepsInSbom.check,
        rationale=(
            "The SBOM is internally consistent; only the AIBOM knows what it is "
            "missing. No amount of SBOM scoring could produce this finding."
        ),
    ),
    Rule(
        key="algorithmQuantumExposure",
        label="Quantum-vulnerable cryptography with no migration path",
        clause="8.5.1",
        severity=Severity.HIGH,
        requires=("cbom",),
        body=quantumExposure.check,
        rationale=(
            "The CBOM records what is in use; the absent QBOM entry only becomes "
            "meaningful once you know what needs migrating."
        ),
    ),
    Rule(
        key="firmwareInHbom",
        label="Hardware firmware with no SBOM coverage",
        clause="10.2.4",
        severity=Severity.MEDIUM,
        requires=("hbom", "sbom"),
        body=firmwareInHbom.check,
        rationale="§10.2.4 makes the HBOM-with-SBOM pairing explicit.",
    ),
    Rule(
        key="vexCoverage",
        label="KEV-listed vulnerability with no VEX statement",
        clause="7.1.6",
        severity=Severity.CRITICAL,
        requires=("sbom",),
        body=vexCoverage.check,
        rationale="Recommendation 7.1.6 makes VEX the perpetual obligation.",
        implemented=False,  # needs enrichment (S10) and the VEX store (S12)
    ),
)


@dataclass(frozen=True, slots=True)
class CorrelationReport:
    findings: list[Finding]
    #: Rules that ran. Distinguishes "found nothing" from "did not run".
    evaluated: list[str]
    #: Rule key → why it was skipped.
    skipped: dict[str, str]

    @property
    def is_clean(self) -> bool:
        return not self.findings


def correlate(lane_entities: Mapping[str, Sequence[dict[str, Any]]]) -> CorrelationReport:
    """Run every applicable rule over the lanes that carried content."""
    available = {lane for lane, entities in lane_entities.items() if entities}

    findings: list[Finding] = []
    evaluated: list[str] = []
    skipped: dict[str, str] = {}

    for rule in RULES:
        if not rule.implemented:
            skipped[rule.key] = "not yet implemented; the lane it reads does not exist"
            continue
        missing = set(rule.requires) - available
        if missing:
            # The §11 rule: correlation with nothing to correlate against is
            # invention, not a finding.
            skipped[rule.key] = (
                f"no content in lane(s) {sorted(missing)}; nothing to correlate against"
            )
            continue

        evaluated.append(rule.key)
        findings.extend(rule.body(dict(lane_entities)))

    logger.info(
        "correlated",
        available=sorted(available),
        evaluated=evaluated,
        findings=[finding.rule_key for finding in findings],
        skipped=len(skipped),
    )
    return CorrelationReport(findings=findings, evaluated=evaluated, skipped=skipped)


def rule_catalogue() -> list[dict[str, Any]]:
    """The rules, inspectable — as the minimum elements are."""
    return [
        {
            "key": rule.key,
            "label": rule.label,
            "clause": rule.clause,
            "severity": str(rule.severity),
            "requires": list(rule.requires),
            "implemented": rule.implemented,
            "rationale": rule.rationale,
        }
        for rule in RULES
    ]
