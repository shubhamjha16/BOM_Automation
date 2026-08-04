"""KEV-listed vulnerabilities with no VEX statement. Activated in S12.

Recommendation 7.1.6 makes VEX the perpetual obligation once a BOM is issued. A
component carrying a CISA KEV-listed CVE and no VEX statement means nobody has
said whether the product is affected — which is the question the whole VEX
lifecycle exists to answer.

Needs the enrichment feeds (S10) to know which CVEs are KEV-listed and the VEX
store (S12) to know what has been stated. Declared now so it is visibly pending
rather than absent.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import Any

from app.services.correlate.rules import Finding, Severity


def check(lanes: Mapping[str, Sequence[dict[str, Any]]]) -> list[Finding]:
    sbom = lanes.get("sbom") or []
    if not sbom:
        return []

    uncovered: list[str] = []
    for entity in sbom:
        kev = entity.get("kev_cves") or []
        if kev and not entity.get("vex_statements"):
            uncovered.append(str(entity.get("name")))

    if not uncovered:
        return []
    return [
        Finding(
            rule_key="vexCoverage",
            severity=Severity.CRITICAL,
            clause="7.1.6",
            detail=(
                f"{len(uncovered)} component(s) carry a CISA KEV-listed "
                f"vulnerability with no VEX statement ({', '.join(uncovered[:5])}). "
                "Recommendation 7.1.6 requires a determination for each."
            ),
            left_ref=uncovered[0],
        )
    ]
