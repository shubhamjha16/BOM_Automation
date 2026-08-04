"""Hardware firmware with no SBOM coverage. Activated in S16 with the HBOM lane.

§10.2.4 makes the HBOM-with-SBOM pairing explicit: a hardware item whose declared
firmware appears in no SBOM has an unassessed firmware supply chain. The rule is
written now so S16 is a lane implementation rather than a lane plus a rule, and
so its absence is visible in `GET /correlations` rather than silently missing.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import Any

from app.services.correlate.rules import Finding, Severity


def check(lanes: Mapping[str, Sequence[dict[str, Any]]]) -> list[Finding]:
    hardware = lanes.get("hbom") or []
    sbom = lanes.get("sbom") or []
    if not hardware or not sbom:
        return []

    covered = {str(entity.get("name") or "").strip().lower() for entity in sbom}
    uncovered: list[str] = []
    for item in hardware:
        firmware = item.get("firmware_version") or item.get("firmware")
        if not firmware:
            continue
        product = str(item.get("product_name") or item.get("name") or "").strip().lower()
        if product and product not in covered:
            uncovered.append(str(item.get("product_name") or item.get("name")))

    if not uncovered:
        return []
    return [
        Finding(
            rule_key="firmwareInHbom",
            severity=Severity.MEDIUM,
            clause="10.2.4",
            detail=(
                f"{len(uncovered)} hardware item(s) declare firmware with no "
                f"corresponding SBOM coverage ({', '.join(uncovered[:5])}). The "
                "firmware supply chain is unassessed."
            ),
            left_ref=uncovered[0],
        )
    ]
