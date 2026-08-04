"""AIBOM software dependencies that are absent from the SBOM.

s.9.3(6) requires an AIBOM to declare the model's software dependencies. If a
dependency is declared there and does not appear in the SBOM, **the SBOM is
incomplete** — and that is a finding about the SBOM which no amount of SBOM
scoring could produce, because the SBOM is internally consistent. Only the other
document knows what is missing.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import Any

from app.services.correlate.rules import Finding, Severity


def _declared_dependencies(models: Sequence[dict[str, Any]]) -> set[str]:
    names: set[str] = set()
    for model in models:
        raw = model.get("software_dependencies")
        if isinstance(raw, str):
            candidates: list[Any] = [raw]
        elif isinstance(raw, (list, tuple)):
            candidates = list(raw)
        elif isinstance(raw, dict):
            candidates = list(raw.values())
        else:
            continue
        for candidate in candidates:
            if isinstance(candidate, dict):
                candidate = candidate.get("name") or candidate.get("ref")
            if candidate:
                # Strip any version suffix: the SBOM may carry a different one,
                # and a version mismatch is a separate finding from an absence.
                names.add(str(candidate).split("@")[0].strip().lower())
    return {name for name in names if name}


def check(lanes: Mapping[str, Sequence[dict[str, Any]]]) -> list[Finding]:
    models = lanes.get("aibom") or []
    sbom = lanes.get("sbom") or []
    if not models or not sbom:
        return []

    declared = _declared_dependencies(models)
    if not declared:
        return []

    present = {
        str(entity.get("name") or "").strip().lower()
        for entity in sbom
        if entity.get("name")
    }
    # Also accept a PURL name match, since an SBOM may name a package by purl.
    for entity in sbom:
        purl = str(entity.get("purl") or "")
        if "/" in purl:
            present.add(purl.rsplit("/", 1)[-1].split("@")[0].strip().lower())

    missing = sorted(declared - present)
    if not missing:
        return []

    return [
        Finding(
            rule_key="modelDepsInSbom",
            severity=Severity.HIGH,
            clause="9.3(6)",
            detail=(
                f"the AIBOM declares {len(missing)} software dependenc"
                f"{'y' if len(missing) == 1 else 'ies'} absent from the SBOM "
                f"({', '.join(missing[:8])}"
                f"{', …' if len(missing) > 8 else ''}). The SBOM is incomplete: a "
                "component the model depends on is not covered by any component "
                "record, so it is unassessed for licence, vulnerability and "
                "lifecycle obligations."
            ),
            left_ref=missing[0],
            right_ref=None,
        )
    ]
