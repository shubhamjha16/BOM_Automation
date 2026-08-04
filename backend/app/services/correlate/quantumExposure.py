"""Public-key cryptography with no declared post-quantum migration path.

s.8.5.1 names RSA, ECC, Diffie-Hellman and DSA as the systems a quantum-capable
adversary breaks. A CBOM that declares them and a QBOM that declares no migration
entry together say: this system is quantum-exposed and nobody has planned for it.

Neither document says that alone. The CBOM is a faithful record of what is in
use; the absence of a QBOM entry is only meaningful once you know what needs
migrating.
"""

from __future__ import annotations

import re
from collections.abc import Mapping, Sequence
from typing import Any

from app.services.correlate.rules import Finding, Severity

#: Quantum-vulnerable public-key families, per s.8.5.1.
VULNERABLE_ALGORITHMS: dict[str, str] = {
    "rsa": "RSA",
    "ecdsa": "ECDSA",
    "ecdh": "ECDH",
    "ecc": "ECC",
    "secp": "ECC",
    "prime256": "ECC",
    "curve25519": "ECC",
    "ed25519": "EdDSA",
    "diffie": "Diffie-Hellman",
    "dh-": "Diffie-Hellman",
    "dsa": "DSA",
    "elgamal": "ElGamal",
}

#: Post-quantum families. Their presence is the migration path being declared.
PQC_ALGORITHMS: tuple[str, ...] = (
    "kyber",
    "ml-kem",
    "dilithium",
    "ml-dsa",
    "falcon",
    "sphincs",
    "slh-dsa",
    "bike",
    "hqc",
    "frodo",
    "ntru",
    "mceliece",
    "xmss",
    "lms",
)

_TOKEN = re.compile(r"[a-z0-9\-]+")


def _algorithm_names(assets: Sequence[dict[str, Any]]) -> list[tuple[str, str]]:
    found: list[tuple[str, str]] = []
    for asset in assets:
        haystack = " ".join(
            str(asset.get(key) or "")
            for key in ("name", "primitive", "algorithm", "asset_type", "oid")
        ).lower()
        if not haystack.strip():
            continue
        for needle, label in VULNERABLE_ALGORITHMS.items():
            if needle in haystack:
                found.append((label, str(asset.get("name") or asset.get("bom_ref") or needle)))
                break
    return found


def _declares_pqc(assets: Sequence[dict[str, Any]]) -> bool:
    for asset in assets:
        haystack = " ".join(
            str(asset.get(key) or "") for key in ("name", "primitive", "algorithm", "migration")
        ).lower()
        if any(candidate in haystack for candidate in PQC_ALGORITHMS):
            return True
    return False


def check(lanes: Mapping[str, Sequence[dict[str, Any]]]) -> list[Finding]:
    cbom = lanes.get("cbom") or []
    qbom = lanes.get("qbom") or []
    if not cbom:
        return []

    exposed = _algorithm_names(cbom)
    if not exposed:
        return []
    if _declares_pqc(qbom) or _declares_pqc(cbom):
        return []

    families = sorted({label for label, _ in exposed})
    return [
        Finding(
            rule_key="algorithmQuantumExposure",
            severity=Severity.HIGH,
            clause="8.5.1",
            detail=(
                f"the CBOM declares quantum-vulnerable public-key cryptography "
                f"({', '.join(families)}) and no post-quantum migration entry is "
                "declared in this submission. s.8.5.1 requires a migration path "
                "for these systems."
            ),
            left_ref=exposed[0][1],
            right_ref=None,
        )
    ]
