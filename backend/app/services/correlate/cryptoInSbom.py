"""Cryptographic libraries in the SBOM with no corresponding CBOM entry.

A supplier who ships OpenSSL and declares no cryptographic assets has not
declared their cryptography. That is a different finding from "the CBOM scored
badly" — there is no CBOM, and the SBOM proves there should be one.

**Only fires on a lane that carried content.** With no CBOM submitted at all and
none expected, this is silent: a client with no cryptography has nothing to
declare, and §11 is explicit that `lane_not_applicable` is not `lane_absent`.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import Any

from app.services.correlate.rules import Finding, Severity

#: Libraries whose presence implies cryptographic assets exist. Matched on the
#: normalised component name, lowercased, as a substring — supplier naming varies
#: ("openssl", "libssl3", "openssl-dev") and a whole-string match would miss most
#: real BOMs.
CRYPTO_LIBRARIES: dict[str, str] = {
    "openssl": "OpenSSL",
    "libssl": "OpenSSL",
    "libcrypto": "OpenSSL",
    "bouncycastle": "Bouncy Castle",
    "bcprov": "Bouncy Castle",
    "libsodium": "libsodium",
    "nacl": "NaCl/libsodium",
    "mbedtls": "Mbed TLS",
    "wolfssl": "wolfSSL",
    "gnutls": "GnuTLS",
    "libgcrypt": "libgcrypt",
    "nss": "Network Security Services",
    "cryptography": "pyca/cryptography",
    "pycryptodome": "PyCryptodome",
    "node-forge": "node-forge",
    "jose": "JOSE",
    "tink": "Google Tink",
}


def _crypto_components(entities: Sequence[dict[str, Any]]) -> list[tuple[str, str]]:
    hits: list[tuple[str, str]] = []
    for entity in entities:
        name = str(entity.get("name") or "").lower()
        if not name:
            continue
        for needle, label in CRYPTO_LIBRARIES.items():
            if needle in name:
                ref = str(entity.get("purl") or entity.get("bom_ref") or entity.get("name"))
                hits.append((label, ref))
                break
    return hits


def check(lanes: Mapping[str, Sequence[dict[str, Any]]]) -> list[Finding]:
    sbom = lanes.get("sbom") or []
    cbom = lanes.get("cbom") or []

    hits = _crypto_components(sbom)
    if not hits:
        return []
    if cbom:
        # A CBOM was submitted and carried assets; whether it covers *these*
        # libraries is a CBOM-lane scoring question (S14), not a correlation one.
        return []

    labels = sorted({label for label, _ in hits})
    return [
        Finding(
            rule_key="cryptoInSbom",
            severity=Severity.HIGH,
            clause="8.4.1.2",
            detail=(
                f"the SBOM declares {len(hits)} cryptographic librar"
                f"{'y' if len(hits) == 1 else 'ies'} ({', '.join(labels)}) but no "
                "cryptographic assets are declared anywhere in this submission. "
                "The algorithms, keys, protocols and certificates these libraries "
                "implement are undeclared."
            ),
            left_ref=hits[0][1],
            right_ref=None,
        )
    ]
