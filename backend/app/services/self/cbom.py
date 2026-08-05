"""Our own CBOM: the cryptography this product actually uses.

Declared for the same reason as the AIBOM — a tool that asks suppliers to declare
their cryptographic assets while declaring none of its own has no standing to
raise `cryptoInSbom` against anyone.

Written by hand because a CBOM is not derivable from a dependency scan: knowing
that `cryptography` is installed says nothing about which algorithms are in use,
at what strength, for what purpose. That gap is exactly why S14 exists and why
correlation flags an SBOM with crypto libraries and no CBOM.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

#: Every cryptographic asset this product uses, per Table 9's shape.
ASSETS: tuple[dict[str, Any], ...] = (
    {
        "name": "Argon2id",
        "asset_type": "algorithm",
        "primitive": "password-hashing",
        "purpose": "user password storage",
        "classical_security_level": 128,
        "quantum_vulnerable": False,
    },
    {
        "name": "HMAC-SHA256",
        "asset_type": "algorithm",
        "primitive": "mac",
        "purpose": "JWT signing (HS256) and outbound webhook signatures",
        "classical_security_level": 128,
        "quantum_vulnerable": False,
    },
    {
        "name": "SHA-256",
        "asset_type": "algorithm",
        "primitive": "hash",
        "purpose": "document checksums, idempotency keys, catalogue checksums",
        "classical_security_level": 128,
        "quantum_vulnerable": False,
    },
    {
        "name": "TLS 1.3",
        "asset_type": "protocol",
        "primitive": "transport-security",
        "purpose": "all outbound feed calls and inbound API traffic",
        "classical_security_level": 128,
        "quantum_vulnerable": False,
    },
    {
        "name": "AWS KMS (SSE-KMS, per-client keys)",
        "asset_type": "key",
        "primitive": "key-management",
        "purpose": "encryption at rest for stored BOM documents",
        "classical_security_level": 128,
        "quantum_vulnerable": False,
        "note": "planned with the storage work; not yet in use while payloads are inline",
    },
)


def build() -> dict[str, Any]:
    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "version": 1,
        "metadata": {
            "timestamp": datetime.now(UTC).isoformat(),
            "authors": [{"name": "BOM Automation"}],
            "component": {"type": "application", "name": "bom-automation", "version": "0.1.0"},
        },
        "components": [
            {
                "type": "cryptographic-asset",
                "bom-ref": f"crypto/{asset['name']}",
                "name": asset["name"],
                "cryptoProperties": {
                    "assetType": asset["asset_type"],
                    "algorithmProperties": {
                        "primitive": asset["primitive"],
                        "classicalSecurityLevel": asset["classical_security_level"],
                    },
                },
                "description": asset["purpose"],
            }
            for asset in ASSETS
        ],
    }


def quantum_exposed_assets() -> list[dict[str, Any]]:
    """Assets s.8.5.1 would flag. Currently none — no public-key cryptography is
    in use beyond TLS, whose key exchange is the platform's to migrate."""
    return [asset for asset in ASSETS if asset.get("quantum_vulnerable")]

def main() -> int:
    """Write the document to ``dist/``. **This exists because it did not.**

    Both self-BOMs were produced by hand once and committed, so when the product
    was renamed they silently kept the old name while every other published
    artifact moved. An artifact §11 promises to publish per release needs a
    command that regenerates it, or it drifts exactly like this.
    """
    import json
    from pathlib import Path

    document = build()
    destination = Path(__file__).resolve().parents[4] / "dist" / "bom-automation.cbom.cdx.json"
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text(json.dumps(document, indent=2) + "\n")
    print(f"  {destination.name}: {len(document.get('components') or [])} components")
    return 0


if __name__ == "__main__":  # pragma: no cover - console entry point
    raise SystemExit(main())
