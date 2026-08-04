"""Document-level checks for the CBOM lane.

**Why these are not field verdicts.** Coverage answers "did the supplier declare
this field?". These answer "is what they declared *wrong*?" — and the difference
matters because a fully-declared expired certificate scores 100% on every field
while being a finding. A supplier who declares a deprecated cipher suite has met
8.4.2.2's declaration requirement and failed its substance.

So each check produces a finding with its own clause, alongside the field
verdicts rather than inside them.
"""

from __future__ import annotations

import re
from collections.abc import Sequence
from dataclasses import dataclass
from datetime import UTC, date, datetime
from typing import Any


@dataclass(frozen=True, slots=True)
class CryptoFinding:
    check_key: str
    clause: str
    severity: str
    detail: str
    asset_ref: str | None = None

    def as_row(self) -> dict[str, Any]:
        return {
            "check_key": self.check_key,
            "clause": self.clause,
            "severity": self.severity,
            "detail": self.detail,
            "asset_ref": self.asset_ref,
        }


#: Cipher suites deprecated or prohibited for TLS. Matched as substrings because
#: suite naming varies between OpenSSL and IANA spellings
#: (`ECDHE-RSA-AES256-SHA` vs `TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA`).
DEPRECATED_SUITE_MARKERS: dict[str, str] = {
    "_rc4": "RC4 is prohibited (RFC 7465)",
    "-rc4": "RC4 is prohibited (RFC 7465)",
    "_3des": "3DES offers 112-bit security and is deprecated",
    "-3des": "3DES offers 112-bit security and is deprecated",
    "_des_": "single DES is broken",
    "_null": "NULL encryption provides no confidentiality",
    "-null": "NULL encryption provides no confidentiality",
    "_export": "EXPORT-grade suites are deliberately weakened",
    "_md5": "MD5 is broken for signatures",
    "-md5": "MD5 is broken for signatures",
    "_anon": "anonymous key exchange provides no authentication",
    "_cbc_sha\b": "CBC with SHA-1 is deprecated",
}

#: Protocol versions no longer acceptable.
DEPRECATED_PROTOCOLS: dict[str, str] = {
    "ssl": "SSL is prohibited in all versions",
    "tls1.0": "TLS 1.0 is deprecated (RFC 8996)",
    "tlsv1.0": "TLS 1.0 is deprecated (RFC 8996)",
    "tls 1.0": "TLS 1.0 is deprecated (RFC 8996)",
    "tls1.1": "TLS 1.1 is deprecated (RFC 8996)",
    "tlsv1.1": "TLS 1.1 is deprecated (RFC 8996)",
    "tls 1.1": "TLS 1.1 is deprecated (RFC 8996)",
}

# No trailing \b: real algorithm names run the digest into the next word
# ("sha1WithRSAEncryption"), and requiring a boundary there let SHA-1
# certificates through. A leading boundary is kept so "sha256" does not match.
# `(?!\d)` stops "sha1" matching inside "sha1024" or similar.
_SHA1_OR_MD5 = re.compile(r"\b(?:sha-?1(?!\d)|md5)", re.IGNORECASE)


def _as_date(value: Any) -> date | None:
    if isinstance(value, datetime):
        return value.date()
    if isinstance(value, date):
        return value
    if isinstance(value, str):
        try:
            return datetime.fromisoformat(value.replace("Z", "+00:00")).date()
        except ValueError:
            try:
                return date.fromisoformat(value[:10])
            except ValueError:
                return None
    return None


def _ref(asset: dict[str, Any]) -> str:
    return str(asset.get("name") or asset.get("bom_ref") or "unnamed asset")


def expired_certificates(
    assets: Sequence[dict[str, Any]], *, today: date | None = None
) -> list[CryptoFinding]:
    """Certificates past their Not Valid After date.

    A declared, complete, expired certificate scores full marks on every field.
    Only a document-level check catches it.
    """
    now = today or datetime.now(UTC).date()
    findings: list[CryptoFinding] = []

    for asset in assets:
        if str(asset.get("asset_type") or "").lower() != "certificate":
            continue
        expiry = _as_date(asset.get("not_valid_after"))
        if expiry is None:
            continue
        if expiry < now:
            findings.append(
                CryptoFinding(
                    check_key="certificateExpired",
                    clause="8.4.3.3",
                    severity="high",
                    detail=(
                        f"certificate {_ref(asset)!r} expired on {expiry.isoformat()} "
                        f"({(now - expiry).days} days ago); it is declared but no "
                        "longer valid"
                    ),
                    asset_ref=_ref(asset),
                )
            )
    return findings


def deprecated_cipher_suites(assets: Sequence[dict[str, Any]]) -> list[CryptoFinding]:
    """Protocol configurations declaring a deprecated suite or version.

    Cited to s.8.4.2.2 — the clause that requires cipher suites to be declared —
    because the declaration is what makes the weakness assessable.
    """
    findings: list[CryptoFinding] = []

    for asset in assets:
        if str(asset.get("asset_type") or "").lower() != "protocol":
            continue

        version = str(asset.get("version") or "").strip().lower()
        for marker, reason in DEPRECATED_PROTOCOLS.items():
            if marker in version.replace(" ", "") or marker in version:
                findings.append(
                    CryptoFinding(
                        check_key="deprecatedProtocolVersion",
                        clause="8.4.2.1",
                        severity="high",
                        detail=f"{_ref(asset)!r} declares {asset.get('version')!r}: {reason}",
                        asset_ref=_ref(asset),
                    )
                )
                break

        suites = asset.get("cipher_suites") or []
        for suite in suites if isinstance(suites, list) else [suites]:
            name = str(suite or "").lower()
            for marker, reason in DEPRECATED_SUITE_MARKERS.items():
                if re.search(marker, name) if marker.endswith(r"\b") else marker in name:
                    findings.append(
                        CryptoFinding(
                            check_key="deprecatedCipherSuite",
                            clause="8.4.2.2",
                            severity="high",
                            detail=f"{_ref(asset)!r} declares {suite!r}: {reason}",
                            asset_ref=_ref(asset),
                        )
                    )
                    break
    return findings


def weak_certificate_signatures(assets: Sequence[dict[str, Any]]) -> list[CryptoFinding]:
    """Certificates signed with SHA-1 or MD5."""
    findings: list[CryptoFinding] = []
    for asset in assets:
        if str(asset.get("asset_type") or "").lower() != "certificate":
            continue
        algorithm = str(asset.get("signature_algorithm") or "")
        if _SHA1_OR_MD5.search(algorithm):
            findings.append(
                CryptoFinding(
                    check_key="weakCertificateSignature",
                    clause="8.4.3.4",
                    severity="high",
                    detail=(
                        f"certificate {_ref(asset)!r} is signed with {algorithm!r}; "
                        "SHA-1 and MD5 are broken for signatures"
                    ),
                    asset_ref=_ref(asset),
                )
            )
    return findings


def run_all(
    assets: Sequence[dict[str, Any]], *, today: date | None = None
) -> list[CryptoFinding]:
    return [
        *expired_certificates(assets, today=today),
        *deprecated_cipher_suites(assets),
        *weak_certificate_signatures(assets),
    ]
