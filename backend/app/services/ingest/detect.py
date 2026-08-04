"""Format detection: **explicit, caller-overridable, never guessed.**

The caller declares the format at upload and this module *confirms* the
declaration against the document's own self-identifying fields. It does not sniff
a string prefix, and it does not fall back to a best guess.

Why that matters more than it sounds: a CycloneDX document mis-detected as SPDX
yields zero packages, and zero packages scores as a clean assessment of a
supplier who submitted nothing wrong. Every guess this module might make has that
failure mode behind it, so it makes none — an ambiguous or contradicted document
raises and the submission is refused (rec. 7.1.5).
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from typing import Any


class Format(StrEnum):
    CYCLONEDX_JSON = "CycloneDX"
    SPDX_JSON = "SPDX"
    SPDX_TAG_VALUE = "SPDX-tag-value"


class UnrecognisedFormat(ValueError):
    """The payload is not a BOM this engine can read.

    Raised rather than returning `None` so the caller cannot accidentally treat
    an unreadable document as an empty one.
    """


class FormatMismatch(ValueError):
    """The document contradicts the format the caller declared."""


@dataclass(frozen=True, slots=True)
class Detection:
    format: Format
    spec_version: str | None
    #: What in the document proved it — recorded so a rejection can say why.
    evidence: str


#: Self-identifying fields. A BOM format worth supporting says what it is.
_CYCLONEDX_MARKER = "bomFormat"
_SPDX_MARKER = "spdxVersion"
_TAG_VALUE_MARKER = "SPDXVersion:"


def detect(payload: Any, *, declared: str | None = None) -> Detection:
    """Identify a document, confirming the caller's declaration if given.

    `declared` is the lane document's `format` field. When present it must match
    what the document says about itself; a mismatch raises rather than
    silently trusting either side, because both are claims and disagreement means
    one of them is wrong.
    """
    detection = _identify(payload)

    if declared:
        expected = _normalise_declared(declared)
        if expected is not None and detection.format.value.split("-")[0] != expected:
            raise FormatMismatch(
                f"caller declared {declared!r} but the document identifies itself as "
                f"{detection.format.value} ({detection.evidence}); refusing to parse "
                "a document whose format is disputed"
            )
    return detection


def _normalise_declared(declared: str) -> str | None:
    lowered = declared.strip().lower()
    if lowered.startswith("cyclonedx"):
        return "CycloneDX"
    if lowered.startswith("spdx"):
        return "SPDX"
    return None


def _identify(payload: Any) -> Detection:
    if isinstance(payload, dict):
        if payload.get(_CYCLONEDX_MARKER) == "CycloneDX":
            return Detection(
                format=Format.CYCLONEDX_JSON,
                spec_version=str(payload.get("specVersion") or "") or None,
                evidence='bomFormat == "CycloneDX"',
            )
        if _SPDX_MARKER in payload:
            return Detection(
                format=Format.SPDX_JSON,
                spec_version=str(payload.get(_SPDX_MARKER) or "") or None,
                evidence=f"spdxVersion == {payload.get(_SPDX_MARKER)!r}",
            )
        raise UnrecognisedFormat(
            "payload is a JSON object but carries neither bomFormat (CycloneDX) nor "
            "spdxVersion (SPDX). Recommendation 7.1.5 requires a BOM in a recognised "
            "machine-readable format; refusing to parse rather than returning an "
            "empty component list, which would render as a clean assessment."
        )

    if isinstance(payload, str):
        if _TAG_VALUE_MARKER in payload.replace(" ", ""):
            version = None
            for line in payload.splitlines():
                if line.replace(" ", "").startswith(_TAG_VALUE_MARKER):
                    version = line.split(":", 1)[1].strip()
                    break
            return Detection(
                format=Format.SPDX_TAG_VALUE,
                spec_version=version,
                evidence="SPDXVersion: tag present",
            )
        raise UnrecognisedFormat(
            "payload is text but contains no SPDXVersion tag; it is not an SPDX "
            "tag-value document (rec. 7.1.5)"
        )

    raise UnrecognisedFormat(
        f"payload is {type(payload).__name__}; a BOM must be a JSON object or an "
        "SPDX tag-value document (rec. 7.1.5)"
    )
