"""SPDX 2.2 / 2.3 tag-value → normalised entities.

Tag-value gets its own parser rather than a pre-pass into JSON because of one
requirement: **a truncated document must fail loudly, naming the byte offset.**

That matters because tag-value has no closing delimiter. A file cut off
mid-transfer is still syntactically valid right up to the truncation — it simply
contains fewer packages than the supplier sent. Converting to JSON first would
discard the byte positions and the failure would surface as "your BOM has 180
components" when 400 were sent, which scores as a complete assessment of an
incomplete document.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any

from app.services.ingest.result import ParseResult

SUPPORTED_SPEC_VERSIONS: frozenset[str] = frozenset({"SPDX-2.2", "SPDX-2.3"})
SPDX_NULL_TOKENS: frozenset[str] = frozenset({"NOASSERTION", "NONE"})

_TAG = re.compile(r"^([A-Za-z][A-Za-z0-9]*):\s*(.*)$")
#: <text>...</text> spans a value across lines; unterminated, it truncates the file.
_TEXT_OPEN = "<text>"
_TEXT_CLOSE = "</text>"


class TruncatedDocument(ValueError):
    """The document ends mid-value. Carries the byte offset where it broke."""

    def __init__(self, offset: int, line: int, detail: str) -> None:
        self.offset = offset
        self.line = line
        super().__init__(
            f"SPDX tag-value document is truncated at byte offset {offset} "
            f"(line {line}): {detail}. The file ended mid-value, so an unknown "
            "number of packages are missing — refusing to score a partial document."
        )


class UnsupportedSpdxVersion(ValueError):
    """The document declares an SPDX version this engine does not parse."""


@dataclass(slots=True)
class _Package:
    ord: int
    fields: dict[str, Any]
    #: Byte offset of this package's first tag, for error reporting.
    offset: int


def _clean(value: str | None) -> str | None:
    if value is None:
        return None
    stripped = value.strip()
    if not stripped or stripped.upper() in SPDX_NULL_TOKENS:
        return None
    return stripped


def _scan(document: str) -> tuple[dict[str, Any], list[_Package]]:
    """Walk the document, tracking byte offsets so truncation can be located."""
    header: dict[str, Any] = {}
    packages: list[_Package] = []
    current: _Package | None = None

    offset = 0
    in_text = False
    text_tag: str | None = None
    text_start_offset = 0
    text_start_line = 0
    buffer: list[str] = []

    for line_number, line in enumerate(document.splitlines(keepends=True), start=1):
        line_offset = offset
        offset += len(line.encode())
        stripped = line.strip()

        if in_text:
            buffer.append(stripped)
            if _TEXT_CLOSE in stripped:
                joined = " ".join(buffer).replace(_TEXT_OPEN, "").replace(_TEXT_CLOSE, "").strip()
                target = current.fields if current is not None else header
                if text_tag:
                    target[text_tag] = joined
                in_text, text_tag, buffer = False, None, []
            continue

        if not stripped or stripped.startswith("#"):
            continue

        match = _TAG.match(stripped)
        if match is None:
            continue

        tag, value = match.group(1), match.group(2)

        if _TEXT_OPEN in value and _TEXT_CLOSE not in value:
            in_text, text_tag = True, tag
            text_start_offset, text_start_line = line_offset, line_number
            buffer = [value]
            continue

        value = value.replace(_TEXT_OPEN, "").replace(_TEXT_CLOSE, "").strip()

        if tag == "PackageName":
            current = _Package(ord=len(packages), fields={"PackageName": value}, offset=line_offset)
            packages.append(current)
        elif current is not None:
            # Repeated tags (ExternalRef, Checksum) accumulate rather than clobber.
            if tag in current.fields:
                existing = current.fields[tag]
                current.fields[tag] = (
                    [*existing, value] if isinstance(existing, list) else [existing, value]
                )
            else:
                current.fields[tag] = value
        else:
            header[tag] = value

    if in_text:
        raise TruncatedDocument(
            text_start_offset,
            text_start_line,
            f"<text> block opened for tag {text_tag!r} was never closed",
        )
    return header, packages


def _relationships(header: dict[str, Any], packages: list[_Package]) -> dict[str, list[str]]:
    """`Relationship: A DEPENDS_ON B`, folded both directions."""
    index: dict[str, list[str]] = {}
    raw = header.get("Relationship")
    entries = raw if isinstance(raw, list) else ([raw] if raw else [])
    for package in packages:
        value = package.fields.get("Relationship")
        entries.extend(value if isinstance(value, list) else ([value] if value else []))

    for entry in entries:
        parts = str(entry).split()
        if len(parts) != 3:
            continue
        source, kind, target = parts
        kind = kind.upper()
        if kind in ("DEPENDENCY_OF", "CONTAINED_BY"):
            source, target = target, source
        elif kind not in ("DEPENDS_ON", "CONTAINS", "STATIC_LINK", "DYNAMIC_LINK"):
            continue
        index.setdefault(source, []).append(target)
    return index


def _first(value: Any) -> str | None:
    if isinstance(value, list):
        return str(value[0]) if value else None
    return None if value is None else str(value)


def _normalise(package: _Package, dependencies: dict[str, list[str]]) -> dict[str, Any]:
    fields = package.fields
    spdx_id = _clean(_first(fields.get("SPDXID"))) or ""

    purl = cpe = None
    refs = fields.get("ExternalRef")
    for reference in refs if isinstance(refs, list) else ([refs] if refs else []):
        parts = str(reference).split()
        if len(parts) >= 3:
            if parts[1].lower() == "purl":
                purl = parts[2]
            elif parts[1].lower().startswith("cpe"):
                cpe = parts[2]

    checksums = []
    raw_checksums = fields.get("PackageChecksum")
    entries = (
        raw_checksums
        if isinstance(raw_checksums, list)
        else ([raw_checksums] if raw_checksums else [])
    )
    for entry in entries:
        parts = str(entry).split()
        if len(parts) >= 2:
            checksums.append(parts[1])

    licence = _clean(_first(fields.get("PackageLicenseConcluded"))) or _clean(
        _first(fields.get("PackageLicenseDeclared"))
    )

    return {
        "name": _clean(_first(fields.get("PackageName"))),
        "version": _clean(_first(fields.get("PackageVersion"))),
        "description": _clean(_first(fields.get("PackageDescription")))
        or _clean(_first(fields.get("PackageSummary"))),
        "supplier_raw": _clean(_first(fields.get("PackageSupplier"))),
        "publisher": _clean(_first(fields.get("PackageOriginator"))),
        "author": _clean(_first(fields.get("PackageOriginator"))),
        "license_expr": licence,
        "purl": purl,
        "cpe": cpe,
        "bom_ref": spdx_id or purl,
        "checksums": checksums,
        "origin": _clean(_first(fields.get("PackageDownloadLocation")))
        or _clean(_first(fields.get("PackageHomePage"))),
        "dependencies": dependencies.get(spdx_id, []),
        "properties": {},
        "vulnerabilities": None,
        "patch_status": None,
        "release_date": _clean(_first(fields.get("ReleaseDate"))),
        "eol_date": _clean(_first(fields.get("ValidUntilDate"))),
        "certin_id": None,
        "supplier_org": None,
    }


def parse(payload: str, *, lane: str = "sbom") -> ParseResult:
    """Parse an SPDX tag-value document."""
    if not isinstance(payload, str):
        raise UnsupportedSpdxVersion(
            f"SPDX tag-value input must be text, got {type(payload).__name__} "
            "(rec. 7.1.5)"
        )

    header, packages = _scan(payload)

    spec_version = str(header.get("SPDXVersion", ""))
    if spec_version not in SUPPORTED_SPEC_VERSIONS:
        raise UnsupportedSpdxVersion(
            f"SPDX version {spec_version!r} is not supported; supported versions are "
            f"{sorted(SUPPORTED_SPEC_VERSIONS)}"
        )

    result = ParseResult(
        spec_version=spec_version,
        format="SPDX",
        doc_author=_clean(_first(header.get("Creator"))),
        doc_timestamp=_clean(_first(header.get("Created"))),
        doc_name=_clean(_first(header.get("DocumentName"))),
        declared_entries=len(packages),
    )

    if lane != "sbom":
        for package in packages:
            result.reject(
                package.ord,
                f"SPDX documents are scored by the SBOM lane only; the {lane} lane "
                "has no SPDX element mapping in guideline v2.0",
                ref=_clean(_first(package.fields.get("SPDXID"))),
            )
        result.assert_conserved()
        return result

    dependencies = _relationships(header, packages)

    for package in packages:
        name = _clean(_first(package.fields.get("PackageName")))
        if not name:
            result.reject(
                package.ord,
                f"package at byte offset {package.offset} has an empty PackageName",
            )
            continue
        if not _clean(_first(package.fields.get("SPDXID"))):
            result.reject(
                package.ord,
                f"package {name!r} at byte offset {package.offset} has no SPDXID; "
                "without one no relationship can reference it",
                ref=name,
            )
            continue
        result.entities.append(_normalise(package, dependencies))

    result.assert_conserved()
    return result
