"""SPDX 2.2 / 2.3 JSON → normalised entities.

SPDX mandates `NOASSERTION` and `NONE` where a producer has no data. Those are
**absences with a name**, not values — a supplier emitting
`"licenseConcluded": "NOASSERTION"` across 400 packages has declared nothing
about licensing and must not score as having met 4.2(5).

Relationship parsing matters for the same reason. 4.2(7) Dependencies is a
critical element and SPDX carries the graph in `relationships` rather than on the
package, so a parser that ignores them reports every component as having no
dependencies — a critical gap manufactured by the parser rather than found in
the document.
"""

from __future__ import annotations

from typing import Any

from app.services.ingest.result import ParseResult

SUPPORTED_SPEC_VERSIONS: frozenset[str] = frozenset({"SPDX-2.2", "SPDX-2.3"})

#: Relationship types that mean "A depends on B" for 4.2(7) purposes.
DEPENDENCY_RELATIONSHIPS: frozenset[str] = frozenset(
    {"DEPENDS_ON", "DEPENDENCY_OF", "CONTAINS", "CONTAINED_BY", "STATIC_LINK", "DYNAMIC_LINK"}
)

#: SPDX's explicit "the producer had no data" tokens.
SPDX_NULL_TOKENS: frozenset[str] = frozenset({"NOASSERTION", "NONE"})


class UnsupportedSpdxVersion(ValueError):
    """The document declares an SPDX version this engine does not parse."""


def _clean(value: Any) -> Any:
    """Map SPDX's null tokens onto real absence."""
    if isinstance(value, str) and value.strip().upper() in SPDX_NULL_TOKENS:
        return None
    return value


def _dependency_index(document: dict[str, Any]) -> dict[str, list[str]]:
    """SPDXID → the elements it depends on.

    Both directions are folded in: `A DEPENDS_ON B` and `B DEPENDENCY_OF A` state
    the same fact, and real producers emit both.
    """
    index: dict[str, list[str]] = {}
    for relationship in document.get("relationships", []) or []:
        if not isinstance(relationship, dict):
            continue
        kind = str(relationship.get("relationshipType", "")).upper()
        if kind not in DEPENDENCY_RELATIONSHIPS:
            continue
        source = relationship.get("spdxElementId")
        target = relationship.get("relatedSpdxElement")
        if not source or not target:
            continue
        if kind in ("DEPENDENCY_OF", "CONTAINED_BY"):
            source, target = target, source
        index.setdefault(str(source), []).append(str(target))
    return index


def _external_refs(package: dict[str, Any]) -> tuple[str | None, str | None]:
    purl = cpe = None
    for reference in package.get("externalRefs", []) or []:
        if not isinstance(reference, dict):
            continue
        ref_type = str(reference.get("referenceType", "")).lower()
        locator = reference.get("referenceLocator")
        if ref_type == "purl":
            purl = locator
        elif ref_type.startswith("cpe"):
            cpe = locator
    return purl, cpe


def _licence(package: dict[str, Any]) -> str | None:
    """Concluded licence first, then declared.

    SPDX distinguishes what the producer *concluded* from what the package
    *declares*. The concluded value is the producer's own determination and the
    stronger claim, so it wins where both are present.
    """
    for key in ("licenseConcluded", "licenseDeclared"):
        if value := _clean(package.get(key)):
            return str(value)
    return None


def _checksums(package: dict[str, Any]) -> list[str]:
    return [
        str(entry.get("checksumValue"))
        for entry in package.get("checksums", []) or []
        if isinstance(entry, dict) and entry.get("checksumValue")
    ]


def _normalise(package: dict[str, Any], dependencies: dict[str, list[str]]) -> dict[str, Any]:
    spdx_id = str(package.get("SPDXID") or "")
    purl, cpe = _external_refs(package)
    return {
        "name": _clean(package.get("name")),
        "version": _clean(package.get("versionInfo")),
        "description": _clean(package.get("description")) or _clean(package.get("summary")),
        "supplier_raw": _clean(package.get("supplier")),
        "publisher": _clean(package.get("originator")),
        "author": _clean(package.get("originator")),
        "license_expr": _licence(package),
        "purl": purl,
        "cpe": cpe,
        "bom_ref": spdx_id or purl,
        "checksums": _checksums(package),
        "origin": _clean(package.get("downloadLocation")) or _clean(package.get("homepage")),
        "dependencies": dependencies.get(spdx_id, []),
        "properties": {},
        # Populated by enrichment (S10) and identifier mapping (S11).
        "vulnerabilities": None,
        "patch_status": None,
        "release_date": _clean(package.get("releaseDate")),
        "eol_date": _clean(package.get("validUntilDate")),
        "certin_id": None,
        "supplier_org": None,
    }


def parse(payload: dict[str, Any], *, lane: str = "sbom") -> ParseResult:
    """Parse an SPDX JSON document."""
    if not isinstance(payload, dict) or "spdxVersion" not in payload:
        raise UnsupportedSpdxVersion(
            "payload is not an SPDX JSON document (no spdxVersion); refusing to "
            "parse rather than returning an empty package list (rec. 7.1.5)"
        )

    spec_version = str(payload.get("spdxVersion", ""))
    if spec_version not in SUPPORTED_SPEC_VERSIONS:
        raise UnsupportedSpdxVersion(
            f"SPDX version {spec_version!r} is not supported; supported versions are "
            f"{sorted(SUPPORTED_SPEC_VERSIONS)}"
        )

    creation = payload.get("creationInfo") or {}
    creators = creation.get("creators") or []
    packages = payload.get("packages") or []

    result = ParseResult(
        spec_version=spec_version,
        format="SPDX",
        doc_author=str(creators[0]) if creators else None,
        doc_timestamp=creation.get("created"),
        doc_name=payload.get("name"),
        declared_entries=len(packages) if isinstance(packages, list) else 0,
    )

    # AIBOM has no SPDX representation in guideline v2.0; scoring SPDX packages
    # against the s.9.3 model catalogue would be an invented mapping. The entries
    # are rejected with a reason rather than dropped.
    if lane != "sbom":
        for ordinal, package in enumerate(packages):
            result.reject(
                ordinal,
                f"SPDX documents are scored by the SBOM lane only; the {lane} lane "
                "has no SPDX element mapping in guideline v2.0",
                ref=str(package.get("SPDXID")) if isinstance(package, dict) else None,
            )
        result.assert_conserved()
        return result

    dependencies = _dependency_index(payload)

    for ordinal, package in enumerate(packages):
        if not isinstance(package, dict):
            result.reject(ordinal, "entry is not an object", payload=package)
            continue
        spdx_id = package.get("SPDXID")
        if not package.get("name"):
            result.reject(
                ordinal,
                "package has no name; SPDX requires PackageName on every package",
                ref=str(spdx_id) if spdx_id else None,
            )
            continue
        if not spdx_id:
            result.reject(
                ordinal,
                "package has no SPDXID; without one no relationship can reference it "
                "and its dependencies cannot be resolved",
                ref=str(package.get("name")),
            )
            continue
        result.entities.append(_normalise(package, dependencies))

    result.assert_conserved()
    return result
