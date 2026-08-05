"""Field shape checks.

A field is *populated* when it carries a usable value — not merely when the key
exists. Generators routinely emit ``"license": "NOASSERTION"``, ``"version": ""``
and ``"supplier": "unknown"``; counting those as present is how a BOM with no
usable licence data scores as having met 4.2(5).
"""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

#: Values that are syntactically present and semantically empty. SPDX mandates
#: NOASSERTION/NONE where a producer has no data, so they are absences by
#: definition, not values.
NULL_TOKENS: frozenset[str] = frozenset(
    {
        "",
        "-",
        "n/a",
        "na",
        "none",
        "null",
        "nil",
        "unknown",
        "undefined",
        "noassertion",
        "not applicable",
        "not specified",
        "notspecified",
        "tbd",
    }
)


def is_meaningful(value: Any) -> bool:
    """True when a value carries information a reader could act on."""
    if value is None or isinstance(value, bool):
        return False
    if isinstance(value, str):
        return value.strip().lower() not in NULL_TOKENS
    if isinstance(value, (list, tuple, set)):
        return any(is_meaningful(item) for item in value)
    if isinstance(value, dict):
        return any(is_meaningful(item) for item in value.values())
    return True


def _read(entity: dict[str, Any], path: str) -> Any:
    """Read a dotted path, tolerating missing intermediates.

    Kept for callers that hold a path as a string. The probe factories below split
    theirs once at construction instead — see `_segments`.
    """
    return _walk(entity, tuple(path.split(".")))


def _segments(paths: tuple[str, ...]) -> tuple[tuple[str, ...], ...]:
    """Pre-split the dotted paths a probe reads.

    A probe is built once and called once per entity per element. A 50,000-
    component SBOM scored against 21 elements is over a million probe calls, so
    splitting the same short string a million times is measurable — it was about a
    fifth of the scoring time before this. The split result is immutable, which is
    why hoisting it out of the hot path is safe rather than merely faster.
    """
    return tuple(tuple(path.split(".")) for path in paths)


def _walk(entity: dict[str, Any], segments: tuple[str, ...]) -> Any:
    cursor: Any = entity
    for part in segments:
        if isinstance(cursor, dict):
            cursor = cursor.get(part)
        else:
            return None
    return cursor


def present(*paths: str) -> Callable[[dict[str, Any]], bool]:
    """Populated when any of ``paths`` holds a meaningful value.

    Several paths because the same CERT-In field lands in different places across
    CycloneDX and SPDX, and the normaliser (S6) keeps both the canonical key and
    the source-shaped one.
    """

    segments = _segments(paths)

    def probe(entity: dict[str, Any]) -> bool:
        return any(is_meaningful(_walk(entity, path)) for path in segments)

    return probe


def all_present(*paths: str) -> Callable[[dict[str, Any]], bool]:
    """Populated only when every path holds a meaningful value.

    For compound elements — a hash is not a hash without both its algorithm and
    its value, and half of one is not half a pass.
    """
    segments = _segments(paths)

    def probe(entity: dict[str, Any]) -> bool:
        return all(is_meaningful(_walk(entity, path)) for path in segments)

    return probe


def never(_: dict[str, Any]) -> bool:
    """A field no BOM artifact can carry.

    Used only by HUMAN-determinability elements, which are excluded from the
    supplier score before this is ever consulted. It exists so the probe field is
    total and every element is uniformly shaped.
    """
    return False


_ASSET_TYPE_PATHS = _segments(("asset_type", "cryptoProperties.assetType", "assetType"))


def asset_type_of(entity: dict[str, Any]) -> str:
    """The Table 9 asset type of a cryptographic asset."""
    for path in _ASSET_TYPE_PATHS:
        if value := _walk(entity, path):
            return str(value).strip().lower()
    return ""


def for_asset_types(
    types: set[str], probe: Callable[[dict[str, Any]], bool]
) -> Callable[[dict[str, Any]], bool]:
    """Apply a probe only to the asset types an element governs.

    **Why the CBOM lane needs this and the SBOM lane does not.** Every s.4.2
    element applies to every component. Table 9's do not: a classical security
    level is meaningful for an algorithm and meaningless for a certificate, and
    reporting a certificate as missing its cipher mode is a category error, not a
    gap.

    Assets outside the element's scope are *excluded from the denominator* rather
    than counted as absent — otherwise a document of ten certificates would score
    zero on every algorithm field and the score would measure document
    composition rather than declaration quality.
    """

    def scoped(entity: dict[str, Any]) -> bool:
        # Only ever consulted for in-scope assets; `coverage.measure` filters the
        # rest out of the denominator using `applies_to` below. Returning True
        # here for an out-of-scope asset would count it as *populated*, which
        # inflates the score — a document of ten certificates would report 100%
        # on every algorithm field.
        return probe(entity)

    scoped.applies_to = types  # type: ignore[attr-defined]
    return scoped
