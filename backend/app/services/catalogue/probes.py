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
    """Read a dotted path, tolerating missing intermediates."""
    cursor: Any = entity
    for part in path.split("."):
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

    def probe(entity: dict[str, Any]) -> bool:
        return any(is_meaningful(_read(entity, path)) for path in paths)

    return probe


def all_present(*paths: str) -> Callable[[dict[str, Any]], bool]:
    """Populated only when every path holds a meaningful value.

    For compound elements — a hash is not a hash without both its algorithm and
    its value, and half of one is not half a pass.
    """

    def probe(entity: dict[str, Any]) -> bool:
        return all(is_meaningful(_read(entity, path)) for path in paths)

    return probe


def never(_: dict[str, Any]) -> bool:
    """A field no BOM artifact can carry.

    Used only by HUMAN-determinability elements, which are excluded from the
    supplier score before this is ever consulted. It exists so the probe field is
    total and every element is uniformly shaped.
    """
    return False
