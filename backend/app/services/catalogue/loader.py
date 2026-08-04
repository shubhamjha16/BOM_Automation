"""Catalogue access, version-pinned and checksummed.

The checksum is the point. S7 writes it onto the ``guideline_versions`` row an
assessment is scored under; if this file is edited afterwards, the checksum moves
and old assessments keep reporting against the version they were actually scored
under rather than silently re-interpreting themselves.
"""

from __future__ import annotations

import hashlib
import json
from functools import lru_cache

from app.configs.envConfig import ALL_LANES, Lane, settings
from app.services.catalogue import aibom, cbom, hbom, qbom, sbom
from app.services.catalogue.types import Catalogue

_MODULES = {
    "sbom": sbom,
    "cbom": cbom,
    "qbom": qbom,
    "aibom": aibom,
    "hbom": hbom,
}


def get_catalogue(lane: Lane) -> Catalogue:
    try:
        return _MODULES[lane].CATALOGUE
    except KeyError:
        raise KeyError(f"unknown lane {lane!r}; valid lanes are {list(ALL_LANES)}") from None


def all_catalogues() -> dict[Lane, Catalogue]:
    return {lane: get_catalogue(lane) for lane in ALL_LANES}


@lru_cache(maxsize=8)
def catalogue_checksum(lane: Lane) -> str:
    """SHA-256 over the lane's clause/tier/determinability triples.

    Deliberately excludes labels and rationale: reworded prose is not a change in
    what was scored, and treating it as one would invalidate every prior
    assessment on a typo fix.
    """
    catalogue = get_catalogue(lane)
    canonical = json.dumps(
        [
            {
                "key": element.key,
                "clause": element.clause,
                "tier": str(element.tier),
                "determinability": str(element.determinability),
                "scope": str(element.scope),
            }
            for element in catalogue.elements
        ],
        sort_keys=True,
        separators=(",", ":"),
    )
    return hashlib.sha256(canonical.encode()).hexdigest()


def guideline_ref() -> dict[str, str]:
    """The pinned guideline every verdict in this process resolves against."""
    return {
        "ref": "CERT-In Technical Guidelines on SBOM, QBOM & CBOM, AIBOM and HBOM",
        "version": settings.GUIDELINE_VERSION,
        "published_on": settings.GUIDELINE_DATE,
    }
