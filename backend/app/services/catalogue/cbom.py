"""CBOM minimum elements — CERT-In s.8.4, Tables 8 and 9. Implemented in S14.

The table is deliberately empty rather than approximated. An empty catalogue makes
the lane report ``lane_absent``; a guessed catalogue would make it report a score,
and a score computed against invented clauses is worse than no score at all.

S14 encodes the four asset types: algorithms (name, primitive, mode, crypto
functions, classical security level, OID), keys (id, state, size, creation and
activation dates), protocols (version, cipher suites) and certificates (subject,
issuer, validity window, signature algorithm, format).
"""

from __future__ import annotations

from app.configs.envConfig import settings
from app.services.catalogue.types import Catalogue, MinimumElement

ELEMENTS: tuple[MinimumElement, ...] = ()

CATALOGUE = Catalogue(
    lane="cbom",
    clause_root="8.4",
    guideline_version=settings.GUIDELINE_VERSION,
    elements=ELEMENTS,
)
