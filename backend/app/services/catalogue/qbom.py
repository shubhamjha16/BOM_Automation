"""QBOM minimum elements — CERT-In s.8.5. Implemented in S14, beside CBOM.

Table 8 embeds `Cryptographic Asset` pointing straight at Table 9, so QBOM adds
only what is QBOM-specific once CBOM's asset model exists: model name, vendor and
origin, communication protocol, hardware, software dependencies, environmental
impact and attestations.

Empty until then, for the reason given in `cbom.py`.
"""

from __future__ import annotations

from app.configs.envConfig import settings
from app.services.catalogue.types import Catalogue, MinimumElement

ELEMENTS: tuple[MinimumElement, ...] = ()

CATALOGUE = Catalogue(
    lane="qbom",
    clause_root="8.5",
    guideline_version=settings.GUIDELINE_VERSION,
    elements=ELEMENTS,
)
