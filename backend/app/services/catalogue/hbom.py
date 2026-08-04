"""HBOM minimum elements — CERT-In s.10.2, Table 11. Implemented in S16.

HBOM lands with the estate dashboard rather than beside the artifact-scanning
lanes because its data is procurement data: manufacturer location, manufacturing
date, serial number, technology node, warranty and AMC, test results and
compliance declarations come from asset registers and purchase records, not from
a scanner. Table 11's final row carries subcomponent recursion.

Empty until then, for the reason given in `cbom.py`.
"""

from __future__ import annotations

from app.configs.envConfig import settings
from app.services.catalogue.types import Catalogue, MinimumElement

ELEMENTS: tuple[MinimumElement, ...] = ()

CATALOGUE = Catalogue(
    lane="hbom",
    clause_root="10.2",
    guideline_version=settings.GUIDELINE_VERSION,
    elements=ELEMENTS,
)
