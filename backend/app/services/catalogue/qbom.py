"""QBOM minimum elements: CERT-In s.8.3, Table 8, guideline v2.0 (09.07.2025).

Table 8 lists 11 rows by name and numbers none of them, so each is cited by section, table and
name (``8.3 Table 8: Model Name``) and the elements are declared in the order the table gives
them. ``tests/test_guideline_fidelity.py`` compares this catalogue with the table, read from the
PDF and checked against its page images. All 11 are anchored.

**QBOM ships beside CBOM because Table 8 embeds `Cryptographic Asset`, which points straight
at Table 9**, the asset model the CBOM lane already builds. So this table scores the quantum
system itself, and that pointer row only asks that the QBOM declares typed cryptographic assets.

The earlier catalogue had 10 elements and cited ``8.5.1`` to ``8.5.10``. Section 8.5 is "Quantum
readiness and migration strategy", a set of recommendations; the minimum elements are in 8.3. It
lacked Version, License Information and Vulnerabilities, split Vendor and Origin into two rows
where Table 8 has one, and held two checks the table does not list (a post-quantum migration
strategy and a deployment exposure). The S9 `algorithmQuantumExposure` rule still reads a
declared migration path from the entity and cites s.8.5.1, which does name RSA, ECC, Diffie-Hellman
and DSA as quantum-vulnerable.

Four elements are judgement calls, because the guideline defines each in one sentence and gives no
tier: Version, License Information, Cryptographic Asset (the pointer row) and Vulnerabilities.
"""

from __future__ import annotations

from typing import Any

from app.configs.envConfig import settings
from app.configs.jobTypes import Determinability, Tier
from app.services.catalogue.probes import present
from app.services.catalogue.types import Catalogue, MinimumElement, table_clause


def _clause(name: str) -> str:
    return table_clause("8.3", 8, name)


#: Every element is checked against Table 8. Kept beside the catalogue so the test and the
#: audit read the same list.
ANCHORED_CLAUSES: dict[str, str] = {
    "model_name": _clause("Model Name"),
    "version": _clause("Version"),
    "vendor_origin": _clause("Vendor & Origin Information"),
    "license_info": _clause("License Information"),
    "cryptographic_asset": _clause("Cryptographic Asset"),
    "communication_protocol": _clause("Communication Protocol"),
    "hardware": _clause("Hardware"),
    "software_dependencies": _clause("Software Dependencies"),
    "environmental_impact": _clause("Environmental Impact"),
    "vulnerabilities": _clause("Vulnerabilities"),
    "attestations": _clause("Attestations"),
}

_VENDOR = present("vendor", "supplier_raw", "publisher")
_ORIGIN = present("origin", "country_of_origin")


def _vendor_and_origin(entity: dict[str, Any]) -> bool:
    """Table 8 records the manufacturer *and* origin in one row; half of it is not a pass."""
    return _VENDOR(entity) and _ORIGIN(entity)


ELEMENTS: tuple[MinimumElement, ...] = (
    MinimumElement(
        key="model_name",
        label="Model Name",
        clause=ANCHORED_CLAUSES["model_name"],
        tier=Tier.CRITICAL,
        determinability=Determinability.AUTO,
        probe=present("name", "model_name"),
        rationale=(
            'The quantum device or system.'
        ),
    ),
    MinimumElement(
        key="version",
        label="Version",
        clause=ANCHORED_CLAUSES["version"],
        tier=Tier.CRITICAL,
        determinability=Determinability.AUTO,
        probe=present("system_version", "model_version"),
        rationale=(
            'Version numbers and updates of the quantum system.'
        ),
    ),
    MinimumElement(
        key="vendor_origin",
        label="Vendor & Origin Information",
        clause=ANCHORED_CLAUSES["vendor_origin"],
        tier=Tier.CRITICAL,
        determinability=Determinability.AUTO,
        probe=_vendor_and_origin,
        rationale=(
            'The manufacturer and origin of the quantum device. Table 8 records both in one row, '
            'so'
            'both must be declared; the earlier catalogue scored them as two.'
        ),
    ),
    MinimumElement(
        key="license_info",
        label="License Information",
        clause=ANCHORED_CLAUSES["license_info"],
        tier=Tier.STANDARD,
        determinability=Determinability.AUTO,
        probe=present("license_expr", "licenses", "license"),
        rationale=(
            'The licensing terms of the quantum device.'
        ),
    ),
    MinimumElement(
        key="cryptographic_asset",
        label="Cryptographic Asset",
        clause=ANCHORED_CLAUSES["cryptographic_asset"],
        tier=Tier.STANDARD,
        determinability=Determinability.AUTO,
        probe=present("asset_type", "cryptographic_assets"),
        rationale=(
            "Table 8's pointer to Table 9: for a cryptographic asset, the minimum elements are "
            "those of Table 9 for its asset type, which the CBOM lane scores. This row only asks "
            "that the QBOM declares its cryptographic assets, as typed assets."
        ),
    ),
    MinimumElement(
        key="communication_protocol",
        label="Communication Protocol",
        clause=ANCHORED_CLAUSES["communication_protocol"],
        tier=Tier.STANDARD,
        determinability=Determinability.AUTO,
        probe=present("protocol", "communication_protocol"),
    ),
    MinimumElement(
        key="hardware",
        label="Hardware",
        clause=ANCHORED_CLAUSES["hardware"],
        tier=Tier.STANDARD,
        determinability=Determinability.AUTO,
        probe=present("hardware", "qubit_technology"),
    ),
    MinimumElement(
        key="software_dependencies",
        label="Software Dependencies",
        clause=ANCHORED_CLAUSES["software_dependencies"],
        tier=Tier.STANDARD,
        determinability=Determinability.AUTO,
        probe=present("software_dependencies", "dependencies"),
    ),
    MinimumElement(
        key="environmental_impact",
        label="Environmental Impact",
        clause=ANCHORED_CLAUSES["environmental_impact"],
        tier=Tier.CONTEXTUAL,
        determinability=Determinability.AUTO,
        probe=present("environmental_impact", "power_consumption", "cooling"),
    ),
    MinimumElement(
        key="vulnerabilities",
        label="Vulnerabilities",
        clause=ANCHORED_CLAUSES["vulnerabilities"],
        tier=Tier.STANDARD,
        determinability=Determinability.AUTO,
        probe=present("vulnerabilities"),
        rationale=(
            'Known vulnerabilities of the quantum system, from the CycloneDX `vulnerabilities` '
            'entries that affect it.'
        ),
    ),
    MinimumElement(
        key="attestations",
        label="Attestations",
        clause=ANCHORED_CLAUSES["attestations"],
        tier=Tier.STANDARD,
        determinability=Determinability.AUTO,
        probe=present("attestations", "certifications", "signature"),
        rationale=(
            'A digital signature for the QBOM, from the CycloneDX `signature` on the component or '
            'the document.'
        ),
    ),
)

CATALOGUE = Catalogue(
    lane="qbom",
    clause_root="8.3",
    guideline_version=settings.GUIDELINE_VERSION,
    elements=ELEMENTS,
)
