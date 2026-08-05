"""QBOM minimum elements — CERT-In s.8.5.

**QBOM ships beside CBOM because Table 8 embeds `Cryptographic Asset`, which
points straight at Table 9** — the asset model the CBOM lane already builds. So
this table adds only what is QBOM-specific: the quantum system itself, and the
migration posture of the classical cryptography it threatens.

s.8.5.1 is anchored by the specification: public-key systems using RSA, ECC,
Diffie-Hellman or DSA are the quantum-exposed set, and the S9
`algorithmQuantumExposure` rule cites it. The remaining ordinals are provisional
pending the S20 audit.
"""

from __future__ import annotations

from app.configs.envConfig import settings
from app.configs.jobTypes import Determinability, Tier
from app.services.catalogue.probes import never, present
from app.services.catalogue.types import Catalogue, MinimumElement

ANCHORED_CLAUSES: dict[str, str] = {
    "migration_strategy": "8.5.1",
}

ELEMENTS: tuple[MinimumElement, ...] = (
    MinimumElement(
        key="migration_strategy",
        label="Post-Quantum Migration Strategy",
        clause="8.5.1",
        tier=Tier.CRITICAL,
        determinability=Determinability.AUTO,
        probe=present("migration", "migration_strategy", "pqc_algorithm"),
        rationale=(
            "The declaration s.8.5.1 exists for. A CBOM declaring RSA, ECC, "
            "Diffie-Hellman or DSA with no migration entry here is the "
            "quantum-exposure finding the S9 correlation rule raises."
        ),
    ),
    MinimumElement(
        key="model_name",
        label="Quantum System / Model Name",
        clause="8.5.2",
        tier=Tier.CRITICAL,
        determinability=Determinability.AUTO,
        probe=present("name", "model_name"),
    ),
    MinimumElement(
        key="vendor",
        label="Vendor",
        clause="8.5.3",
        tier=Tier.CRITICAL,
        determinability=Determinability.AUTO,
        probe=present("vendor", "supplier_raw", "publisher"),
    ),
    MinimumElement(
        key="origin",
        label="Country of Origin",
        clause="8.5.4",
        tier=Tier.STANDARD,
        determinability=Determinability.AUTO,
        probe=present("origin", "country_of_origin"),
        rationale=(
            "Quantum hardware supply is concentrated in a handful of jurisdictions, "
            "which is a procurement consideration rather than a technical one."
        ),
    ),
    MinimumElement(
        key="communication_protocol",
        label="Communication Protocol",
        clause="8.5.5",
        tier=Tier.STANDARD,
        determinability=Determinability.AUTO,
        probe=present("protocol", "communication_protocol"),
    ),
    MinimumElement(
        key="hardware",
        label="Hardware",
        clause="8.5.6",
        tier=Tier.STANDARD,
        determinability=Determinability.AUTO,
        probe=present("hardware", "qubit_technology"),
    ),
    MinimumElement(
        key="software_dependencies",
        label="Software Dependencies",
        clause="8.5.7",
        tier=Tier.STANDARD,
        determinability=Determinability.AUTO,
        probe=present("software_dependencies", "dependencies"),
    ),
    MinimumElement(
        key="environmental_impact",
        label="Environmental Impact",
        clause="8.5.8",
        tier=Tier.CONTEXTUAL,
        determinability=Determinability.AUTO,
        probe=present("environmental_impact", "power_consumption", "cooling"),
        rationale="Cryogenic operation is an operational and siting constraint.",
    ),
    MinimumElement(
        key="attestations",
        label="Attestations and Certifications",
        clause="8.5.9",
        tier=Tier.STANDARD,
        determinability=Determinability.AUTO,
        probe=present("attestations", "certifications"),
    ),
    MinimumElement(
        key="deployment_exposure",
        label="Quantum Exposure of the Consuming Deployment",
        clause="8.5.10",
        tier=Tier.CONTEXTUAL,
        determinability=Determinability.HUMAN,
        probe=never,
        rationale=(
            "Which of the consumer's own systems hold data whose confidentiality "
            "must outlast a cryptographically relevant quantum computer. A supplier "
            "cannot know the consumer's data retention horizon."
        ),
        consumer_action=(
            "Identify data whose confidentiality requirement exceeds the expected "
            "arrival of a cryptographically relevant quantum computer, and prioritise "
            "its migration first."
        ),
    ),
)

CATALOGUE = Catalogue(
    lane="qbom",
    clause_root="8.5",
    guideline_version=settings.GUIDELINE_VERSION,
    elements=ELEMENTS,
)
