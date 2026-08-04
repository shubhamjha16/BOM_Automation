"""CBOM minimum elements — CERT-In s.8.4, Tables 8 and 9.

**Clause provenance.** s.8.4.1.2 is anchored by the specification (the S9
`cryptoInSbom` rule cites it) and s.8.4.2.2 governs protocol configuration. The
per-element ordinals below are encoded from the Table 8/9 structure and remain
**provisional** pending the S20 catalogue audit, exactly as the SBOM lane's are.

**A CBOM is four kinds of thing in one document**, and that shapes the scoring.
Table 9 defines a Cryptographic Asset as an algorithm, a key, a protocol or a
certificate, and the fields that matter differ completely between them: a
classical security level is meaningful for an algorithm and meaningless for a
certificate; a validity window is the opposite. Scoring every element against
every asset would report a certificate as missing its cipher mode, which is not a
gap — it is a category error.

So each element declares the asset types it applies to, and coverage is measured
only across the assets it could apply to. That is a departure from the SBOM lane,
where every element applies to every component, and it is the reason
`probes.applies_to` exists.
"""

from __future__ import annotations

from app.configs.envConfig import settings
from app.configs.jobTypes import Determinability, Tier
from app.services.catalogue.probes import for_asset_types, present
from app.services.catalogue.types import Catalogue, MinimumElement

ANCHORED_CLAUSES: dict[str, str] = {
    # Cited by the S9 cryptoInSbom rule.
    "asset_name": "8.4.1.2",
}

ELEMENTS: tuple[MinimumElement, ...] = (
    # --- every asset ------------------------------------------------------
    MinimumElement(
        key="asset_name",
        label="Cryptographic Asset Name",
        clause="8.4.1.2",
        tier=Tier.CRITICAL,
        determinability=Determinability.AUTO,
        probe=present("name", "asset_name"),
    ),
    MinimumElement(
        key="asset_type",
        label="Asset Type (algorithm | key | protocol | certificate)",
        clause="8.4.1.3",
        tier=Tier.CRITICAL,
        determinability=Determinability.AUTO,
        probe=present("asset_type", "cryptoProperties.assetType"),
        rationale=(
            "Table 9's four asset types. Without it the remaining fields cannot be "
            "interpreted — a 'size' is a key length or a certificate serial "
            "depending entirely on this."
        ),
    ),
    # --- algorithms (Table 9) ---------------------------------------------
    MinimumElement(
        key="primitive",
        label="Cryptographic Primitive",
        clause="8.4.1.4",
        tier=Tier.CRITICAL,
        determinability=Determinability.AUTO,
        probe=for_asset_types({"algorithm"}, present("primitive", "algorithmProperties.primitive")),
        rationale="Signature, encryption, hash or key-exchange — what the algorithm is for.",
    ),
    MinimumElement(
        key="mode",
        label="Mode of Operation",
        clause="8.4.1.5",
        tier=Tier.STANDARD,
        determinability=Determinability.AUTO,
        probe=for_asset_types({"algorithm"}, present("mode", "algorithmProperties.mode")),
        rationale="AES-GCM and AES-ECB are the same primitive and not the same risk.",
    ),
    MinimumElement(
        key="crypto_functions",
        label="Cryptographic Functions",
        clause="8.4.1.6",
        tier=Tier.STANDARD,
        determinability=Determinability.AUTO,
        probe=for_asset_types(
            {"algorithm"}, present("crypto_functions", "algorithmProperties.cryptoFunctions")
        ),
    ),
    MinimumElement(
        key="classical_security_level",
        label="Classical Security Level",
        clause="8.4.1.7",
        tier=Tier.CRITICAL,
        determinability=Determinability.AUTO,
        probe=for_asset_types(
            {"algorithm"},
            present("classical_security_level", "algorithmProperties.classicalSecurityLevel"),
        ),
        rationale=(
            "The strength claim. Without it 'RSA' could be 1024 or 4096 bits, which "
            "is the difference between a finding and a control."
        ),
    ),
    MinimumElement(
        key="oid",
        label="Object Identifier (OID)",
        clause="8.4.1.8",
        tier=Tier.STANDARD,
        determinability=Determinability.AUTO,
        probe=for_asset_types({"algorithm"}, present("oid", "cryptoProperties.oid")),
        rationale="The unambiguous identifier; algorithm names vary between vendors.",
    ),
    # --- keys (Table 9) ----------------------------------------------------
    MinimumElement(
        key="key_id",
        label="Key Identifier",
        clause="8.4.1.9",
        tier=Tier.CRITICAL,
        determinability=Determinability.AUTO,
        probe=for_asset_types({"key", "related-crypto-material"}, present("key_id", "id")),
    ),
    MinimumElement(
        key="key_state",
        label="Key State",
        clause="8.4.1.10",
        tier=Tier.STANDARD,
        determinability=Determinability.AUTO,
        probe=for_asset_types({"key", "related-crypto-material"}, present("state", "key_state")),
        rationale="Pre-activation, active, suspended, deactivated, compromised, destroyed.",
    ),
    MinimumElement(
        key="key_size",
        label="Key Size",
        clause="8.4.1.11",
        tier=Tier.CRITICAL,
        determinability=Determinability.AUTO,
        probe=for_asset_types({"key", "related-crypto-material"}, present("size", "key_size")),
    ),
    MinimumElement(
        key="key_creation_date",
        label="Key Creation Date",
        clause="8.4.1.12",
        tier=Tier.STANDARD,
        determinability=Determinability.AUTO,
        probe=for_asset_types(
            {"key", "related-crypto-material"}, present("creation_date", "creationDate")
        ),
    ),
    MinimumElement(
        key="key_activation_date",
        label="Key Activation Date",
        clause="8.4.1.13",
        tier=Tier.CONTEXTUAL,
        determinability=Determinability.AUTO,
        probe=for_asset_types(
            {"key", "related-crypto-material"}, present("activation_date", "activationDate")
        ),
    ),
    # --- protocols (Table 9) -----------------------------------------------
    MinimumElement(
        key="protocol_version",
        label="Protocol Version",
        clause="8.4.2.1",
        tier=Tier.CRITICAL,
        determinability=Determinability.AUTO,
        probe=for_asset_types(
            {"protocol"}, present("version", "protocolProperties.version")
        ),
        rationale="TLS 1.0 and TLS 1.3 are the same protocol and not the same posture.",
    ),
    MinimumElement(
        key="cipher_suites",
        label="Cipher Suites",
        clause="8.4.2.2",
        tier=Tier.CRITICAL,
        determinability=Determinability.AUTO,
        probe=for_asset_types(
            {"protocol"}, present("cipher_suites", "protocolProperties.cipherSuites")
        ),
        rationale=(
            "Checked at document level too: a declared deprecated suite is flagged "
            "citing this clause regardless of how many healthy suites accompany it."
        ),
    ),
    # --- certificates (Table 9) --------------------------------------------
    MinimumElement(
        key="cert_subject",
        label="Certificate Subject",
        clause="8.4.3.1",
        tier=Tier.CRITICAL,
        determinability=Determinability.AUTO,
        probe=for_asset_types(
            {"certificate"}, present("subject", "certificateProperties.subjectName")
        ),
    ),
    MinimumElement(
        key="cert_issuer",
        label="Certificate Issuer",
        clause="8.4.3.2",
        tier=Tier.CRITICAL,
        determinability=Determinability.AUTO,
        probe=for_asset_types(
            {"certificate"}, present("issuer", "certificateProperties.issuerName")
        ),
    ),
    MinimumElement(
        key="cert_validity",
        label="Certificate Validity Window",
        clause="8.4.3.3",
        tier=Tier.CRITICAL,
        determinability=Determinability.AUTO,
        probe=for_asset_types(
            {"certificate"},
            present("not_valid_after", "certificateProperties.notValidAfter"),
        ),
        rationale=(
            "Also checked at document level: a certificate past Not Valid After is "
            "a finding, not merely a populated field."
        ),
    ),
    MinimumElement(
        key="cert_signature_algorithm",
        label="Certificate Signature Algorithm",
        clause="8.4.3.4",
        tier=Tier.STANDARD,
        determinability=Determinability.AUTO,
        probe=for_asset_types(
            {"certificate"},
            present("signature_algorithm", "certificateProperties.signatureAlgorithmRef"),
        ),
    ),
    MinimumElement(
        key="cert_format",
        label="Certificate Format",
        clause="8.4.3.5",
        tier=Tier.CONTEXTUAL,
        determinability=Determinability.AUTO,
        probe=for_asset_types(
            {"certificate"}, present("format", "certificateProperties.certificateFormat")
        ),
    ),
    # --- deployment context ------------------------------------------------
    MinimumElement(
        key="deployment_context",
        label="Deployment Context",
        clause="8.4.4.1",
        tier=Tier.CONTEXTUAL,
        determinability=Determinability.HUMAN,
        probe=present("never"),
        rationale=(
            "Where in the consuming deployment an asset is used, and how exposed it "
            "is. A supplier shipping a library cannot know which of their consumers "
            "terminates TLS at the edge and which does so internally."
        ),
        consumer_action=(
            "Record where each declared cryptographic asset is used in your own "
            "deployment and its exposure."
        ),
    ),
)

CATALOGUE = Catalogue(
    lane="cbom",
    clause_root="8.4",
    guideline_version=settings.GUIDELINE_VERSION,
    elements=ELEMENTS,
)
