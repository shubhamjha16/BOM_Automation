"""CBOM minimum elements: CERT-In s.8.3, Table 9, guideline v2.0 (09.07.2025).

Table 9 (Minimum Elements pertaining to Cryptographic Asset) lists 30 rows by name, grouped by
cryptographic asset type (Algorithms 8, Keys 7, Protocols 5, Certificates 10), and numbers none of
them. Each element is therefore cited by
section, table, group and name (``8.3 Table 9: Keys - Creation Date``), because the same name
(Name, Asset Type, OID) recurs in several groups, and the elements are declared in the order
the table gives them. ``tests/test_guideline_fidelity.py`` compares this catalogue with the
table, read from the PDF and checked against its page images. All 30 are anchored.

The earlier catalogue had 20 elements and cited ``8.4.1.2`` to ``8.4.4.1``. Those numbers are
the guideline's *recommendations* (s.8.4.1 is a numbered list of rules about supplying BOMs),
not its minimum elements, which are in s.8.3. It lacked ten rows (the Name and Asset Type of
keys, protocols and certificates, the algorithm List, the protocol OID, Subject Public Key
Reference and Certificate Extension), had one element standing for both Not Valid Before and
Not Valid After while checking only After, and held a Deployment Context check the table does
not list.

Seven elements are judgement calls, because the guideline defines each in one sentence and gives
no tier: the algorithm List, and the Name and Asset Type rows of keys, protocols and certificates
(which are scored at the lowest tier where an asset's own type makes them trivially met).

**A CBOM is four kinds of thing in one document**, and that shapes the scoring.
Table 9 defines a Cryptographic Asset as an algorithm, a key, a protocol or a
certificate, and the fields that matter differ completely between them: a
classical security level is meaningful for an algorithm and meaningless for a
certificate; a validity window is the opposite. Scoring every element against
every asset would report a certificate as missing its cipher mode, which is not a
gap; it is a category error.

So each element declares the asset types it applies to, and coverage is measured
only across the assets it could apply to. That is a departure from the SBOM lane,
where every element applies to every component, and it is the reason
`probes.applies_to` exists.
"""

from __future__ import annotations

from app.configs.envConfig import settings
from app.configs.jobTypes import Determinability, Tier
from app.services.catalogue.probes import for_asset_types, present
from app.services.catalogue.types import Catalogue, MinimumElement, table_clause

#: The asset types each group of Table 9 governs. CycloneDX 1.6 calls a key a
#: ``related-crypto-material`` asset.
ALGORITHM = {"algorithm"}
KEY = {"key", "related-crypto-material"}
PROTOCOL = {"protocol"}
CERTIFICATE = {"certificate"}
#: Assets that declare no type at all (``asset_type_of`` returns an empty string).
ALGORITHM_OR_UNTYPED = ALGORITHM | {""}


def _clause(group: str, name: str) -> str:
    return table_clause("8.3", 9, name, group)


#: Every element is checked against Table 9. Kept beside the catalogue so the test and the
#: audit read the same list.
ANCHORED_CLAUSES: dict[str, str] = {
    "algorithm_name": _clause("Algorithms", "Name"),
    "algorithm_asset_type": _clause("Algorithms", "Asset Type"),
    "primitive": _clause("Algorithms", "Primitive"),
    "mode": _clause("Algorithms", "Mode"),
    "crypto_functions": _clause("Algorithms", "Crypto Functions"),
    "classical_security_level": _clause("Algorithms", "Classical security level"),
    "oid": _clause("Algorithms", "OID"),
    "algorithm_list": _clause("Algorithms", "List"),
    "key_name": _clause("Keys", "Name"),
    "key_asset_type": _clause("Keys", "Asset Type"),
    "key_id": _clause("Keys", "id"),
    "key_state": _clause("Keys", "state"),
    "key_size": _clause("Keys", "size"),
    "key_creation_date": _clause("Keys", "Creation Date"),
    "key_activation_date": _clause("Keys", "Activation Date"),
    "protocol_name": _clause("Protocols", "Name"),
    "protocol_asset_type": _clause("Protocols", "Asset Type"),
    "protocol_version": _clause("Protocols", "Version"),
    "cipher_suites": _clause("Protocols", "Cipher Suites"),
    "protocol_oid": _clause("Protocols", "OID"),
    "certificate_name": _clause("Certificates", "Name"),
    "certificate_asset_type": _clause("Certificates", "Asset Type"),
    "cert_subject": _clause("Certificates", "Subject Name"),
    "cert_issuer": _clause("Certificates", "Issuer Name"),
    "cert_not_valid_before": _clause("Certificates", "Not Valid Before"),
    "cert_not_valid_after": _clause("Certificates", "Not Valid After"),
    "cert_signature_algorithm": _clause("Certificates", "Signature Algorithm Reference"),
    "cert_subject_public_key": _clause("Certificates", "Subject Public Key Reference"),
    "cert_format": _clause("Certificates", "Certificate Format"),
    "cert_extension": _clause("Certificates", "Certificate Extension"),
}

ELEMENTS: tuple[MinimumElement, ...] = (
    MinimumElement(
        key="algorithm_name",
        label="Algorithms - Name",
        clause=ANCHORED_CLAUSES["algorithm_name"],
        tier=Tier.CRITICAL,
        determinability=Determinability.AUTO,
        probe=for_asset_types(ALGORITHM, present("name", "asset_name")),
    ),
    MinimumElement(
        key="algorithm_asset_type",
        label="Algorithms - Asset Type",
        clause=ANCHORED_CLAUSES["algorithm_asset_type"],
        tier=Tier.CRITICAL,
        determinability=Determinability.AUTO,
        probe=for_asset_types(
            ALGORITHM_OR_UNTYPED,
            present("asset_type", "cryptoProperties.assetType"),
        ),
        rationale=(
            "Table 9's four asset types. Without it the remaining fields cannot be interpreted: a "
            "'size' is a key length or a certificate serial depending entirely on this. This is "
            "the"
            "one Asset Type row that also counts assets declaring no type at all, so a missing "
            "type"
            "is a gap and is counted once; the other three Asset Type rows cover only assets of "
            "their own type."
        ),
    ),
    MinimumElement(
        key="primitive",
        label="Algorithms - Primitive",
        clause=ANCHORED_CLAUSES["primitive"],
        tier=Tier.CRITICAL,
        determinability=Determinability.AUTO,
        probe=for_asset_types(ALGORITHM, present("primitive", "algorithmProperties.primitive")),
        rationale=(
            'Signature, encryption, hash or key-exchange: what the algorithm is for.'
        ),
    ),
    MinimumElement(
        key="mode",
        label="Algorithms - Mode",
        clause=ANCHORED_CLAUSES["mode"],
        tier=Tier.STANDARD,
        determinability=Determinability.AUTO,
        probe=for_asset_types(ALGORITHM, present("mode", "algorithmProperties.mode")),
        rationale=(
            'AES-GCM and AES-ECB are the same primitive and not the same risk.'
        ),
    ),
    MinimumElement(
        key="crypto_functions",
        label="Algorithms - Crypto Functions",
        clause=ANCHORED_CLAUSES["crypto_functions"],
        tier=Tier.STANDARD,
        determinability=Determinability.AUTO,
        probe=for_asset_types(
            ALGORITHM,
            present("crypto_functions", "algorithmProperties.cryptoFunctions"),
        ),
    ),
    MinimumElement(
        key="classical_security_level",
        label="Algorithms - Classical security level",
        clause=ANCHORED_CLAUSES["classical_security_level"],
        tier=Tier.CRITICAL,
        determinability=Determinability.AUTO,
        probe=for_asset_types(
            ALGORITHM,
            present("classical_security_level", "algorithmProperties.classicalSecurityLevel"),
        ),
        rationale=(
            "The strength claim. Without it 'RSA' could be 1024 or 4096 bits, which is the "
            "difference between a finding and a control."
        ),
    ),
    MinimumElement(
        key="oid",
        label="Algorithms - OID",
        clause=ANCHORED_CLAUSES["oid"],
        tier=Tier.STANDARD,
        determinability=Determinability.AUTO,
        probe=for_asset_types(ALGORITHM, present("oid", "cryptoProperties.oid")),
        rationale=(
            'The unambiguous identifier; algorithm names vary between vendors.'
        ),
    ),
    MinimumElement(
        key="algorithm_list",
        label="Algorithms - List",
        clause=ANCHORED_CLAUSES["algorithm_list"],
        tier=Tier.CONTEXTUAL,
        determinability=Determinability.AUTO,
        probe=for_asset_types(ALGORITHM, present("algorithm_list", "algorithms", "name")),
        rationale=(
            "Table 9's List row asks for the cryptographic algorithms the system employs. Each "
            "algorithm asset is an entry of that list, so an algorithm that is declared by name "
            "reads as listed; the guideline gives no finer test."
        ),
    ),
    MinimumElement(
        key="key_name",
        label="Keys - Name",
        clause=ANCHORED_CLAUSES["key_name"],
        tier=Tier.STANDARD,
        determinability=Determinability.AUTO,
        probe=for_asset_types(KEY, present("name", "key_name")),
    ),
    MinimumElement(
        key="key_asset_type",
        label="Keys - Asset Type",
        clause=ANCHORED_CLAUSES["key_asset_type"],
        tier=Tier.CONTEXTUAL,
        determinability=Determinability.AUTO,
        probe=for_asset_types(KEY, present("asset_type", "cryptoProperties.assetType")),
    ),
    MinimumElement(
        key="key_id",
        label="Keys - id",
        clause=ANCHORED_CLAUSES["key_id"],
        tier=Tier.CRITICAL,
        determinability=Determinability.AUTO,
        probe=for_asset_types(KEY, present("key_id", "id")),
    ),
    MinimumElement(
        key="key_state",
        label="Keys - state",
        clause=ANCHORED_CLAUSES["key_state"],
        tier=Tier.STANDARD,
        determinability=Determinability.AUTO,
        probe=for_asset_types(KEY, present("state", "key_state")),
        rationale=(
            'Pre-activation, active, suspended, deactivated, compromised, destroyed.'
        ),
    ),
    MinimumElement(
        key="key_size",
        label="Keys - size",
        clause=ANCHORED_CLAUSES["key_size"],
        tier=Tier.CRITICAL,
        determinability=Determinability.AUTO,
        probe=for_asset_types(KEY, present("size", "key_size")),
    ),
    MinimumElement(
        key="key_creation_date",
        label="Keys - Creation Date",
        clause=ANCHORED_CLAUSES["key_creation_date"],
        tier=Tier.STANDARD,
        determinability=Determinability.AUTO,
        probe=for_asset_types(KEY, present("creation_date", "creationDate")),
    ),
    MinimumElement(
        key="key_activation_date",
        label="Keys - Activation Date",
        clause=ANCHORED_CLAUSES["key_activation_date"],
        tier=Tier.CONTEXTUAL,
        determinability=Determinability.AUTO,
        probe=for_asset_types(KEY, present("activation_date", "activationDate")),
    ),
    MinimumElement(
        key="protocol_name",
        label="Protocols - Name",
        clause=ANCHORED_CLAUSES["protocol_name"],
        tier=Tier.STANDARD,
        determinability=Determinability.AUTO,
        probe=for_asset_types(PROTOCOL, present("name", "protocol_name")),
    ),
    MinimumElement(
        key="protocol_asset_type",
        label="Protocols - Asset Type",
        clause=ANCHORED_CLAUSES["protocol_asset_type"],
        tier=Tier.CONTEXTUAL,
        determinability=Determinability.AUTO,
        probe=for_asset_types(PROTOCOL, present("asset_type", "cryptoProperties.assetType")),
    ),
    MinimumElement(
        key="protocol_version",
        label="Protocols - Version",
        clause=ANCHORED_CLAUSES["protocol_version"],
        tier=Tier.CRITICAL,
        determinability=Determinability.AUTO,
        probe=for_asset_types(PROTOCOL, present("version", "protocolProperties.version")),
        rationale=(
            'TLS 1.0 and TLS 1.3 are the same protocol and not the same posture.'
        ),
    ),
    MinimumElement(
        key="cipher_suites",
        label="Protocols - Cipher Suites",
        clause=ANCHORED_CLAUSES["cipher_suites"],
        tier=Tier.CRITICAL,
        determinability=Determinability.AUTO,
        probe=for_asset_types(
            PROTOCOL,
            present("cipher_suites", "protocolProperties.cipherSuites"),
        ),
        rationale=(
            'Checked at document level too: a declared deprecated suite is flagged citing this '
            'element regardless of how many healthy suites accompany it.'
        ),
    ),
    MinimumElement(
        key="protocol_oid",
        label="Protocols - OID",
        clause=ANCHORED_CLAUSES["protocol_oid"],
        tier=Tier.STANDARD,
        determinability=Determinability.AUTO,
        probe=for_asset_types(PROTOCOL, present("oid", "cryptoProperties.oid")),
    ),
    MinimumElement(
        key="certificate_name",
        label="Certificates - Name",
        clause=ANCHORED_CLAUSES["certificate_name"],
        tier=Tier.STANDARD,
        determinability=Determinability.AUTO,
        probe=for_asset_types(CERTIFICATE, present("name", "certificate_name")),
    ),
    MinimumElement(
        key="certificate_asset_type",
        label="Certificates - Asset Type",
        clause=ANCHORED_CLAUSES["certificate_asset_type"],
        tier=Tier.CONTEXTUAL,
        determinability=Determinability.AUTO,
        probe=for_asset_types(CERTIFICATE, present("asset_type", "cryptoProperties.assetType")),
    ),
    MinimumElement(
        key="cert_subject",
        label="Certificates - Subject Name",
        clause=ANCHORED_CLAUSES["cert_subject"],
        tier=Tier.CRITICAL,
        determinability=Determinability.AUTO,
        probe=for_asset_types(CERTIFICATE, present("subject", "certificateProperties.subjectName")),
    ),
    MinimumElement(
        key="cert_issuer",
        label="Certificates - Issuer Name",
        clause=ANCHORED_CLAUSES["cert_issuer"],
        tier=Tier.CRITICAL,
        determinability=Determinability.AUTO,
        probe=for_asset_types(CERTIFICATE, present("issuer", "certificateProperties.issuerName")),
    ),
    MinimumElement(
        key="cert_not_valid_before",
        label="Certificates - Not Valid Before",
        clause=ANCHORED_CLAUSES["cert_not_valid_before"],
        tier=Tier.STANDARD,
        determinability=Determinability.AUTO,
        probe=for_asset_types(
            CERTIFICATE,
            present("not_valid_before", "certificateProperties.notValidBefore"),
        ),
    ),
    MinimumElement(
        key="cert_not_valid_after",
        label="Certificates - Not Valid After",
        clause=ANCHORED_CLAUSES["cert_not_valid_after"],
        tier=Tier.CRITICAL,
        determinability=Determinability.AUTO,
        probe=for_asset_types(
            CERTIFICATE,
            present("not_valid_after", "certificateProperties.notValidAfter"),
        ),
        rationale=(
            'Also checked at document level: a certificate past Not Valid After is a finding, not '
            'merely a populated field.'
        ),
    ),
    MinimumElement(
        key="cert_signature_algorithm",
        label="Certificates - Signature Algorithm Reference",
        clause=ANCHORED_CLAUSES["cert_signature_algorithm"],
        tier=Tier.STANDARD,
        determinability=Determinability.AUTO,
        probe=for_asset_types(
            CERTIFICATE,
            present("signature_algorithm", "certificateProperties.signatureAlgorithmRef"),
        ),
    ),
    MinimumElement(
        key="cert_subject_public_key",
        label="Certificates - Subject Public Key Reference",
        clause=ANCHORED_CLAUSES["cert_subject_public_key"],
        tier=Tier.STANDARD,
        determinability=Determinability.AUTO,
        probe=for_asset_types(
            CERTIFICATE,
            present("subject_public_key", "certificateProperties.subjectPublicKeyRef"),
        ),
    ),
    MinimumElement(
        key="cert_format",
        label="Certificates - Certificate Format",
        clause=ANCHORED_CLAUSES["cert_format"],
        tier=Tier.CONTEXTUAL,
        determinability=Determinability.AUTO,
        probe=for_asset_types(
            CERTIFICATE,
            present("format", "certificateProperties.certificateFormat"),
        ),
    ),
    MinimumElement(
        key="cert_extension",
        label="Certificates - Certificate Extension",
        clause=ANCHORED_CLAUSES["cert_extension"],
        tier=Tier.CONTEXTUAL,
        determinability=Determinability.AUTO,
        probe=for_asset_types(
            CERTIFICATE,
            present("certificate_extension", "certificateProperties.certificateFileExtension"),
        ),
    ),
)

CATALOGUE = Catalogue(
    lane="cbom",
    clause_root="8.3",
    guideline_version=settings.GUIDELINE_VERSION,
    elements=ELEMENTS,
)
