"""SBOM minimum elements — CERT-In s.4.2, guideline v2.0 (09.07.2025).

**Clause provenance.** Eight positions are anchored directly by the specification
in ``BOM_AUTOMATION_SPRINTS.md``: 4.2(5) Licence, 4.2(8) Vulnerabilities, 4.2(9)
Patch Status, 4.2(10) Release Date, 4.2(11) End-of-Life, 4.2(12) Criticality,
4.2(13) Usage Restrictions and 4.2(21) CERT-In Unique Identifier. The remaining
thirteen ordinals are encoded from the s.4.2 table and carry
``audit=Audit.PROVISIONAL`` until an assessor re-derives them from the published
PDF clause by clause — that is the S20 catalogue audit, and it is a gate, not a
formality. One wrong clause discredits every assessment issued (§11).

``tests/test_catalogue.py`` asserts the eight anchors so a careless edit to this
file fails the build.
"""

from __future__ import annotations

from enum import StrEnum

from app.configs.envConfig import settings
from app.configs.jobTypes import Determinability, Tier
from app.services.catalogue.probes import all_present, never, present
from app.services.catalogue.types import Catalogue, MinimumElement, Scope


class Audit(StrEnum):
    #: Clause number confirmed against the published guideline.
    ANCHORED = "anchored"
    #: Encoded from the table; ordinal not yet confirmed against the PDF (S20).
    PROVISIONAL = "provisional"


#: Keys whose clause numbers are confirmed. Kept beside the catalogue so the test
#: and the S20 audit read the same list.
ANCHORED_CLAUSES: dict[str, str] = {
    "license": "4.2(5)",
    "vulnerabilities": "4.2(8)",
    "patch_status": "4.2(9)",
    "release_date": "4.2(10)",
    "end_of_life": "4.2(11)",
    "criticality": "4.2(12)",
    "usage_restrictions": "4.2(13)",
    "certin_identifier": "4.2(21)",
}

ELEMENTS: tuple[MinimumElement, ...] = (
    MinimumElement(
        key="component_name",
        label="Component Name",
        clause="4.2(1)",
        tier=Tier.CRITICAL,
        determinability=Determinability.AUTO,
        probe=present("name"),
    ),
    MinimumElement(
        key="version",
        label="Version of the Component",
        clause="4.2(2)",
        tier=Tier.CRITICAL,
        determinability=Determinability.AUTO,
        probe=present("version"),
        rationale=(
            "A component without a version cannot be matched to a CVE, a licence "
            "obligation or an end-of-life date, which is every purpose s.4.2 exists to serve."
        ),
    ),
    MinimumElement(
        key="description",
        label="Component Description",
        clause="4.2(3)",
        tier=Tier.CONTEXTUAL,
        determinability=Determinability.AUTO,
        probe=present("description"),
    ),
    MinimumElement(
        key="supplier_name",
        label="Supplier Name",
        clause="4.2(4)",
        tier=Tier.CRITICAL,
        determinability=Determinability.AUTO,
        probe=present("supplier_raw", "supplier.name", "publisher"),
        rationale="The organisation the CERT-In unique identifier of 4.2(21) is built from.",
    ),
    MinimumElement(
        key="license",
        label="Licence",
        clause="4.2(5)",
        tier=Tier.CRITICAL,
        determinability=Determinability.AUTO,
        probe=present("license_expr", "licenses"),
        rationale=(
            "Scored as coverage across the component set, never as a document-level "
            "yes/no: licences on 12 of 400 components has not met this clause."
        ),
    ),
    MinimumElement(
        key="origin",
        label="Origin / Source Repository",
        clause="4.2(6)",
        tier=Tier.STANDARD,
        determinability=Determinability.AUTO,
        probe=present("origin", "externalReferences"),
    ),
    MinimumElement(
        key="dependencies",
        label="Dependencies",
        clause="4.2(7)",
        tier=Tier.CRITICAL,
        determinability=Determinability.AUTO,
        probe=present("dependencies", "dependsOn"),
        rationale=(
            "A flat component list without a dependency graph cannot answer the "
            "transitive-exposure question a consumer asks after a disclosure."
        ),
    ),
    MinimumElement(
        key="vulnerabilities",
        label="Known Unknowns / Vulnerabilities",
        clause="4.2(8)",
        tier=Tier.STANDARD,
        determinability=Determinability.ENRICH,
        probe=present("vulnerabilities"),
        rationale=(
            "Enriched from NVD, CISA KEV and CERT-In advisories at S10 where the "
            "supplier did not declare it; the source is recorded so a reviewer can "
            "see the finding was not supplier-declared."
        ),
    ),
    MinimumElement(
        key="patch_status",
        label="Patch Status",
        clause="4.2(9)",
        tier=Tier.STANDARD,
        determinability=Determinability.ENRICH,
        probe=present("patch_status"),
    ),
    MinimumElement(
        key="release_date",
        label="Release Date",
        clause="4.2(10)",
        tier=Tier.STANDARD,
        determinability=Determinability.ENRICH,
        probe=present("release_date"),
    ),
    MinimumElement(
        key="end_of_life",
        label="End-of-Life Date",
        clause="4.2(11)",
        tier=Tier.STANDARD,
        determinability=Determinability.ENRICH,
        probe=present("eol_date", "end_of_life"),
        rationale=(
            "Resolved from lifecycle feeds first; the S10 agent fills only what the "
            "feeds miss, and reports unresolved rather than a plausible-looking date."
        ),
    ),
    MinimumElement(
        key="criticality",
        label="Criticality",
        clause="4.2(12)",
        tier=Tier.CONTEXTUAL,
        determinability=Determinability.HUMAN,
        probe=never,
        rationale=(
            "Criticality is relative to the consuming deployment. The same library is "
            "critical in an authentication path and incidental in a build script; a "
            "supplier shipping to two hundred consumers could not have supplied this."
        ),
        consumer_action=(
            "Rate each component against your own deployment and record the rating in "
            "your asset register."
        ),
    ),
    MinimumElement(
        key="usage_restrictions",
        label="Usage Restrictions",
        clause="4.2(13)",
        tier=Tier.CONTEXTUAL,
        determinability=Determinability.HUMAN,
        probe=never,
        rationale=(
            "A legal determination about the consumer's own use, not a property of "
            "the artifact."
        ),
        consumer_action=(
            "Have counsel review the declared licences against your intended use and "
            "distribution model."
        ),
    ),
    MinimumElement(
        key="checksums",
        label="Cryptographic Hash of the Component",
        clause="4.2(14)",
        tier=Tier.STANDARD,
        determinability=Determinability.AUTO,
        probe=present("checksums", "hashes"),
    ),
    MinimumElement(
        key="executable_property",
        label="Executable Property",
        clause="4.2(15)",
        tier=Tier.CONTEXTUAL,
        determinability=Determinability.AUTO,
        probe=present("executable", "properties.executable"),
    ),
    MinimumElement(
        key="archive_property",
        label="Archive Property",
        clause="4.2(16)",
        tier=Tier.CONTEXTUAL,
        determinability=Determinability.AUTO,
        probe=present("archive", "properties.archive"),
    ),
    MinimumElement(
        key="structured_property",
        label="Structured Property",
        clause="4.2(17)",
        tier=Tier.CONTEXTUAL,
        determinability=Determinability.AUTO,
        probe=present("structured", "properties.structured"),
    ),
    MinimumElement(
        key="component_identifier",
        label="Unique Identifier of the Component",
        clause="4.2(18)",
        tier=Tier.CRITICAL,
        determinability=Determinability.AUTO,
        probe=present("purl", "cpe", "bom_ref"),
    ),
    MinimumElement(
        key="author_name",
        label="Author / Originator Name",
        clause="4.2(19)",
        tier=Tier.STANDARD,
        determinability=Determinability.AUTO,
        probe=present("author", "originator", "doc_author"),
        scope=Scope.DOCUMENT,
        rationale=(
            "The author of the SBOM, distinct from the supplier of 4.2(4). A "
            "property of the document, so it is scored once per document rather "
            "than per component."
        ),
    ),
    MinimumElement(
        key="timestamp",
        label="Timestamp",
        clause="4.2(20)",
        tier=Tier.STANDARD,
        determinability=Determinability.AUTO,
        probe=present("timestamp", "doc_timestamp"),
        scope=Scope.DOCUMENT,
        rationale="When the SBOM was generated — a property of the document.",
    ),
    MinimumElement(
        key="certin_identifier",
        label="CERT-In Unique Identifier",
        clause="4.2(21)",
        tier=Tier.CRITICAL,
        determinability=Determinability.AUTO,
        probe=all_present("certin_id", "supplier_org"),
        rationale=(
            "Table 3 mandates pkg:supplier/OrganizationName/Component@Version. "
            "`supplier` is not a registered PURL type, so no generator emits this; "
            "S11 resolves it from the curated registry and reports unresolved rather "
            "than emitting a plausible-looking wrong identifier."
        ),
    ),
)

#: Elements whose clause ordinal still needs the S20 PDF re-derivation.
AUDIT_STATUS: dict[str, Audit] = {
    element.key: (Audit.ANCHORED if element.key in ANCHORED_CLAUSES else Audit.PROVISIONAL)
    for element in ELEMENTS
}

CATALOGUE = Catalogue(
    lane="sbom",
    clause_root="4.2",
    guideline_version=settings.GUIDELINE_VERSION,
    elements=ELEMENTS,
)
