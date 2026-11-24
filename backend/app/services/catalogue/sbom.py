"""SBOM minimum elements — CERT-In s.4.2, guideline v2.0 (09.07.2025).

**Clause provenance.** s.4.2 of the guideline numbers its 21 data fields 1 to 21, so
every clause here is the guideline's own number. All 21 were checked against the
published PDF (v2.0, 09.07.2025, s.4.2 and Table 5) and are anchored. The earlier
catalogue had 15 to 20 in the wrong order, no "Comments or Notes" (4.2(15)), and an
extra "Unique Identifier of the Component" that the guideline does not list.

``tests/test_catalogue.py`` asserts every anchor, and ``tests/test_guideline_fidelity.py``
compares the whole catalogue with the guideline's list, so a careless edit fails the build.
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
    "component_name": "4.2(1)",
    "version": "4.2(2)",
    "description": "4.2(3)",
    "supplier_name": "4.2(4)",
    "license": "4.2(5)",
    "origin": "4.2(6)",
    "dependencies": "4.2(7)",
    "vulnerabilities": "4.2(8)",
    "patch_status": "4.2(9)",
    "release_date": "4.2(10)",
    "end_of_life": "4.2(11)",
    "criticality": "4.2(12)",
    "usage_restrictions": "4.2(13)",
    "checksums": "4.2(14)",
    "comments_notes": "4.2(15)",
    "author_name": "4.2(16)",
    "timestamp": "4.2(17)",
    "executable_property": "4.2(18)",
    "archive_property": "4.2(19)",
    "structured_property": "4.2(20)",
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
        key="comments_notes",
        label="Comments or Notes",
        clause="4.2(15)",
        tier=Tier.CONTEXTUAL,
        determinability=Determinability.AUTO,
        probe=present("comment"),
        rationale=(
            "Notes or annotations about the component or its inclusion in the SBOM: "
            "CycloneDX `annotations` about the component, SPDX `comment` or "
            "`annotations`, or tag-value `PackageComment`."
        ),
    ),
    MinimumElement(
        key="author_name",
        label="Author / Originator Name",
        clause="4.2(16)",
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
        clause="4.2(17)",
        tier=Tier.STANDARD,
        determinability=Determinability.AUTO,
        probe=present("timestamp", "doc_timestamp"),
        scope=Scope.DOCUMENT,
        rationale="When the SBOM was generated — a property of the document.",
    ),
    MinimumElement(
        key="executable_property",
        label="Executable Property",
        clause="4.2(18)",
        tier=Tier.CONTEXTUAL,
        determinability=Determinability.AUTO,
        probe=present("executable", "properties.executable"),
    ),
    MinimumElement(
        key="archive_property",
        label="Archive Property",
        clause="4.2(19)",
        tier=Tier.CONTEXTUAL,
        determinability=Determinability.AUTO,
        probe=present("archive", "properties.archive"),
    ),
    MinimumElement(
        key="structured_property",
        label="Structured Property",
        clause="4.2(20)",
        tier=Tier.CONTEXTUAL,
        determinability=Determinability.AUTO,
        probe=present("structured", "properties.structured"),
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
