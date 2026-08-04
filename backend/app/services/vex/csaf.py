"""CSAF 2.0 export.

CSAF is how a VEX statement leaves this system and is consumed by somebody
else's vulnerability management. The mapping matters more than it looks: CSAF's
product_status groups are the interoperable form of rec. 7.1.6's four statuses,
and getting the mapping wrong means a consumer's tooling reads "not affected" as
"affected" or drops the statement entirely.

`known_not_affected` is CSAF's name for `not_affected`, and `fixed` maps to
`fixed`. `under_investigation` has a direct CSAF group. Only `affected` needs
care: CSAF distinguishes `known_affected` from `first_affected`/`last_affected`
ranges, and without a version range the only honest mapping is `known_affected`.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from app.services.vex.authoring import VexStatement, VexStatus

CSAF_VERSION = "2.0"

#: rec. 7.1.6 status → CSAF product_status group.
STATUS_TO_CSAF: dict[VexStatus, str] = {
    VexStatus.NOT_AFFECTED: "known_not_affected",
    VexStatus.AFFECTED: "known_affected",
    VexStatus.FIXED: "fixed",
    VexStatus.UNDER_INVESTIGATION: "under_investigation",
}

#: CSAF requires a justification label on known_not_affected. Ours are written
#: prose, so the label is the machine-readable summary and the prose goes in
#: `details` — dropping the prose to fit a label would lose the analyst's actual
#: reasoning, which is the part a reader needs.
DEFAULT_NOT_AFFECTED_LABEL = "vulnerable_code_not_present"


class CsafExportError(ValueError):
    """The statement cannot be represented as a conformant CSAF document."""


def _product_id(statement: VexStatement) -> str:
    return statement.component_ref or "PRODUCT-1"


def to_csaf(
    statements: list[VexStatement],
    *,
    document_title: str,
    publisher_name: str,
    publisher_namespace: str,
    tracking_id: str,
) -> dict[str, Any]:
    """Build a CSAF 2.0 VEX document from a set of statements."""
    if not statements:
        raise CsafExportError(
            "a CSAF document requires at least one VEX statement; an empty advisory "
            "asserts nothing and would be read as 'nothing applies'"
        )

    products: dict[str, dict[str, Any]] = {}
    vulnerabilities: list[dict[str, Any]] = []

    for statement in statements:
        product_id = _product_id(statement)
        products.setdefault(
            product_id,
            {"name": product_id, "product_id": product_id},
        )

        group = STATUS_TO_CSAF[statement.status]
        entry: dict[str, Any] = {
            "cve": statement.cve_id,
            "product_status": {group: [product_id]},
        }

        if statement.justification:
            entry["notes"] = [
                {
                    "category": "other",
                    "title": "Justification",
                    "text": statement.justification,
                }
            ]
        if statement.status is VexStatus.NOT_AFFECTED:
            # CSAF mandates a machine-readable flag alongside the prose.
            entry["flags"] = [
                {"label": DEFAULT_NOT_AFFECTED_LABEL, "product_ids": [product_id]}
            ]
        if statement.evidence_refs:
            entry["references"] = [
                {"category": "external", "summary": "Evidence", "url": url}
                for url in statement.evidence_refs
                if url
            ]
        vulnerabilities.append(entry)

    return {
        "document": {
            "category": "csaf_vex",
            "csaf_version": CSAF_VERSION,
            "title": document_title,
            "publisher": {
                "category": "vendor",
                "name": publisher_name,
                "namespace": publisher_namespace,
            },
            "tracking": {
                "id": tracking_id,
                "status": "final",
                "version": "1",
                "initial_release_date": datetime.now(UTC).isoformat(),
                "current_release_date": datetime.now(UTC).isoformat(),
                "revision_history": [
                    {
                        "number": "1",
                        "date": datetime.now(UTC).isoformat(),
                        "summary": "Initial release",
                    }
                ],
            },
        },
        "product_tree": {"full_product_names": list(products.values())},
        "vulnerabilities": vulnerabilities,
    }


def validate(document: dict[str, Any]) -> list[str]:
    """Structural validation against CSAF 2.0's required fields.

    Returns problems rather than raising, so an exporter can report every defect
    at once. Not a full JSON-Schema validation — that needs the published schema
    — and the difference is stated rather than implied.
    """
    problems: list[str] = []

    document_section = document.get("document") or {}
    for required in ("category", "csaf_version", "title", "publisher", "tracking"):
        if not document_section.get(required):
            problems.append(f"document.{required} is required by CSAF 2.0")

    if document_section.get("csaf_version") != CSAF_VERSION:
        problems.append(f"document.csaf_version must be {CSAF_VERSION!r}")
    if document_section.get("category") != "csaf_vex":
        problems.append("document.category must be 'csaf_vex' for a VEX document")

    tracking = document_section.get("tracking") or {}
    for required in ("id", "status", "version", "initial_release_date"):
        if not tracking.get(required):
            problems.append(f"document.tracking.{required} is required")

    if not (document.get("product_tree") or {}).get("full_product_names"):
        problems.append("product_tree.full_product_names must name at least one product")

    vulnerabilities = document.get("vulnerabilities") or []
    if not vulnerabilities:
        problems.append("vulnerabilities must carry at least one entry")

    valid_groups = set(STATUS_TO_CSAF.values())
    for index, entry in enumerate(vulnerabilities):
        if not entry.get("cve"):
            problems.append(f"vulnerabilities[{index}].cve is required")
        status = entry.get("product_status") or {}
        if not status:
            problems.append(f"vulnerabilities[{index}].product_status is required")
        for group in status:
            if group not in valid_groups:
                problems.append(
                    f"vulnerabilities[{index}].product_status.{group} is not a CSAF "
                    f"group; valid groups are {sorted(valid_groups)}"
                )

    return problems
