"""HBOM minimum elements — CERT-In s.10.2, Table 11.

**This lane's data is procurement data, and that changes what a verdict means.**
Manufacturer location, manufacturing date, serial number, technology node,
warranty and AMC, test results and compliance declarations come from asset
registers, purchase records and delivery documentation — not from a scanner. No
tool can derive them, and no supplier "forgot to run cdxgen".

So an absent HBOM field is a different kind of finding from an absent SBOM field.
An absent licence means a generator was not configured; an absent manufacturing
date means the purchase record was never captured, or was captured somewhere the
assessment cannot see. `SOURCE_NOTE` below is rendered on every HBOM section so a
reader can tell which claims rest on a scan and which on a purchase order (§11).

Table 11's final row carries subcomponent recursion — a server contains boards
contain chips — which `hardware_items.parent_item_id` models.
"""

from __future__ import annotations

from app.configs.envConfig import settings
from app.configs.jobTypes import Determinability, Tier
from app.services.catalogue.probes import never, present
from app.services.catalogue.types import Catalogue, MinimumElement

#: Rendered on every HBOM finding. The distinction is the point.
SOURCE_NOTE = (
    "Hardware BOM fields are procurement-sourced: they come from asset registers, "
    "purchase records and delivery documentation, not from scanning an artifact. "
    "An unmet field here means the record was not captured or was not supplied — "
    "it is not a tooling gap."
)

ANCHORED_CLAUSES: dict[str, str] = {
    # The HBOM-with-SBOM pairing the S9 firmwareInHbom rule cites.
    "firmware_version": "10.2.4",
}

ELEMENTS: tuple[MinimumElement, ...] = (
    MinimumElement(
        key="product_name",
        label="Product Name",
        clause="10.2(1)",
        tier=Tier.CRITICAL,
        determinability=Determinability.AUTO,
        probe=present("product_name", "name"),
    ),
    MinimumElement(
        key="model_number",
        label="Model Number",
        clause="10.2(2)",
        tier=Tier.CRITICAL,
        determinability=Determinability.AUTO,
        probe=present("model_number", "model"),
    ),
    MinimumElement(
        key="serial_number",
        label="Serial Number",
        clause="10.2(3)",
        tier=Tier.CRITICAL,
        determinability=Determinability.AUTO,
        probe=present("serial_number", "serial"),
        rationale=(
            "The only field that identifies a specific unit rather than a model. "
            "Recall and warranty both operate on it."
        ),
    ),
    MinimumElement(
        key="manufacturer",
        label="Manufacturer",
        clause="10.2(4)",
        tier=Tier.CRITICAL,
        determinability=Determinability.AUTO,
        probe=present("manufacturer", "maker"),
    ),
    MinimumElement(
        key="manufacturing_location",
        label="Manufacturing Location",
        clause="10.2(5)",
        tier=Tier.CRITICAL,
        determinability=Determinability.AUTO,
        probe=present("mfg_location", "manufacturing_location", "country_of_origin"),
        rationale=(
            "A supply-chain provenance question rather than a technical one, and "
            "the reason HBOM matters to a government procurement reader."
        ),
    ),
    MinimumElement(
        key="manufacturing_date",
        label="Manufacturing Date",
        clause="10.2(6)",
        tier=Tier.STANDARD,
        determinability=Determinability.AUTO,
        probe=present("mfg_date", "manufacturing_date"),
    ),
    MinimumElement(
        key="supplier_name",
        label="Supplier Name",
        clause="10.2(7)",
        tier=Tier.CRITICAL,
        determinability=Determinability.AUTO,
        probe=present("supplier_name", "supplier", "vendor"),
        rationale="Distinct from the manufacturer: the reseller is often neither.",
    ),
    MinimumElement(
        key="supplier_location",
        label="Supplier Location",
        clause="10.2(8)",
        tier=Tier.STANDARD,
        determinability=Determinability.AUTO,
        probe=present("supplier_location"),
    ),
    MinimumElement(
        key="technology_node",
        label="Technology Node",
        clause="10.2(9)",
        tier=Tier.CONTEXTUAL,
        determinability=Determinability.AUTO,
        probe=present("technology_node", "process_node"),
        rationale="Fabrication process geometry, where the component is a die.",
    ),
    MinimumElement(
        key="warranty_ref",
        label="Warranty / AMC Reference",
        clause="10.2(10)",
        tier=Tier.STANDARD,
        determinability=Determinability.AUTO,
        probe=present("warranty_ref", "warranty", "amc_ref"),
    ),
    MinimumElement(
        key="test_results",
        label="Test Results",
        clause="10.2(11)",
        tier=Tier.STANDARD,
        determinability=Determinability.AUTO,
        probe=present("test_results", "test_report"),
    ),
    MinimumElement(
        key="compliance_declarations",
        label="Compliance Declarations",
        clause="10.2(12)",
        tier=Tier.CRITICAL,
        determinability=Determinability.AUTO,
        probe=present("compliance_decls", "compliance", "certifications"),
        rationale="BIS, CE, FCC and the like — declared on delivery documentation.",
    ),
    MinimumElement(
        key="firmware_version",
        label="Firmware Version",
        clause="10.2.4",
        tier=Tier.CRITICAL,
        determinability=Determinability.AUTO,
        probe=present("firmware_version", "firmware"),
        rationale=(
            "s.10.2.4 makes the HBOM-with-SBOM pairing explicit. A hardware item "
            "whose declared firmware has no SBOM coverage has an unassessed "
            "firmware supply chain — the S9 firmwareInHbom finding."
        ),
    ),
    MinimumElement(
        key="subcomponents",
        label="Subcomponents",
        clause="10.2(13)",
        tier=Tier.STANDARD,
        determinability=Determinability.AUTO,
        probe=present("subcomponents", "parent_item_id", "children"),
        rationale=(
            "Table 11's final row: a server contains boards contain chips. "
            "Recursion is modelled by hardware_items.parent_item_id."
        ),
    ),
    MinimumElement(
        key="deployment_criticality",
        label="Deployment Criticality and Siting",
        clause="10.2(14)",
        tier=Tier.CONTEXTUAL,
        determinability=Determinability.HUMAN,
        probe=never,
        rationale=(
            "Where the hardware sits in the consuming estate and how critical it "
            "is there. The same switch model is core in one rack and spare in "
            "another; a supplier cannot know which."
        ),
        consumer_action=(
            "Record each item's siting and criticality in your own asset register, "
            "and rate it against your continuity requirements."
        ),
    ),
)

CATALOGUE = Catalogue(
    lane="hbom",
    clause_root="10.2",
    guideline_version=settings.GUIDELINE_VERSION,
    elements=ELEMENTS,
)
