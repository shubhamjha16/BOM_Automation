"""HBOM minimum elements: CERT-In s.10.3, Table 11, guideline v2.0 (09.07.2025).

**This lane's data is procurement data, and that changes what a verdict means.**
Manufacturer location, manufacturing date, serial number, technology node,
warranty and AMC, test results and compliance declarations come from asset
registers, purchase records and delivery documentation, not from a scanner. No
tool can derive them, and no supplier "forgot to run cdxgen".

So an absent HBOM field is a different kind of finding from an absent SBOM field.
An absent licence means a generator was not configured; an absent manufacturing
date means the purchase record was never captured, or was captured somewhere the
assessment cannot see. `SOURCE_NOTE` below is rendered on every HBOM section so a
reader can tell which claims rest on a scan and which on a purchase order (§11).

Table 11 lists 20 elements by name and numbers none of them, so each is cited by
section, table and name (``10.3 Table 11: Model Number``) and the elements are declared
in the order the table gives them. ``tests/test_guideline_fidelity.py`` compares this
catalogue with the table, read from the PDF and checked against its page images. The
table names "Supplier Information" and "Supplier Location" twice: first for the product
(the company that provided or sold it), then for a component (the company that supplied
it to the manufacturer of the larger product). Those four are told apart by a ``Product``
or ``Component`` group in the citation.

The earlier catalogue had 15 elements, cited the wrong section (10.2 is "Benefits of
HBOM"; the minimum elements are in 10.3), lacked seven of the table's rows (Product
Version, Product Details, Technical Specification, the component's Supplier Information
and Supplier Location, Power supply, License Information) and held two checks the table
does not list: Firmware Version and Deployment Criticality. Firmware version appears only
in the recommendations (10.4.1.4), and the S9 ``firmwareInHbom`` rule still reads it from
the register and cites s.10.2.4, which is the guideline's "Integration with SBOM" section.

Seven elements are judgement calls, because the guideline defines each in one sentence
and gives no tier: Product Version, Product Details, Technical Specification, the
component's Supplier Information and Supplier Location, Power supply and License
Information. The "component" rows are scored for every item in a register, because a
register lists each item it holds; the guideline gives no way to separate products from
components.

Table 11's final row carries subcomponent recursion (a server contains boards contain
chips), which `hardware_items.parent_item_id` models.
"""

from __future__ import annotations

from app.configs.envConfig import settings
from app.configs.jobTypes import Determinability, Tier
from app.services.catalogue.probes import present
from app.services.catalogue.types import Catalogue, MinimumElement, table_clause

#: Rendered on every HBOM finding. The distinction is the point.
SOURCE_NOTE = (
    "Hardware BOM fields are procurement-sourced: they come from asset registers, "
    "purchase records and delivery documentation, not from scanning an artifact. "
    "An unmet field here means the record was not captured or was not supplied — "
    "it is not a tooling gap."
)


def _clause(name: str, group: str | None = None) -> str:
    return table_clause("10.3", 11, name, group)


#: Every element is checked against Table 11. Kept beside the catalogue so the test and
#: the audit read the same list.
ANCHORED_CLAUSES: dict[str, str] = {
    "product_name": _clause("Product Name"),
    "product_version": _clause("Product Version"),
    "product_details": _clause("Product Details"),
    "warranty_ref": _clause("Warranty/AMC"),
    "manufacturer": _clause("Manufacturer Name"),
    "manufacturing_location": _clause("Manufacturer Location"),
    "manufacturing_date": _clause("Manufacturing Date"),
    "supplier_name": _clause("Supplier Information", "Product"),
    "supplier_location": _clause("Supplier Location", "Product"),
    "model_number": _clause("Model Number"),
    "serial_number": _clause("Serial Number"),
    "technical_specification": _clause("Technical Specification"),
    "component_supplier": _clause("Supplier Information", "Component"),
    "component_supplier_location": _clause("Supplier Location", "Component"),
    "technology_node": _clause("Technology Node"),
    "compliance_declarations": _clause("Compliance"),
    "power_supply": _clause("Power supply"),
    "license_info": _clause("License Information"),
    "test_results": _clause("Test Result"),
    "subcomponents": _clause("Sub-component"),
}

ELEMENTS: tuple[MinimumElement, ...] = (
    MinimumElement(
        key="product_name",
        label="Product Name",
        clause=ANCHORED_CLAUSES["product_name"],
        tier=Tier.CRITICAL,
        determinability=Determinability.AUTO,
        probe=present("product_name", "name"),
    ),
    MinimumElement(
        key="product_version",
        label="Product Version",
        clause=ANCHORED_CLAUSES["product_version"],
        tier=Tier.STANDARD,
        determinability=Determinability.AUTO,
        probe=present("product_version", "version"),
        rationale=(
            'The specific iteration or release number of the product.'
        ),
    ),
    MinimumElement(
        key="product_details",
        label="Product Details",
        clause=ANCHORED_CLAUSES["product_details"],
        tier=Tier.CONTEXTUAL,
        determinability=Determinability.AUTO,
        probe=present("product_details", "details"),
        rationale=(
            'Key specifications and features that describe the hardware.'
        ),
    ),
    MinimumElement(
        key="warranty_ref",
        label="Warranty/AMC",
        clause=ANCHORED_CLAUSES["warranty_ref"],
        tier=Tier.STANDARD,
        determinability=Determinability.AUTO,
        probe=present("warranty_ref", "warranty", "amc_ref"),
    ),
    MinimumElement(
        key="manufacturer",
        label="Manufacturer Name",
        clause=ANCHORED_CLAUSES["manufacturer"],
        tier=Tier.CRITICAL,
        determinability=Determinability.AUTO,
        probe=present("manufacturer", "maker"),
    ),
    MinimumElement(
        key="manufacturing_location",
        label="Manufacturer Location",
        clause=ANCHORED_CLAUSES["manufacturing_location"],
        tier=Tier.CRITICAL,
        determinability=Determinability.AUTO,
        probe=present("mfg_location", "manufacturing_location", "country_of_origin"),
        rationale=(
            'A supply-chain provenance question rather than a technical one, and the reason HBOM '
            'matters to a government procurement reader.'
        ),
    ),
    MinimumElement(
        key="manufacturing_date",
        label="Manufacturing Date",
        clause=ANCHORED_CLAUSES["manufacturing_date"],
        tier=Tier.STANDARD,
        determinability=Determinability.AUTO,
        probe=present("mfg_date", "manufacturing_date"),
    ),
    MinimumElement(
        key="supplier_name",
        label="Supplier Information (product)",
        clause=ANCHORED_CLAUSES["supplier_name"],
        tier=Tier.CRITICAL,
        determinability=Determinability.AUTO,
        probe=present("supplier_name", "supplier", "vendor"),
        rationale=(
            'Distinct from the manufacturer: the reseller is often neither.'
        ),
    ),
    MinimumElement(
        key="supplier_location",
        label="Supplier Location (product)",
        clause=ANCHORED_CLAUSES["supplier_location"],
        tier=Tier.STANDARD,
        determinability=Determinability.AUTO,
        probe=present("supplier_location"),
    ),
    MinimumElement(
        key="model_number",
        label="Model Number",
        clause=ANCHORED_CLAUSES["model_number"],
        tier=Tier.CRITICAL,
        determinability=Determinability.AUTO,
        probe=present("model_number", "model"),
    ),
    MinimumElement(
        key="serial_number",
        label="Serial Number",
        clause=ANCHORED_CLAUSES["serial_number"],
        tier=Tier.CRITICAL,
        determinability=Determinability.AUTO,
        probe=present("serial_number", "serial"),
        rationale=(
            'The only field that identifies a specific unit rather than a model. Recall and '
            'warranty both operate on it.'
        ),
    ),
    MinimumElement(
        key="technical_specification",
        label="Technical Specification",
        clause=ANCHORED_CLAUSES["technical_specification"],
        tier=Tier.STANDARD,
        determinability=Determinability.AUTO,
        probe=present("technical_specification", "specification"),
        rationale=(
            'Detailed technical characteristics and performance parameters of the component (for '
            'example voltage, frequency, capacity).'
        ),
    ),
    MinimumElement(
        key="component_supplier",
        label="Supplier Information (component)",
        clause=ANCHORED_CLAUSES["component_supplier"],
        tier=Tier.CONTEXTUAL,
        determinability=Determinability.AUTO,
        probe=present("component_supplier"),
        rationale=(
            "The company that supplied the component to the manufacturer of the larger product, "
            "which can differ from the product's own supplier."
        ),
    ),
    MinimumElement(
        key="component_supplier_location",
        label="Supplier Location (component)",
        clause=ANCHORED_CLAUSES["component_supplier_location"],
        tier=Tier.CONTEXTUAL,
        determinability=Determinability.AUTO,
        probe=present("component_supplier_location"),
        rationale=(
            'The location of the direct supplier of the component (city, country).'
        ),
    ),
    MinimumElement(
        key="technology_node",
        label="Technology Node",
        clause=ANCHORED_CLAUSES["technology_node"],
        tier=Tier.CONTEXTUAL,
        determinability=Determinability.AUTO,
        probe=present("technology_node", "process_node"),
        rationale=(
            'Fabrication process geometry, where the component is a die.'
        ),
    ),
    MinimumElement(
        key="compliance_declarations",
        label="Compliance",
        clause=ANCHORED_CLAUSES["compliance_declarations"],
        tier=Tier.CRITICAL,
        determinability=Determinability.AUTO,
        probe=present("compliance_decls", "compliance", "certifications"),
        rationale=(
            'BIS, CE, FCC and the like, declared on delivery documentation.'
        ),
    ),
    MinimumElement(
        key="power_supply",
        label="Power supply",
        clause=ANCHORED_CLAUSES["power_supply"],
        tier=Tier.CONTEXTUAL,
        determinability=Determinability.AUTO,
        probe=present("power_supply"),
        rationale=(
            "The component's power requirements: voltage, current and wattage."
        ),
    ),
    MinimumElement(
        key="license_info",
        label="License Information",
        clause=ANCHORED_CLAUSES["license_info"],
        tier=Tier.CONTEXTUAL,
        determinability=Determinability.AUTO,
        probe=present("license_info", "license"),
        rationale=(
            'Intellectual property licences or usage terms, particularly for firmware or embedded '
            'software within the component.'
        ),
    ),
    MinimumElement(
        key="test_results",
        label="Test Result",
        clause=ANCHORED_CLAUSES["test_results"],
        tier=Tier.STANDARD,
        determinability=Determinability.AUTO,
        probe=present("test_results", "test_report"),
    ),
    MinimumElement(
        key="subcomponents",
        label="Sub-component",
        clause=ANCHORED_CLAUSES["subcomponents"],
        tier=Tier.STANDARD,
        determinability=Determinability.AUTO,
        probe=present("subcomponents", "parent_item_id", "children"),
        rationale=(
            "Table 11's final row: a server contains boards contain chips. Recursion is modelled "
            "by"
            "hardware_items.parent_item_id."
        ),
    ),
)

CATALOGUE = Catalogue(
    lane="hbom",
    clause_root="10.3",
    guideline_version=settings.GUIDELINE_VERSION,
    elements=ELEMENTS,
)
