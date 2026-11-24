"""Each of Table 11's 20 elements must be readable from an asset register.

A new catalogue element that no parser fills would report every supplier absent on it
however well their register documented the item. These tests build one fully documented
register row and check that every element reads present, strip each new column in turn and
check that its element reads absent, and check that the new header aliases do not take a
column that already belongs to another field.
"""

from __future__ import annotations

import csv
import io

import pytest

from app.services.catalogue.loader import get_catalogue
from app.services.ingest.parsers import assetRegister

HEADERS = {
    "product_name": "Product Name",
    "product_version": "Product Version",
    "product_details": "Product Details",
    "warranty_ref": "Warranty",
    "manufacturer": "Manufacturer",
    "manufacturing_location": "Manufacturing Location",
    "manufacturing_date": "Manufacturing Date",
    "supplier_name": "Supplier",
    "supplier_location": "Supplier Location",
    "model_number": "Model Number",
    "serial_number": "Serial Number",
    "technical_specification": "Technical Specification",
    "component_supplier": "Component Supplier",
    "component_supplier_location": "Component Supplier Location",
    "technology_node": "Technology Node",
    "compliance_declarations": "Compliance",
    "power_supply": "Power Supply",
    "license_info": "License Information",
    "test_results": "Test Results",
    "subcomponents": "Subcomponents",
}
NEW = (
    "product_version",
    "product_details",
    "technical_specification",
    "component_supplier",
    "component_supplier_location",
    "power_supply",
    "license_info",
)


def _register(skip: set[str] | None = None) -> str:
    skip = skip or set()
    columns = {key: header for key, header in HEADERS.items() if key not in skip}
    out = io.StringIO()
    writer = csv.writer(out)
    writer.writerow(columns.values())
    writer.writerow([f"{header} value" for header in columns.values()])
    return out.getvalue()


def _item(register: str) -> dict:
    return assetRegister.parse(register, lane="hbom").entities[0]


def test_every_element_reads_present_on_a_fully_documented_register():
    item = _item(_register())
    for element in get_catalogue("hbom").elements:
        assert element.probe(item), f"{element.key} reads absent on a documented register"


@pytest.mark.parametrize("key", NEW)
def test_each_new_element_reads_absent_when_its_column_is_missing(key):
    item = _item(_register(skip={key}))
    assert not get_catalogue("hbom").by_key(key).probe(item)


def test_the_component_supplier_column_is_not_taken_by_the_product_supplier():
    """Product and component supplier are separate rows of Table 11; one column must
    not satisfy both."""
    item = _item(_register())
    assert item["supplier_name"] == "Supplier value"
    assert item["component_supplier"] == "Component Supplier value"
    assert item["supplier_location"] == "Supplier Location value"
    assert item["component_supplier_location"] == "Component Supplier Location value"


def test_a_register_without_the_component_columns_does_not_satisfy_the_component_rows():
    item = _item(_register(skip={"component_supplier", "component_supplier_location"}))
    catalogue = get_catalogue("hbom")
    assert catalogue.by_key("supplier_name").probe(item)
    assert not catalogue.by_key("component_supplier").probe(item)
    assert not catalogue.by_key("component_supplier_location").probe(item)


def test_the_two_old_extras_are_gone_but_firmware_is_still_read_for_the_pairing_rule():
    keys = {element.key for element in get_catalogue("hbom").elements}
    assert not keys & {"firmware_version", "deployment_criticality"}
    item = _item("Product Name,Firmware Version\nRouter,21.4R3\n")
    assert item["firmware_version"] == "21.4R3"
