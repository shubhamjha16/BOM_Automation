"""Asset-register ingestion — CSV and Excel, per S16.

**HBOM data arrives as a spreadsheet.** ServiceNow, SAP and an estate manager's
own workbook are the real sources; there is no scanner to run. That shapes two
decisions here.

**Column names are matched, not positional.** Every organisation names these
columns differently — "Serial No", "serial_number", "Asset Serial" — and a
positional parser would silently map warranty into technology node. Unrecognised
columns are preserved in `fields` rather than dropped, so nothing is lost and a
reviewer can see what the register carried.

**Entry conservation applies exactly as it does to CycloneDX.** parsed + rejected
== rows, asserted. A spreadsheet row that cannot be read is rejected with a
reason, never skipped — the same rule, because the same failure inflates the same
percentages.
"""

from __future__ import annotations

import csv
import io
from typing import Any

from app.services.ingest.result import ParseResult

#: Canonical field → the header spellings seen in real exports, lowercased with
#: punctuation stripped. Order matters: the first match wins.
COLUMN_ALIASES: dict[str, tuple[str, ...]] = {
    "product_name": ("productname", "product", "assetname", "name", "description", "item"),
    "model_number": ("modelnumber", "model", "modelno", "partnumber", "sku"),
    "serial_number": ("serialnumber", "serialno", "serial", "assetserial", "assettag"),
    "manufacturer": ("manufacturer", "maker", "oem", "brand", "make"),
    "mfg_location": (
        "manufacturinglocation",
        "mfglocation",
        "countryoforigin",
        "origin",
        "madein",
    ),
    "mfg_date": ("manufacturingdate", "mfgdate", "dateofmanufacture", "builddate"),
    "supplier_name": ("suppliername", "supplier", "vendor", "reseller", "vendorname"),
    "supplier_location": ("supplierlocation", "vendorlocation", "supplycountry"),
    "technology_node": ("technologynode", "processnode", "node", "processgeometry"),
    "warranty_ref": ("warranty", "warrantyref", "amc", "amcref", "warrantycontract"),
    "test_results": ("testresults", "testreport", "qareport", "inspection"),
    "compliance_decls": (
        "compliance",
        "compliancedeclarations",
        "certifications",
        "certificates",
        "standards",
    ),
    "firmware_version": ("firmwareversion", "firmware", "fwversion", "biosversion"),
    "parent_item_id": ("parent", "parentid", "parentasset", "belongsto", "installedin"),
    "subcomponents": ("subcomponents", "children", "components"),
}


class UnreadableRegister(ValueError):
    """The payload is not a readable asset register."""


def _normalise_header(header: str) -> str:
    return "".join(character for character in str(header).lower() if character.isalnum())


def build_column_map(headers: list[str]) -> dict[str, str]:
    """Header → canonical field. Unmatched headers are left out and preserved
    later in `fields`, because a register's own columns are evidence too."""
    mapping: dict[str, str] = {}
    normalised = {header: _normalise_header(header) for header in headers}

    for canonical, aliases in COLUMN_ALIASES.items():
        for header, cleaned in normalised.items():
            if header in mapping:
                continue
            if cleaned in aliases:
                mapping[header] = canonical
                break
    return mapping


def _clean(value: Any) -> Any:
    if value is None:
        return None
    text = str(value).strip()
    return text if text and text.lower() not in ("n/a", "na", "-", "none", "unknown") else None


def _normalise_row(row: dict[str, Any], mapping: dict[str, str]) -> dict[str, Any]:
    item: dict[str, Any] = {"source": "asset_register"}
    extra: dict[str, Any] = {}

    for header, raw in row.items():
        value = _clean(raw)
        canonical = mapping.get(header)
        if canonical:
            item[canonical] = value
        elif value is not None:
            # Kept, not dropped: the register's own columns are evidence.
            extra[str(header)] = value

    item["fields"] = extra or None
    return item


def _rows_from_csv(text: str) -> tuple[list[str], list[dict[str, Any]]]:
    reader = csv.DictReader(io.StringIO(text))
    if not reader.fieldnames:
        raise UnreadableRegister(
            "the CSV carries no header row; column names are how an asset register "
            "is interpreted and a positional read would silently mis-map fields"
        )
    return list(reader.fieldnames), list(reader)


def _rows_from_xlsx(payload: bytes) -> tuple[list[str], list[dict[str, Any]]]:
    from openpyxl import load_workbook

    workbook = load_workbook(io.BytesIO(payload), read_only=True, data_only=True)
    sheet = workbook[workbook.sheetnames[0]]
    rows = sheet.iter_rows(values_only=True)

    try:
        header_row = next(rows)
    except StopIteration:
        raise UnreadableRegister("the workbook's first sheet is empty") from None

    headers = [
        str(cell) if cell is not None else f"column_{index}"
        for index, cell in enumerate(header_row)
    ]
    records = [
        dict(zip(headers, row, strict=False))
        for row in rows
        if any(cell is not None for cell in row)
    ]
    return headers, records


def parse(payload: Any, *, lane: str = "hbom") -> ParseResult:
    """Parse a CSV or XLSX asset register into hardware items."""
    if lane != "hbom":
        raise UnreadableRegister(
            f"an asset register is scored by the HBOM lane only; the {lane} lane "
            "has no Table 11 mapping"
        )

    if isinstance(payload, bytes):
        headers, rows = _rows_from_xlsx(payload)
        source_format = "XLSX"
    elif isinstance(payload, str):
        headers, rows = _rows_from_csv(payload)
        source_format = "CSV"
    else:
        raise UnreadableRegister(
            f"an asset register must be CSV text or XLSX bytes, got {type(payload).__name__}"
        )

    mapping = build_column_map(headers)
    if not mapping:
        raise UnreadableRegister(
            f"none of the {len(headers)} columns matched a Table 11 field "
            f"({', '.join(headers[:6])}...). Refusing to parse rather than "
            "returning an empty hardware list, which would render as a clean "
            "assessment of an estate nobody read."
        )

    result = ParseResult(
        spec_version=f"asset-register/{source_format}",
        format="AssetRegister",
        doc_name=None,
        declared_entries=len(rows),
    )

    for ordinal, row in enumerate(rows):
        item = _normalise_row(row, mapping)
        if not item.get("product_name") and not item.get("serial_number"):
            result.reject(
                ordinal,
                "row identifies no asset: neither a product name nor a serial "
                "number could be read from it",
                ref=None,
            )
            continue
        result.entities.append(item)

    result.assert_conserved()
    return result
