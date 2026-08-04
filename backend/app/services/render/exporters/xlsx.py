"""The XLSX gap register — what a supplier actually works from.

**One tab per lane, clause column intact, usable without editing.** That last
part is the requirement: a register a supplier has to reformat before they can
assign it is a register they will reformat wrongly, and the clause column is the
first thing lost when someone pastes into their own template.

Sorted by tier then clause, for the same reason the roadmap is: a supplier
working top-down must start at the critical gaps, and clause order would start
them at 4.2(1).

Formula injection is handled here rather than at S20's security review because
component names are supplier-controlled text and this file is opened in Excel by
a person who trusts it.
"""

from __future__ import annotations

from io import BytesIO
from typing import Any

from openpyxl import Workbook
from openpyxl.styles import Alignment, Font, PatternFill
from openpyxl.utils import get_column_letter

TIER_RANK = {"critical": 0, "standard": 1, "contextual": 2}

HEADERS = (
    "Clause",
    "Minimum element",
    "Tier",
    "Verdict",
    "Declared on",
    "Of",
    "Coverage",
    "What is required",
)

#: Excel treats a leading =, +, -, @ as a formula. A component named
#: `=cmd|'/c calc'!A1` is a supplier-controlled payload, so the cell is prefixed
#: to render it inert while keeping the text readable.
_FORMULA_LEAD = ("=", "+", "-", "@", "\t", "\r")


def _inert(value: Any) -> Any:
    """Neutralise a cell that Excel would evaluate as a formula."""
    if isinstance(value, str) and value.startswith(_FORMULA_LEAD):
        return f"'{value}"
    return value


def _style_header(sheet: Any) -> None:
    fill = PatternFill("solid", fgColor="1F2933")
    for index, header in enumerate(HEADERS, start=1):
        cell = sheet.cell(row=1, column=index, value=header)
        cell.font = Font(bold=True, color="FFFFFF")
        cell.fill = fill
    sheet.freeze_panes = "A2"


def _autosize(sheet: Any) -> None:
    widths = {1: 12, 2: 44, 3: 12, 4: 20, 5: 12, 6: 8, 7: 12, 8: 70}
    for column, width in widths.items():
        sheet.column_dimensions[get_column_letter(column)].width = width


def build_gap_register(
    lane_results: list[Any], *, watermark: str | None = None
) -> bytes:
    """One tab per lane carrying that lane's unmet elements."""
    workbook = Workbook()
    workbook.remove(workbook.active)

    for lane in lane_results:
        rows = [
            row
            for row in (getattr(lane, "field_results", None) or [])
            if str(row.get("verdict")) in ("absent", "not_determinable")
        ]
        sheet = workbook.create_sheet(title=str(lane.lane).upper()[:31])
        _style_header(sheet)

        ordered = sorted(
            rows,
            key=lambda row: (
                TIER_RANK.get(str(row.get("tier")), 3),
                str(row.get("clause")),
            ),
        )
        for index, row in enumerate(ordered, start=2):
            coverage = row.get("coverage")
            required = (
                row.get("consumer_action")
                if str(row.get("verdict")) == "not_determinable"
                else row.get("detail")
            )
            values = (
                row.get("clause"),
                row.get("label") or row.get("element_key"),
                row.get("tier"),
                row.get("verdict"),
                row.get("populated"),
                row.get("total"),
                f"{round(float(coverage) * 100, 1)}%" if coverage is not None else "n/a",
                required,
            )
            for column, value in enumerate(values, start=1):
                cell = sheet.cell(row=index, column=column, value=_inert(value))
                if column == 8:
                    cell.alignment = Alignment(wrap_text=True, vertical="top")

        if not ordered:
            sheet.cell(row=2, column=1, value="No unmet elements in this lane.")
        _autosize(sheet)

        if watermark:
            note = sheet.cell(row=len(ordered) + 3, column=1, value=watermark)
            note.font = Font(bold=True, color="A4262C")

    if not workbook.sheetnames:  # pragma: no cover - a lane list is never empty
        workbook.create_sheet(title="EMPTY")

    buffer = BytesIO()
    workbook.save(buffer)
    return buffer.getvalue()
