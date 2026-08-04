"""DOCX assessment export.

The watermark is a first-page banner rather than a page background: python-docx
cannot set a true watermark without dropping into raw XML, and a banner a reader
cannot miss serves the purpose better than a faint diagonal they can. An
unapproved assessment must not be mistakable for an issued one.
"""

from __future__ import annotations

from io import BytesIO
from typing import Any

from docx import Document
from docx.enum.text import WD_ALIGN_PARAGRAPH
from docx.shared import Pt, RGBColor


def build_assessment(
    sections: list[Any],
    *,
    title: str,
    watermark: str | None = None,
) -> bytes:
    document = Document()

    if watermark:
        banner = document.add_paragraph()
        banner.alignment = WD_ALIGN_PARAGRAPH.CENTER
        run = banner.add_run(watermark.upper())
        run.bold = True
        run.font.size = Pt(14)
        run.font.color.rgb = RGBColor(0xA4, 0x26, 0x2C)
        document.add_paragraph()

    document.add_heading(title, level=0)

    for section in sections:
        document.add_heading(section.title, level=1)
        for line in section.body.split("\n"):
            if not line.strip():
                document.add_paragraph()
                continue
            paragraph = document.add_paragraph(line)
            paragraph.paragraph_format.space_after = Pt(2)

    document.add_page_break()
    closing = document.add_paragraph()
    closing.add_run(
        "This is a conformance assessment against the CERT-In Technical Guidelines "
        "on SBOM, QBOM & CBOM, AIBOM and HBOM v2.0. It is not a legal opinion. "
        "Elements recorded as consumer determinations were not assessed and require "
        "a determination by the consuming organisation."
    ).italic = True

    buffer = BytesIO()
    document.save(buffer)
    return buffer.getvalue()
