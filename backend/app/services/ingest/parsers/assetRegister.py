"""Asset-register (CSV / XLSX) -> hardware items. Implemented in S16.

HBOM data is procurement data: ServiceNow, SAP and spreadsheet exports, not
scanner output. The assessment must state plainly that these fields are
procurement-sourced rather than artifact-derived, because a reader has to know
which claims rest on a scan and which on a purchase order.
"""

from __future__ import annotations

from typing import Any

from app.services.ingest.parsers.cyclonedx import ParseResult


def parse(payload: Any, *, lane: str = "hbom") -> ParseResult:
    raise NotImplementedError(
        "asset-register ingestion lands in S16 alongside the HBOM lane"
    )
