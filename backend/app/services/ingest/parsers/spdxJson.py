"""SPDX 2.2 / 2.3 JSON → normalised entities. Implemented in S6.

Raises rather than returning nothing. A parser that returns an empty list for a
format it cannot read produces a green assessment of a document nobody scored,
which is the single worst failure mode this product has.
"""

from __future__ import annotations

from typing import Any

from app.services.ingest.parsers.cyclonedx import ParseResult

SUPPORTED_SPEC_VERSIONS: frozenset[str] = frozenset({"SPDX-2.2", "SPDX-2.3"})


def parse(payload: dict[str, Any], *, lane: str = "sbom") -> ParseResult:
    raise NotImplementedError(
        "SPDX JSON ingestion lands in S6 with its schema validation and entry "
        "conservation assertions; submit CycloneDX 1.4-1.6 until then"
    )
