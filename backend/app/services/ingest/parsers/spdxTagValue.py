"""SPDX 2.2 / 2.3 tag-value → normalised entities. Implemented in S6.

S6 also makes a truncated document fail loudly naming the byte offset, which is
the reason this format gets its own parser rather than a pre-pass into JSON.
"""

from __future__ import annotations

from app.services.ingest.parsers.cyclonedx import ParseResult


def parse(payload: str, *, lane: str = "sbom") -> ParseResult:
    raise NotImplementedError(
        "SPDX tag-value ingestion lands in S6; submit CycloneDX 1.4-1.6 until then"
    )
