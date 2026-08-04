"""Submission request bodies.

These describe the wire format and nothing else. Business rules — lane
enablement, size policy, supported spec versions — live in
`validators/submissionValidator.py`, because a schema that reads settings stops
being a description of the wire and starts being a second, competing source of
truth.
"""

from __future__ import annotations

from typing import Any, Literal
from uuid import UUID

from pydantic import BaseModel, Field


class DocumentIn(BaseModel):
    """One BOM document attached to a submission."""

    lane: Literal["sbom", "cbom", "qbom", "aibom", "hbom"] = Field(
        description="Which BOM facet this document is. Declared by the caller, never "
        "guessed from the payload: a mis-sniffed format scores the wrong catalogue."
    )
    format: Literal["CycloneDX", "SPDX"]
    spec_version: str | None = Field(default=None, examples=["1.6"])
    filename: str | None = None
    payload: dict[str, Any] = Field(
        description="The BOM document itself. Bounded by MAX_BOM_MB and rejected at "
        "the edge before it is read into memory."
    )


class SubmissionCreate(BaseModel):
    engagement_id: UUID = Field(
        description="Required. A submission outside an engagement has no client, no "
        "enabled lanes and no one to report to."
    )
    documents: list[DocumentIn] = Field(
        description="At least one. A submission with no documents is refused rather "
        "than assessed — an assessment of nothing reads as an assessment of "
        "something clean."
    )
