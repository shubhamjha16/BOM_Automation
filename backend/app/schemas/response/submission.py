"""Submission response bodies."""

from __future__ import annotations

from datetime import datetime
from uuid import UUID

from pydantic import BaseModel, Field


class DocumentOut(BaseModel):
    id: UUID
    lane: str
    format: str
    spec_version: str | None
    filename: str | None
    checksum: str
    size_bytes: int
    status: str
    entry_count: int
    parsed_count: int
    rejected_count: int

    model_config = {"from_attributes": True}


class SubmissionOut(BaseModel):
    id: UUID
    engagement_id: UUID
    status: str
    #: Null until the engine computes one. Never zero as a placeholder — the
    #: console renders null as an em dash, not as 0%.
    overall_score: float | None = None
    overall_verdict: str | None = None
    created_at: datetime
    documents: list[DocumentOut] = Field(default_factory=list)

    model_config = {"from_attributes": True}


class LaneRollupOut(BaseModel):
    lane: str
    verdict: str
    score: float | None
    entity_count: int
    detail: str
    #: lane_not_applicable is excluded from the overall score; lane_absent is a
    #: finding. The console must never render the two the same way.
    counts_toward_overall: bool
    is_finding: bool


class SubmissionDetailOut(SubmissionOut):
    lanes: list[LaneRollupOut] = Field(default_factory=list)
