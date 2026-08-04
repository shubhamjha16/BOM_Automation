"""Job response bodies."""

from __future__ import annotations

from datetime import datetime
from uuid import UUID

from pydantic import BaseModel, Field


class JobOut(BaseModel):
    id: UUID
    job_type: str
    status: str
    submission_id: UUID | None = None
    engagement_id: UUID | None = None
    error: str | None = None
    created_at: datetime
    terminal_at: datetime | None = None

    model_config = {"from_attributes": True}


class NodeRunOut(BaseModel):
    node: str
    lane: str | None
    status: str
    attempt: int
    started_at: datetime | None
    finished_at: datetime | None
    latency_ms: float | None
    error: str | None

    model_config = {"from_attributes": True}


class JobDetailOut(JobOut):
    node_runs: list[NodeRunOut] = Field(
        default_factory=list,
        description="Per-node execution log. Overlapping lane intervals here are the "
        "evidence the fan-out ran concurrently rather than in sequence.",
    )
