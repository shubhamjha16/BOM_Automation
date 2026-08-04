"""The graph's state and the value types that flow through it.

Five lanes write concurrently, so every field a lane touches is an ``Annotated``
list with an ``operator.add``-style reducer. Nothing else writes shared state —
that rule is what makes the fan-out safe (§4).
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Annotated, Any, Literal, TypedDict

from app.configs.envConfig import Lane
from app.configs.jobTypes import JobStatus, JobType, LaneVerdict
from app.services.graph.reducers import merge_lane_results, merge_node_runs, merge_unique

BomFormat = Literal["CycloneDX", "SPDX"]
NodeStatus = Literal["running", "succeeded", "failed", "timeout"]


def _now() -> datetime:
    return datetime.now(UTC)


@dataclass(frozen=True, slots=True)
class SubmissionDocument:
    """One BOM document inside a submission. A submission is one artifact with up
    to five facets, not five jobs."""

    lane: Lane
    format: BomFormat
    payload: dict[str, Any]
    spec_version: str | None = None
    filename: str | None = None

    @property
    def checksum(self) -> str:
        canonical = json.dumps(self.payload, sort_keys=True, separators=(",", ":"))
        return hashlib.sha256(canonical.encode()).hexdigest()


@dataclass(frozen=True, slots=True)
class NodeRun:
    """One node execution. ``started_at``/``finished_at`` are what prove the lanes
    ran concurrently rather than in sequence; S2 persists these rows."""

    node: str
    status: NodeStatus
    started_at: datetime
    finished_at: datetime
    lane: Lane | None = None
    attempt: int = 1
    error: str | None = None

    @property
    def latency_ms(self) -> float:
        return (self.finished_at - self.started_at).total_seconds() * 1000

    def overlaps(self, other: NodeRun) -> bool:
        return self.started_at < other.finished_at and other.started_at < self.finished_at


@dataclass(frozen=True, slots=True)
class LaneResult:
    """A lane's outcome. ``score`` stays None until the catalogue and the scorer
    land in S7 — a placeholder number here would be a fabricated verdict."""

    lane: Lane
    verdict: LaneVerdict
    entity_count: int = 0
    score: float | None = None
    detail: str = ""
    engine_version: str = ""
    inputs_hash: str | None = None
    computed_at: datetime = field(default_factory=_now)
    #: Per-element verdicts, carried so they can be persisted and rendered.
    #: A lane result without them is a score with nothing behind it, and the
    #: whole product is the traceability from score to clause to BOM entry.
    field_results: list[dict[str, Any]] = field(default_factory=list)
    #: Entries the parser refused, so the count is reportable per lane.
    rejected_count: int = 0
    #: The normalised entities this lane scored, carried to the join.
    #: Correlation compares one lane's declarations against another's, so it
    #: needs the entities themselves and not merely the verdicts about them.
    #: These are references to objects already in memory, not copies.
    entities: list[dict[str, Any]] = field(default_factory=list)

    @property
    def counts_toward_overall(self) -> bool:
        """lane_not_applicable is excluded from the overall score; lane_absent is a
        finding and is included. They are not the same thing (§11)."""
        return self.verdict not in (LaneVerdict.LANE_NOT_APPLICABLE, LaneVerdict.LANE_TIMEOUT)


@dataclass(frozen=True, slots=True)
class CorrelationFinding:
    """A cross-BOM finding — the class of result no single-lane tool can produce."""

    rule_key: str
    severity: Literal["low", "medium", "high", "critical"]
    clause: str
    detail: str
    left_ref: str | None = None
    right_ref: str | None = None


class GraphState(TypedDict, total=False):
    """Everything the graph reads or writes.

    Scalar keys are written by exactly one node. The three list keys below are
    written by the five concurrent lanes and therefore carry reducers.
    """

    # --- identity ----------------------------------------------------------
    job_id: str
    org_id: str
    submission_id: str
    job_type: JobType
    status: JobStatus

    # --- input -------------------------------------------------------------
    documents: list[SubmissionDocument]
    requested_lanes: list[Lane]

    # --- set by detect / fanout -------------------------------------------
    detected_lanes: list[Lane]
    lanes_to_run: list[Lane]

    # --- written concurrently by the lanes --------------------------------
    lane_results: Annotated[list[LaneResult], merge_lane_results]
    node_runs: Annotated[list[NodeRun], merge_node_runs]
    errors: Annotated[list[str], merge_unique]

    # --- post-join ---------------------------------------------------------
    correlation_findings: list[CorrelationFinding]
    identifier_mappings: list[dict[str, Any]]
    gate_verdict: Literal["passed", "blocked"]
    gate_reason: str | None

    # --- narrative path (S15 fills these in) -------------------------------
    section_plan: list[dict[str, Any]]
    sections: list[dict[str, Any]]
    critic_notes: list[str]
    heal_attempts: int
    artifact_key: str | None


def initial_state(
    *,
    job_id: str,
    org_id: str,
    submission_id: str,
    documents: list[SubmissionDocument],
    requested_lanes: list[Lane] | None = None,
    job_type: JobType = JobType.ASSESS_SUBMISSION,
) -> GraphState:
    return GraphState(
        job_id=job_id,
        org_id=org_id,
        submission_id=submission_id,
        job_type=job_type,
        status=JobStatus.RUNNING,
        documents=documents,
        requested_lanes=list(requested_lanes) if requested_lanes is not None else [],
        lane_results=[],
        node_runs=[],
        errors=[],
        correlation_findings=[],
        heal_attempts=0,
    )
