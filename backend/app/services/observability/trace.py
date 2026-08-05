"""Reconstructing an assessment from its logs.

The exit condition §S21 sets is precise and worth reading literally: **a
`submission_id` alone reconstructs all five lane lifecycles.** Not "logs exist",
not "the lane that failed logged something" — one identifier, one query, five
lifecycles, including the lanes that did nothing.

That last part is the whole difficulty. A lane which was not enabled, or which
received no document, does no work and has nothing interesting to say, so it is
exactly the lane that gets left out of the logs. Then a client asks why their CBOM
was not assessed and the answer has to be reconstructed from memory. So every lane
emits a start and a terminal event whatever it did, and the five together are the
lifecycle set this module rebuilds.

Correlation comes from `structlog.contextvars`: `assessment_context` binds
`submission_id`, `job_id` and `org_id` once, and every line emitted underneath
carries them — including from inside the lane threads, because `asyncio.to_thread`
copies the context. Threading the identifiers through call signatures instead
would work until the first place somebody forgot, and the place somebody forgot
would be the place that mattered.
"""

from __future__ import annotations

import json
from collections.abc import Iterable, Iterator
from contextlib import contextmanager
from dataclasses import dataclass, field
from typing import Any

import structlog

from app.configs.envConfig import ALL_LANES

LANE_STARTED = "lane_started"
LANE_COMPLETE = "lane_complete"
LANE_FAILED = "lane_failed"
ASSESSMENT_STARTED = "assessment_started"
ASSESSMENT_COMPLETE = "assessment_complete"

#: Events that end a lane's lifecycle. `lane_failed` is not one: the runner logs
#: it and then still completes the lane with a FAIL verdict, because a lane never
#: fails the submission (§11).
TERMINAL_EVENTS = frozenset({LANE_COMPLETE})


@contextmanager
def assessment_context(
    *, submission_id: str, job_id: str | None = None, org_id: str | None = None
) -> Iterator[None]:
    """Bind the correlation keys for the duration of one assessment."""
    bindings: dict[str, Any] = {"submission_id": submission_id}
    if job_id:
        bindings["job_id"] = job_id
    if org_id:
        bindings["org_id"] = org_id

    tokens = structlog.contextvars.bind_contextvars(**bindings)
    try:
        yield
    finally:
        structlog.contextvars.reset_contextvars(**tokens)


@dataclass(slots=True)
class LaneLifecycle:
    """One lane's story, as the logs tell it."""

    lane: str
    started: bool = False
    terminal_event: str | None = None
    verdict: str | None = None
    entity_count: int | None = None
    latency_ms: float | None = None
    errors: list[str] = field(default_factory=list)

    @property
    def complete(self) -> bool:
        """A lifecycle is complete when it both began and ended.

        Started-but-never-ended is the shape a hung lane leaves behind, and it has
        to be distinguishable from a lane that was never reached at all.
        """
        return self.started and self.terminal_event is not None

    def as_row(self) -> dict[str, Any]:
        return {
            "lane": self.lane,
            "started": self.started,
            "terminal_event": self.terminal_event,
            "verdict": self.verdict,
            "entity_count": self.entity_count,
            "latency_ms": self.latency_ms,
            "errors": list(self.errors),
            "complete": self.complete,
        }


@dataclass(slots=True)
class Reconstruction:
    submission_id: str
    lanes: dict[str, LaneLifecycle]
    line_count: int

    @property
    def missing(self) -> list[str]:
        """Lanes the logs say nothing about — the failure this exists to catch."""
        return [lane for lane in ALL_LANES if lane not in self.lanes]

    @property
    def incomplete(self) -> list[str]:
        return sorted(lane for lane, cycle in self.lanes.items() if not cycle.complete)

    @property
    def is_whole(self) -> bool:
        return not self.missing and not self.incomplete

    def as_report(self) -> dict[str, Any]:
        return {
            "submission_id": self.submission_id,
            "lines": self.line_count,
            "lanes": [self.lanes[lane].as_row() for lane in ALL_LANES if lane in self.lanes],
            "missing": self.missing,
            "incomplete": self.incomplete,
            "whole": self.is_whole,
        }


def parse_lines(raw: Iterable[str]) -> list[dict[str, Any]]:
    """Read JSON log lines, skipping anything that is not one.

    Tolerant on purpose. A log stream in production carries lines from libraries
    that never heard of structlog, and a reconstruction tool that dies on the
    first one is useless exactly when it is needed.
    """
    parsed: list[dict[str, Any]] = []
    for line in raw:
        line = line.strip()
        if not line.startswith("{"):
            continue
        try:
            record = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(record, dict):
            parsed.append(record)
    return parsed


def reconstruct(raw: Iterable[str], submission_id: str) -> Reconstruction:
    """Rebuild every lane lifecycle for one submission, from logs alone.

    The `submission_id` filter is the only input. No database, no job row, no
    in-memory state — because at the point somebody needs this, the process that
    ran the assessment is gone.
    """
    records = [
        record
        for record in parse_lines(raw)
        if record.get("submission_id") == submission_id
    ]

    lanes: dict[str, LaneLifecycle] = {}
    for record in records:
        lane = record.get("lane")
        if not isinstance(lane, str):
            continue
        cycle = lanes.setdefault(lane, LaneLifecycle(lane=lane))
        event = record.get("event")

        if event == LANE_STARTED:
            cycle.started = True
        elif event in TERMINAL_EVENTS:
            cycle.terminal_event = event
            cycle.verdict = record.get("verdict")
            if isinstance(record.get("entity_count"), int):
                cycle.entity_count = record["entity_count"]
            if isinstance(record.get("latency_ms"), (int, float)):
                cycle.latency_ms = float(record["latency_ms"])
        elif event == LANE_FAILED:
            cycle.errors.append(str(record.get("exception") or record.get("error") or event))

    return Reconstruction(
        submission_id=submission_id, lanes=lanes, line_count=len(records)
    )


def latency_percentiles(reconstructions: Iterable[Reconstruction]) -> dict[str, dict[str, float]]:
    """Per-lane p50/p95 across many assessments.

    Per lane rather than per assessment, because the number that answers "does the
    fan-out hold or is it serialising?" is the *slowest lane's* p95 against the
    assessment's own — and an aggregate hides exactly that.
    """
    samples: dict[str, list[float]] = {}
    for reconstruction in reconstructions:
        for lane, cycle in reconstruction.lanes.items():
            if cycle.latency_ms is not None:
                samples.setdefault(lane, []).append(cycle.latency_ms)

    summary: dict[str, dict[str, float]] = {}
    for lane, values in samples.items():
        ordered = sorted(values)
        summary[lane] = {
            "n": float(len(ordered)),
            "p50": _percentile(ordered, 50),
            "p95": _percentile(ordered, 95),
            "max": ordered[-1],
        }
    return summary


def _percentile(ordered: list[float], percentile: float) -> float:
    if not ordered:
        return 0.0
    # Nearest-rank. With the sample sizes a load run produces, interpolating
    # would imply a precision the measurement does not have.
    index = max(0, min(len(ordered) - 1, round(percentile / 100 * len(ordered)) - 1))
    return round(ordered[index], 2)
