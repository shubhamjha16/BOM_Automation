"""Per-lane progress, as Server-Sent Events.

**Five lanes should read as five tracks, not one spinner.** A single progress bar
over a fan-out is a lie about the shape of the work: the lanes finish at wildly
different times, and a user watching one bar cannot tell a fast assessment from a
stuck one. Per-lane events make a hung CBOM lane visible while SBOM is still
counting components.

Events are derived from persisted `node_runs` rather than pushed from inside the
graph. That keeps the graph free of transport concerns and means a client that
reconnects mid-assessment sees the history rather than only what happens next.
"""

from __future__ import annotations

import json
from collections.abc import AsyncIterator
from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True, slots=True)
class ProgressEvent:
    event: str
    lane: str | None
    message: str
    data: dict[str, Any]

    def to_sse(self) -> str:
        """One SSE frame. The blank line terminates it — omitting it makes the
        client wait for a frame that never arrives."""
        payload = json.dumps(
            {"lane": self.lane, "message": self.message, **self.data}, default=str
        )
        return f"event: {self.event}\ndata: {payload}\n\n"


def event_for_node_run(run: Any) -> ProgressEvent:
    """Turn one persisted node run into a line a human can read."""
    lane = getattr(run, "lane", None)
    node = getattr(run, "node", "?")
    status = str(getattr(run, "status", ""))

    if lane:
        message = {
            "succeeded": f"{lane}: scored",
            "timeout": f"{lane}: timed out",
            "failed": f"{lane}: failed",
        }.get(status, f"{lane}: {status}")
    else:
        message = f"{node}: {status}"

    return ProgressEvent(
        event="lane" if lane else "node",
        lane=lane,
        message=message,
        data={
            "node": node,
            "status": status,
            "latency_ms": getattr(run, "latency_ms", None),
            "error": getattr(run, "error", None),
        },
    )


def summary_event(summary: Any) -> ProgressEvent:
    lanes = {
        result.lane: {"verdict": str(result.verdict), "score": result.score}
        for result in getattr(summary, "lane_results", [])
    }
    return ProgressEvent(
        event="complete",
        lane=None,
        message=f"assessment {summary.status}",
        data={"overall_score": summary.overall_score, "lanes": lanes},
    )


async def stream(job: Any, node_runs: list[Any], summary: Any | None = None) -> AsyncIterator[str]:
    """Replay a job's progress as SSE frames."""
    yield ProgressEvent(
        event="started",
        lane=None,
        message=f"assessment {job.status}",
        data={"job_id": str(job.id), "submission_id": str(job.submission_id or "")},
    ).to_sse()

    for run in sorted(node_runs, key=lambda item: (getattr(item, "started_at", None) or 0)):
        yield event_for_node_run(run).to_sse()

    if summary is not None:
        yield summary_event(summary).to_sse()

    if getattr(job, "is_terminal", False):
        # A terminal job's stream ends. Holding it open would leave a client
        # waiting for progress that has already finished.
        yield ProgressEvent(
            event="end", lane=None, message="stream closed", data={}
        ).to_sse()
