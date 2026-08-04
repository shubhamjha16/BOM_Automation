"""The convergence point: every lane has reported, nothing is outstanding.

The reducers have already merged the concurrent writes by the time this runs.
What join adds is the completeness assertion — every lane that fanned out must
have produced exactly one result, because a lane that produced none is a lane
whose absence would otherwise go unnoticed in the overall score.
"""

from __future__ import annotations

from datetime import UTC, datetime

from app.services.graph.state import GraphState, NodeRun
from app.utils.logger import get_logger

logger = get_logger(__name__)


class LaneResultMissing(RuntimeError):
    """A lane fanned out and never reported. Never silently tolerated."""


async def join(state: GraphState) -> GraphState:
    started_at = datetime.now(UTC)
    results = state.get("lane_results", [])
    reported = {result.lane for result in results}
    expected = set(state.get("lanes_to_run", []))

    if missing := expected - reported:
        raise LaneResultMissing(
            f"lane(s) {sorted(missing)} produced no result; an unreported lane would "
            "be excluded from the overall score without appearing as a finding"
        )

    runs = state.get("node_runs", [])
    lane_runs = [run for run in runs if run.lane is not None]
    logger.info(
        "join",
        lanes_reported=sorted(reported),
        verdicts={result.lane: str(result.verdict) for result in results},
        max_lane_latency_ms=round(max((run.latency_ms for run in lane_runs), default=0), 2),
    )
    return GraphState(
        node_runs=[
            NodeRun(
                node="join",
                status="succeeded",
                started_at=started_at,
                finished_at=datetime.now(UTC),
            )
        ]
    )
