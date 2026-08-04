"""Decide the lane set, then hand off to five concurrent lanes.

Every lane node runs on every assessment. That is deliberate: a lane the
engagement enabled but the supplier did not submit must report ``lane_absent``,
and only a lane that *ran* can report anything. Skipping the node would make an
undeclared CBOM indistinguishable from a client who has no cryptography.
"""

from __future__ import annotations

from datetime import UTC, datetime

from app.configs.laneConfig import resolve_lanes
from app.services.graph.state import GraphState, NodeRun
from app.utils.logger import get_logger

logger = get_logger(__name__)


async def fanout(state: GraphState) -> GraphState:
    started_at = datetime.now(UTC)
    requested = state.get("requested_lanes") or None
    lanes_to_run = list(resolve_lanes(requested))

    logger.info(
        "fanout",
        lanes_to_run=lanes_to_run,
        detected=state.get("detected_lanes", []),
        requested=requested,
    )
    return GraphState(
        lanes_to_run=lanes_to_run,
        node_runs=[
            NodeRun(
                node="fanout",
                status="succeeded",
                started_at=started_at,
                finished_at=datetime.now(UTC),
            )
        ],
    )
