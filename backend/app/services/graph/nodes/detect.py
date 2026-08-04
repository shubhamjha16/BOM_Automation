"""Which lanes this submission actually carries.

Detection here is *declaration reading*, not sniffing: the caller states the lane
each document belongs to at upload. S6 adds format validation that confirms the
declaration and rejects the document when it does not hold — an unrecognised
format raises rather than returning an empty component list, because an empty
list renders a green assessment.
"""

from __future__ import annotations

from datetime import UTC, datetime

from app.configs.envConfig import ALL_LANES
from app.services.graph.state import GraphState, NodeRun
from app.utils.logger import get_logger

logger = get_logger(__name__)


async def detect(state: GraphState) -> GraphState:
    started_at = datetime.now(UTC)
    submitted = {document.lane for document in state.get("documents", [])}
    detected = [lane for lane in ALL_LANES if lane in submitted]

    logger.info("detect", detected_lanes=detected)
    return GraphState(
        detected_lanes=detected,
        node_runs=[
            NodeRun(
                node="detect",
                status="succeeded",
                started_at=started_at,
                finished_at=datetime.now(UTC),
            )
        ],
    )
