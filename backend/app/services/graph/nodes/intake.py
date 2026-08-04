"""Entry node: bind the log context and assert the submission is non-empty.

A submission with zero documents must never reach the lanes, because five
``lane_absent`` results and an overall score of zero reads as an assessment of a
supplier who submitted nothing wrong — it is an assessment of nothing at all.
"""

from __future__ import annotations

from datetime import UTC, datetime

import structlog

from app.services.graph.state import GraphState, NodeRun
from app.utils.logger import get_logger

logger = get_logger(__name__)


class EmptySubmission(ValueError):
    """Raised when a submission carries no BOM documents at all."""


async def intake(state: GraphState) -> GraphState:
    started_at = datetime.now(UTC)
    structlog.contextvars.bind_contextvars(
        job_id=state.get("job_id"),
        submission_id=state.get("submission_id"),
        org_id=state.get("org_id"),
    )

    documents = state.get("documents", [])
    if not documents:
        raise EmptySubmission(
            "submission carries no BOM documents; refusing to produce an assessment "
            "of an empty submission (rec. 7.1.2)"
        )

    logger.info(
        "intake",
        document_count=len(documents),
        lanes_submitted=sorted({document.lane for document in documents}),
    )
    return GraphState(
        node_runs=[
            NodeRun(
                node="intake",
                status="succeeded",
                started_at=started_at,
                finished_at=datetime.now(UTC),
            )
        ]
    )
