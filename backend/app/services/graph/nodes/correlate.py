"""Cross-BOM reconciliation — what the join buys. Rules land in S9.

The one rule enforced from S1 is the negative one: **a single-lane submission
produces zero correlation findings rather than false positives.** Correlation
compares one lane's declarations against another's; with only one lane present
there is nothing to compare against, and a rule that fires anyway is inventing a
finding about a document that was never submitted.
"""

from __future__ import annotations

from datetime import UTC, datetime

from app.configs.jobTypes import LaneVerdict
from app.services.graph.state import GraphState, NodeRun
from app.utils.logger import get_logger

logger = get_logger(__name__)


def _lanes_with_content(state: GraphState) -> set[str]:
    """Lanes that actually carried a scored document.

    An absent, timed-out or not-applicable lane declared nothing, so it can be
    neither side of a correlation.
    """
    return {
        result.lane
        for result in state.get("lane_results", [])
        if result.verdict
        not in (
            LaneVerdict.LANE_ABSENT,
            LaneVerdict.LANE_TIMEOUT,
            LaneVerdict.LANE_NOT_APPLICABLE,
        )
    }


async def correlate(state: GraphState) -> GraphState:
    started_at = datetime.now(UTC)
    participating = _lanes_with_content(state)

    findings: list = []
    if len(participating) < 2:
        logger.info("correlate_skipped", reason="fewer than two lanes carried content")
    else:
        # S9 applies correlate/rules.py here: cryptoInSbom, modelDepsInSbom,
        # firmwareInHbom, algorithmQuantumExposure, vexCoverage.
        logger.info("correlate", participating=sorted(participating), findings=0)

    return GraphState(
        correlation_findings=findings,
        node_runs=[
            NodeRun(
                node="correlate",
                status="succeeded",
                started_at=started_at,
                finished_at=datetime.now(UTC),
            )
        ],
    )
