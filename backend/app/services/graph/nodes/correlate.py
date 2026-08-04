"""Cross-BOM reconciliation — what the join buys.

Rules live in `services/correlate/`, held as data with their clause references so
a correlation finding cites the guideline exactly as a field verdict does and
passes the same conformance gate.

The node's own responsibility is narrow: gather what each lane actually carried,
hand it to the engine, and record what ran. **A lane that reported absent,
timed out or was not applicable declared nothing**, so it can be neither side of
a correlation — which is how "a single-lane submission produces zero correlation
findings rather than false positives" is enforced.
"""

from __future__ import annotations

from datetime import UTC, datetime

from app.configs.jobTypes import LaneVerdict
from app.services.correlate.engine import correlate as run_rules
from app.services.graph.state import CorrelationFinding, GraphState, NodeRun
from app.utils.logger import get_logger

logger = get_logger(__name__)

#: Verdicts meaning the lane declared nothing usable for comparison.
_DECLARED_NOTHING = (
    LaneVerdict.LANE_ABSENT,
    LaneVerdict.LANE_TIMEOUT,
    LaneVerdict.LANE_NOT_APPLICABLE,
)


def _lane_entities(state: GraphState) -> dict[str, list[dict]]:
    return {
        result.lane: list(result.entities)
        for result in state.get("lane_results", [])
        if result.verdict not in _DECLARED_NOTHING
    }


async def correlate(state: GraphState) -> GraphState:
    started_at = datetime.now(UTC)
    lane_entities = _lane_entities(state)

    report = run_rules(lane_entities)
    findings = [
        CorrelationFinding(
            rule_key=finding.rule_key,
            severity=str(finding.severity),  # type: ignore[arg-type]
            clause=finding.clause,
            detail=finding.detail,
            left_ref=finding.left_ref,
            right_ref=finding.right_ref,
        )
        for finding in report.findings
    ]

    if findings:
        logger.info(
            "correlation_findings",
            count=len(findings),
            rules=[finding.rule_key for finding in findings],
        )

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
