"""CBOM lane — CERT-In s.8.4. Scoring implemented in S14.

The node exists from S1 and runs on every assessment. The runner sees an
unimplemented lane and reports `lane_absent`, which is a finding — distinct from
`lane_not_applicable`, which is what an engagement that does not enable this lane
reports and which is excluded from the overall score (§11).

Wiring the node now rather than at S14 means the lane's absence is visible in
every assessment issued before it ships, instead of silently missing.
"""

from __future__ import annotations

from app.services.graph.laneRunner import run_lane
from app.services.graph.state import GraphState, LaneResult, SubmissionDocument


def score_cbom(documents: list[SubmissionDocument]) -> LaneResult:
    raise NotImplementedError("cbom scoring lands in S14")


async def cbom_lane(state: GraphState) -> GraphState:
    return await run_lane(state, "cbom", score_cbom)
