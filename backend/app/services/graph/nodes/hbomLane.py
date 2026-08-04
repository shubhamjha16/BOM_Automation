"""HBOM lane — CERT-In s.10.2. Scoring implemented in S16.

The node exists from S1 and runs on every assessment. The runner sees an
unimplemented lane and reports `lane_absent`, which is a finding — distinct from
`lane_not_applicable`, which is what an engagement that does not enable this lane
reports and which is excluded from the overall score (§11).

Wiring the node now rather than at S16 means the lane's absence is visible in
every assessment issued before it ships, instead of silently missing.
"""

from __future__ import annotations

from app.services.graph.laneRunner import run_lane
from app.services.graph.state import GraphState, LaneResult, SubmissionDocument


def score_hbom(documents: list[SubmissionDocument]) -> LaneResult:
    raise NotImplementedError("hbom scoring lands in S16")


async def hbom_lane(state: GraphState) -> GraphState:
    return await run_lane(state, "hbom", score_hbom)
