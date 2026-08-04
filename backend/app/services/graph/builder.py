"""Graph wiring. Pure structure — zero prompt text, zero business rules.

    intake → detect → fanout ─┬→ sbomLane  ─┐
                              ├→ cbomLane  ─┤
                              ├→ qbomLane  ─┼→ join → correlate → conformanceGate
                              ├→ aibomLane ─┤
                              └→ hbomLane  ─┘

All five lane nodes are edged in unconditionally. A lane that the engagement did
not enable reports ``lane_not_applicable`` from inside the node; skipping the
edge instead would make that indistinguishable from a lane nobody ran.

Prompts live under ``graph/prompts/``, one module per node, and are imported by
the drafter nodes — never here.
"""

from __future__ import annotations

from typing import Any

from langgraph.graph import END, START, StateGraph

from app.configs.envConfig import ALL_LANES
from app.services.graph.nodes.aibomLane import aibom_lane
from app.services.graph.nodes.cbomLane import cbom_lane
from app.services.graph.nodes.conformanceGate import conformance_gate
from app.services.graph.nodes.correlate import correlate
from app.services.graph.nodes.detect import detect
from app.services.graph.nodes.fanout import fanout
from app.services.graph.nodes.hbomLane import hbom_lane
from app.services.graph.nodes.intake import intake
from app.services.graph.nodes.join import join
from app.services.graph.nodes.qbomLane import qbom_lane
from app.services.graph.nodes.sbomLane import sbom_lane
from app.services.graph.state import GraphState

LANE_NODES = {
    "sbom": sbom_lane,
    "cbom": cbom_lane,
    "qbom": qbom_lane,
    "aibom": aibom_lane,
    "hbom": hbom_lane,
}


def build_assessment_graph() -> StateGraph:
    graph: StateGraph = StateGraph(GraphState)

    graph.add_node("intake", intake)
    graph.add_node("detect", detect)
    graph.add_node("fanout", fanout)
    for lane in ALL_LANES:
        graph.add_node(f"{lane}Lane", LANE_NODES[lane])
    graph.add_node("join", join)
    graph.add_node("correlate", correlate)
    graph.add_node("conformanceGate", conformance_gate)

    graph.add_edge(START, "intake")
    graph.add_edge("intake", "detect")
    graph.add_edge("detect", "fanout")

    # The fan-out: one edge out of fanout per lane, one edge into join per lane.
    # LangGraph runs the five as a concurrent superstep and the state reducers
    # merge their writes.
    for lane in ALL_LANES:
        graph.add_edge("fanout", f"{lane}Lane")
        graph.add_edge(f"{lane}Lane", "join")

    graph.add_edge("join", "correlate")
    graph.add_edge("correlate", "conformanceGate")
    graph.add_edge("conformanceGate", END)

    return graph


def compile_assessment_graph() -> Any:
    return build_assessment_graph().compile()
