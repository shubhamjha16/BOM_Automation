"""Conditional-edge predicates.

Kept out of `builder.py` so wiring stays readable and routing stays testable
without compiling a graph. S15 adds the narrative branch (drafter → critic →
healer, bounded at 2 attempts); S8 wires the gate's blocked path to END.
"""

from __future__ import annotations

from typing import Literal

from app.configs.jobTypes import JobStatus
from app.services.graph.state import GraphState

MAX_HEAL_ATTEMPTS = 2


def after_gate(state: GraphState) -> Literal["render", "blocked"]:
    """A blocked gate renders nothing at all."""
    blocked = state.get("status") == JobStatus.BLOCKED_CONFORMANCE
    if state.get("gate_verdict") == "blocked" or blocked:
        return "blocked"
    return "render"


def after_critic(state: GraphState) -> Literal["heal", "render"]:
    """Bounded at two heal attempts, as in the sibling factories.

    An unbounded critic/healer loop on a model that disagrees with itself burns
    the budget and still ships the third draft.
    """
    if state.get("critic_notes") and state.get("heal_attempts", 0) < MAX_HEAL_ATTEMPTS:
        return "heal"
    return "render"
