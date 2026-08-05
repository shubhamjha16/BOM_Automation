"""Drafting one assessment section. Orchestration only — no SQL, no rules.

**Returns the retrieved passages alongside the draft, deliberately.** A drafted
paragraph on its own is unfalsifiable: a reader cannot tell whether the wording
came from the firm's own house style or from the model's imagination, nor whether
any figure in it was earned. Showing the fact-masked sources beside it makes both
checkable — the ⟨count⟩ and ⟨clause⟩ placeholders in those passages are the
visible proof that the model saw the firm's sentence shape and none of another
client's numbers. The route handler stays thin and this explanation lives here,
because §13 caps a handler at fifteen lines and the suite enforces it — which is
how this docstring ended up in the right file.
"""

from __future__ import annotations

import uuid
from typing import Any

from app.repositories.corpusRepository import CorpusRepository
from app.repositories.laneRepository import LaneRepository
from app.services.llm.anthropicClient import active_generator
from app.services.narrative.drafter import UnsupportedFigure, draft_section


async def draft(
    lanes: LaneRepository,
    corpus: CorpusRepository,
    *,
    submission_id: uuid.UUID,
    section: str,
    engagement_id: uuid.UUID | None = None,
) -> dict[str, Any]:
    """Draft one section from the engine's own field verdicts."""
    facts = await _facts_for(lanes, submission_id, section)

    try:
        drafted = await draft_section(
            corpus,
            section=section,
            facts=facts,
            engagement_id=engagement_id,
            generator=active_generator(),
        )
    except UnsupportedFigure as error:
        # Surfaced rather than swallowed. A refused draft is the boundary doing
        # its job, and a reader watching a demo should see it happen.
        return {
            "section": section,
            "refused": True,
            "reason": str(error),
            "supplied_facts": facts.splitlines(),
        }

    return {
        **drafted.as_row(),
        "refused": False,
        "facts": facts.splitlines(),
        "retrieval": drafted.retrieval.as_report() if drafted.retrieval else None,
    }


async def _facts_for(
    lanes: LaneRepository, submission_id: uuid.UUID, section: str
) -> str:
    """The FACTS block: verdicts the engine produced, and nothing else.

    Built from `field_verdicts` rows rather than from prose, so every figure the
    drafter is permitted to restate traces to a scored element.
    """
    lines: list[str] = []

    for result in await lanes.for_submission(submission_id):
        if result.score is not None:
            lines.append(
                f"- {result.lane.upper()} lane: {result.verdict}, scored {result.score}%"
            )
        for verdict in await lanes.verdicts_for(result.id):
            # Only unmet elements. A section about what a supplier must fix does
            # not need the model restating what they already did.
            if str(verdict.verdict) == "present":
                continue
            lines.append(
                f"- {verdict.clause} {verdict.element_key} ({result.lane.upper()}): "
                f"{verdict.verdict}, declared on {verdict.populated} of {verdict.total}"
            )

    return "\n".join(lines[:24]) or "(no findings recorded for this submission)"
