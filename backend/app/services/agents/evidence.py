"""Evidence. **Every agentic output is evidenced or it does not ship** (§11).

An agent that returns a date without a source is indistinguishable from an agent
that guessed one, and the difference is the entire reason this product can be
sold to a firm that signs assessments. So a proposal carries where it looked,
what it read, how confident it is and how many hops it took — and a proposal with
no supporting evidence cannot be constructed.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass(frozen=True, slots=True)
class Evidence:
    """One retrieval, kept whether or not it supported the answer.

    Non-supporting evidence is retained deliberately: a reviewer needs to see
    what was searched and rejected, not only what was accepted, or "we found
    nothing" is unfalsifiable.
    """

    hop: int
    query: str
    source_url: str | None
    snippet: str
    supports: bool
    confidence: float

    def __post_init__(self) -> None:
        if not 0.0 <= self.confidence <= 1.0:
            raise ValueError(f"confidence must be in [0, 1], got {self.confidence}")
        if self.supports and not self.source_url:
            raise ValueError(
                "supporting evidence must carry a source URL; an unsourced claim is "
                "a guess wearing a citation's clothes"
            )


@dataclass(slots=True)
class Proposal:
    """What an agent produces. Never a decision — a proposal for confirmation.

    `value` is the researched answer. It reaches a review queue, not the
    assessment: §11 is explicit that agents research and never decide.
    """

    batch_key: str
    value: Any
    confidence: float
    hops: int
    evidence: list[Evidence] = field(default_factory=list)
    #: 'resolved' | 'insufficient' | 'hop_budget_exhausted'
    verdict: str = "resolved"
    reason: str = ""

    def __post_init__(self) -> None:
        if self.verdict == "resolved":
            if self.value is None:
                raise ValueError("a resolved proposal must carry a value")
            if not any(item.supports for item in self.evidence):
                raise ValueError(
                    f"{self.batch_key}: a resolved proposal must carry at least one "
                    "supporting piece of evidence — unevidenced output does not ship"
                )

    @property
    def is_actionable(self) -> bool:
        return self.verdict == "resolved" and self.value is not None

    @property
    def supporting(self) -> list[Evidence]:
        return [item for item in self.evidence if item.supports]

    def as_row(self) -> dict[str, Any]:
        return {
            "batch_key": self.batch_key,
            "verdict": self.verdict,
            "hops": self.hops,
            "confidence": self.confidence,
            "value": self.value,
            "reason": self.reason,
            "evidence_count": len(self.evidence),
        }


def unresolved(batch_key: str, *, hops: int, reason: str, evidence: list[Evidence]) -> Proposal:
    """A proposal that resolved nothing.

    **This is the important constructor.** A hop budget that runs out reports
    "unresolved" and never a plausible-looking guess — the difference between a
    research assistant and a fabricator.
    """
    return Proposal(
        batch_key=batch_key,
        value=None,
        confidence=0.0,
        hops=hops,
        evidence=evidence,
        verdict="hop_budget_exhausted" if "budget" in reason.lower() else "insufficient",
        reason=reason,
    )
