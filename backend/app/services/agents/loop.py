"""The bounded agentic loop: plan → retrieve → sufficiency → re-query.

**What makes this agentic rather than a search call** is the sufficiency gate. A
search returns the first plausible result; this asks whether what came back
actually supports a determination, and re-queries *from a different angle* when
it does not. Re-querying from the same angle returns the same answer, so a gate
that cannot suggest a new angle stops the loop rather than burning the budget.

**Three hard rules, all from §11:**

* **The hop budget is a cap, not a target.** When it runs out the loop reports
  `hop_budget_exhausted` and no value. A plausible-looking guess at the end of a
  budget is the single worst thing this component could produce — it is
  indistinguishable from a researched answer and it is wrong.
* **Nothing ships unevidenced.** A resolved proposal must carry supporting
  evidence with a source URL, enforced in `Proposal.__post_init__`.
* **The loop proposes; a human confirms.** It writes to a review queue, never to
  the registry or the assessment.

The retriever is injected. That keeps the loop's control flow testable without a
network or a model — and the control flow is where the rules above live.
"""

from __future__ import annotations

from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from typing import Any

from app.configs.envConfig import settings
from app.services.agents.evidence import Evidence, Proposal, unresolved
from app.services.agents.sufficiency import Sufficiency
from app.utils.logger import get_logger

logger = get_logger(__name__)


@dataclass(frozen=True, slots=True)
class Retrieved:
    """One retrieval result."""

    url: str | None
    snippet: str
    #: The value the retriever extracted, if any. The gate decides whether to
    #: trust it; the retriever never decides.
    candidate: Any = None


#: Given a query, return what was found. Injected so the loop is testable.
Retriever = Callable[[str], Awaitable[Retrieved]]
#: Given the batch key and the previous angle, produce the next query.
Planner = Callable[[str, str | None], str]
#: Given the batch key and a retrieval, decide whether it suffices.
Gate = Callable[[str, Retrieved], Sufficiency]


@dataclass(frozen=True, slots=True)
class LoopResult:
    proposal: Proposal
    #: Every query issued, for the cost table the sprint exits on.
    queries: list[str]


async def run_loop(
    *,
    batch_key: str,
    planner: Planner,
    retriever: Retriever,
    gate: Gate,
    max_hops: int | None = None,
    min_confidence: float | None = None,
) -> LoopResult:
    """Research one batch key, bounded.

    `batch_key` is a distinct *product*, never a component — batching is what
    makes this affordable, and it is the caller's job to have done it.
    """
    budget = max_hops if max_hops is not None else settings.AGENT_MAX_HOPS
    floor = min_confidence if min_confidence is not None else settings.AGENT_MIN_CONFIDENCE

    evidence: list[Evidence] = []
    queries: list[str] = []
    angle: str | None = None

    for hop in range(1, budget + 1):
        query = planner(batch_key, angle)
        queries.append(query)

        retrieved = await retriever(query)
        verdict = gate(batch_key, retrieved)
        evidence.append(
            Evidence(
                hop=hop,
                query=query,
                source_url=retrieved.url,
                snippet=(retrieved.snippet or "")[:500],
                supports=verdict.sufficient,
                confidence=verdict.confidence,
            )
        )

        if verdict.sufficient and retrieved.candidate is not None:
            if verdict.confidence < floor:
                # Sufficient in kind but not in strength. Reported as
                # insufficient rather than shipped with a caveat nobody reads.
                logger.info(
                    "agent_below_confidence_floor",
                    batch_key=batch_key,
                    confidence=verdict.confidence,
                    floor=floor,
                )
                return LoopResult(
                    proposal=unresolved(
                        batch_key,
                        hops=hop,
                        reason=(
                            f"best candidate scored {verdict.confidence:.2f}, below the "
                            f"{floor:.2f} confidence floor"
                        ),
                        evidence=evidence,
                    ),
                    queries=queries,
                )

            logger.info("agent_resolved", batch_key=batch_key, hops=hop)
            return LoopResult(
                proposal=Proposal(
                    batch_key=batch_key,
                    value=retrieved.candidate,
                    confidence=verdict.confidence,
                    hops=hop,
                    evidence=evidence,
                    verdict="resolved",
                    reason=verdict.reason,
                ),
                queries=queries,
            )

        angle = verdict.next_angle
        if angle is None:
            # No new angle to try. Re-querying identically would return the same
            # answer and spend budget to learn nothing.
            logger.info("agent_no_further_angle", batch_key=batch_key, hops=hop)
            return LoopResult(
                proposal=unresolved(
                    batch_key,
                    hops=hop,
                    reason=f"no further angle to search: {verdict.reason}",
                    evidence=evidence,
                ),
                queries=queries,
            )

    logger.info("agent_hop_budget_exhausted", batch_key=batch_key, hops=budget)
    return LoopResult(
        proposal=unresolved(
            batch_key,
            hops=budget,
            reason=(
                f"hop budget of {budget} exhausted without sufficient evidence; "
                "reporting unresolved rather than a plausible-looking guess"
            ),
            evidence=evidence,
        ),
        queries=queries,
    )


@dataclass(slots=True)
class BatchReport:
    """The cost and hop table the sprint exits on."""

    proposals: list[Proposal]
    total_hops: int = 0
    #: Components covered by these proposals — the batching ratio.
    components_covered: int = 0

    @property
    def resolved(self) -> list[Proposal]:
        return [item for item in self.proposals if item.is_actionable]

    @property
    def unresolved(self) -> list[Proposal]:
        return [item for item in self.proposals if not item.is_actionable]

    @property
    def batching_ratio(self) -> float:
        """Components per agent run. The number that makes this affordable."""
        if not self.proposals:
            return 0.0
        return round(self.components_covered / len(self.proposals), 1)

    def as_table(self) -> dict[str, Any]:
        return {
            "batches": len(self.proposals),
            "components_covered": self.components_covered,
            "components_per_batch": self.batching_ratio,
            "total_hops": self.total_hops,
            "resolved": len(self.resolved),
            "unresolved": len(self.unresolved),
            "hop_budget_exhausted": sum(
                1 for item in self.proposals if item.verdict == "hop_budget_exhausted"
            ),
        }
