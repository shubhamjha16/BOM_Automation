"""S10's gap-filler: lifecycle data the deterministic feeds could not answer.

**Batched per distinct product, never per component** (§11). A 50,000-component
SBOM has perhaps forty unknown products; per-component retrieval would be forty
thousand loops and a cost failure rather than a design choice. The caller batches
before it gets here — `kb/enrichment.batch_key_for` is what does that — and this
module runs one loop per batch key.

**Results land in a review queue, not the assessment.** An agent-sourced EOL date
is marked `needs_review` and its source is `agent`, so the assessment can say
"researched, not supplier-declared, not yet confirmed" — three different claims
that a single populated field would flatten into one.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from app.services.agents.evidence import Proposal
from app.services.agents.loop import BatchReport, Retrieved, Retriever, run_loop
from app.services.agents.sufficiency import Sufficiency, supports_lifecycle
from app.utils.logger import get_logger

logger = get_logger(__name__)

KIND = "enrich"


def plan_query(batch_key: str, angle: str | None) -> str:
    """The next query for a product's lifecycle.

    The first hop asks the obvious question; later hops use the angle the
    sufficiency gate suggested, because repeating the first query returns the
    first answer.
    """
    product = batch_key.split("/")[-1]
    if angle is None:
        return f"{product} end of life date support schedule"
    return f"{product} {angle}"


def gate(batch_key: str, retrieved: Retrieved) -> Sufficiency:
    return supports_lifecycle(batch_key, retrieved.snippet or "")


@dataclass(slots=True)
class EnrichmentProposal:
    """An agent-researched lifecycle answer, awaiting confirmation."""

    product: str
    eol_date: str | None
    proposal: Proposal

    @property
    def needs_review(self) -> bool:
        return True  # always: agents research, they never decide

    def as_row(self) -> dict[str, Any]:
        return {
            **self.proposal.as_row(),
            "product": self.product,
            "eol_date": self.eol_date,
            "source": "agent",
            "status": "needs_review",
        }


async def resolve_batches(
    batch_keys: list[str],
    *,
    retriever: Retriever,
    components_per_key: dict[str, int] | None = None,
    max_hops: int | None = None,
) -> tuple[list[EnrichmentProposal], BatchReport]:
    """Research every unresolved product, one bounded loop each."""
    proposals: list[EnrichmentProposal] = []
    raw: list[Proposal] = []
    total_hops = 0

    for batch_key in batch_keys:
        result = await run_loop(
            batch_key=batch_key,
            planner=plan_query,
            retriever=retriever,
            gate=gate,
            max_hops=max_hops,
        )
        total_hops += result.proposal.hops
        raw.append(result.proposal)
        proposals.append(
            EnrichmentProposal(
                product=batch_key,
                # None whenever unresolved — never a plausible-looking date.
                eol_date=result.proposal.value if result.proposal.is_actionable else None,
                proposal=result.proposal,
            )
        )

    report = BatchReport(
        proposals=raw,
        total_hops=total_hops,
        components_covered=sum((components_per_key or {}).get(key, 1) for key in batch_keys),
    )
    logger.info("enrich_agent_batch_complete", **report.as_table())
    return proposals, report
