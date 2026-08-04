"""S11's agent: "which organisation supplies this package?"

**The best agentic fit in the product**, and worth saying why. Field scoring is a
table lookup; clause resolution reads a fixed catalogue; correlation is a
deterministic join. Wrapping retrieval around any of those would add cost and
nondeterminism to operations that are currently exact. This question is
different: it is genuine research with no authoritative source, and the answer
does not exist in any dataset we could buy.

**The sufficiency check is the whole point.** Retrieval will happily return a
GitHub handle, a maintainer's personal account or a mirror. Publishing one as an
OrganizationName produces a CERT-In identifier that looks official, passes
review, and is wrong. So the gate refuses anything without an organisational
marker and re-queries from a different angle.

**Output is a proposal.** The agent never writes to `supplier_registry_entries`
— an agent with write access to the curated asset would compound its own
mistakes into every future assessment. A human confirms, and that confirmation
permanently improves the registry for every submission that follows.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from app.services.agents.evidence import Proposal
from app.services.agents.loop import BatchReport, Retrieved, Retriever, run_loop
from app.services.agents.sufficiency import Sufficiency, is_organisation
from app.utils.logger import get_logger

logger = get_logger(__name__)

KIND = "supplier"


def plan_query(batch_key: str, angle: str | None) -> str:
    """Ask who publishes a package; then ask differently.

    The angles escalate from the package registry to project governance, because
    a registry owner is often a handle while a governance page names the
    organisation that holds the trademark.
    """
    name = batch_key.split("/")[-1]
    if angle is None:
        return f"who publishes the {name} package — owning organisation"
    return f"{name} {angle}"


def gate(batch_key: str, retrieved: Retrieved) -> Sufficiency:
    """Is the candidate an organisation, or a handle?"""
    candidate = retrieved.candidate
    if not candidate:
        return Sufficiency(
            False,
            0.0,
            "no candidate organisation was extracted from the retrieved page",
            next_angle="governance page or trademark owner",
        )
    return is_organisation(str(candidate))


@dataclass(slots=True)
class SupplierProposal:
    """A proposed registry entry, awaiting human confirmation."""

    purl_type: str
    namespace_or_name: str
    proposed_supplier: str | None
    proposal: Proposal

    @property
    def status(self) -> str:
        return "pending" if self.proposal.is_actionable else "rejected"

    def as_row(self) -> dict[str, Any]:
        return {
            "purl_type": self.purl_type,
            "namespace_or_name": self.namespace_or_name,
            "proposed_supplier": self.proposed_supplier,
            "confidence": self.proposal.confidence,
            "hops": self.proposal.hops,
            "status": self.status,
            "reason": self.proposal.reason,
            "evidence": [
                {
                    "hop": item.hop,
                    "query": item.query,
                    "source_url": item.source_url,
                    "supports": item.supports,
                }
                for item in self.proposal.evidence
            ],
        }


async def resolve_suppliers(
    coordinates: list[str],
    *,
    retriever: Retriever,
    components_per_key: dict[str, int] | None = None,
    max_hops: int | None = None,
) -> tuple[list[SupplierProposal], BatchReport]:
    """Research each unresolved coordinate. One loop per product, never per component."""
    proposals: list[SupplierProposal] = []
    raw: list[Proposal] = []
    total_hops = 0

    for coordinate in coordinates:
        result = await run_loop(
            batch_key=coordinate,
            planner=plan_query,
            retriever=retriever,
            gate=gate,
            max_hops=max_hops,
        )
        total_hops += result.proposal.hops
        raw.append(result.proposal)

        parts = coordinate.split("/")
        proposals.append(
            SupplierProposal(
                purl_type=parts[0] if len(parts) > 1 else "generic",
                namespace_or_name=coordinate,
                proposed_supplier=(
                    str(result.proposal.value) if result.proposal.is_actionable else None
                ),
                proposal=result.proposal,
            )
        )

    report = BatchReport(
        proposals=raw,
        total_hops=total_hops,
        components_covered=sum((components_per_key or {}).get(key, 1) for key in coordinates),
    )
    logger.info("supplier_resolver_batch_complete", **report.as_table())
    return proposals, report


def confirm(proposal: SupplierProposal, *, reviewed_by: str) -> dict[str, Any]:
    """Promote a proposal into a curated registry entry.

    A human action, deliberately a separate function from anything the agent can
    reach. Confirming permanently improves the curated asset for every future
    submission — the compounding property S11 exists to build.
    """
    if not proposal.proposal.is_actionable:
        raise ValueError(
            f"{proposal.namespace_or_name}: cannot confirm a proposal the sufficiency "
            f"check rejected ({proposal.proposal.reason})"
        )
    return {
        "purl_type": proposal.purl_type,
        "namespace_or_name": proposal.namespace_or_name,
        "supplier_org": proposal.proposed_supplier,
        # Once a human signs it, it is curated and carries full confidence.
        "source": "curated",
        "confidence": 1.0,
        "verified_by": reviewed_by,
    }
