"""Assemble the evidence a VEX justification needs. **Never set the status.**

The four statuses of rec. 7.1.6 are an analyst's determination. A machine-set VEX
status is professional judgement laundered through a model: the firm's name goes
on a statement telling a client to stop investigating a live vulnerability, and
nobody made that call. So this module has no code path that produces a status —
`draft()` returns a justification and evidence, and the status field is filled by
whoever signs it.

**What the sufficiency check asks here is different from S10 and S11.** Those ask
"is this a date?" and "is this an organisation?". This one asks whether the
retrieved text *supports a determination about this CVE in this configuration*,
or merely **mentions the CVE**. An advisory listing a CVE proves the CVE exists;
it says nothing about whether the product is affected. Treating the first as the
second is exactly how a `not_affected` gets issued for a product that is affected.

**Insufficient evidence proposes `under_investigation`**, never `not_affected`.
Reasoning toward "not affected" because nothing was found turns an absence of
evidence into a clearance.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any

from app.services.agents.evidence import Evidence, Proposal
from app.services.agents.loop import BatchReport, Retrieved, Retriever, run_loop
from app.services.agents.sufficiency import Sufficiency
from app.services.vex.authoring import VexStatus, default_status_for_insufficient_evidence
from app.utils.logger import get_logger

logger = get_logger(__name__)

KIND = "vex_evidence"

#: Language that indicates a determination rather than a mention. An advisory
#: that says "affected versions 2.0 through 2.14" is evidence; one that lists the
#: CVE in a table of references is not.
_DETERMINATION_MARKERS = (
    "not affected",
    "unaffected",
    "affected versions",
    "affected releases",
    "fixed in",
    "resolved in",
    "patched in",
    "remediated in",
    "does not affect",
    "is not exploitable",
    "not exploitable",
    "requires configuration",
    "only exploitable",
    "mitigated by",
)

#: The four questions a justification has to answer, per the sprint spec.
EVIDENCE_ANGLES: tuple[str, ...] = (
    "vendor security advisory affected version range",
    "CERT-In vulnerability note",
    "whether the vulnerable code path is reachable in a default configuration",
    "upstream fix commit or release notes",
)

_CVE = re.compile(r"CVE-\d{4}-\d{4,}", re.IGNORECASE)


def plan_query(batch_key: str, angle: str | None) -> str:
    """batch_key is 'CVE-XXXX-NNNN|component'."""
    cve, _, component = batch_key.partition("|")
    if angle is None:
        return f"{cve} {component} {EVIDENCE_ANGLES[0]}"
    return f"{cve} {component} {angle}"


def _next_angle(used: str | None) -> str | None:
    """Walk the angles in order; None once they are exhausted."""
    if used is None:
        return EVIDENCE_ANGLES[1]
    try:
        index = EVIDENCE_ANGLES.index(used)
    except ValueError:
        return EVIDENCE_ANGLES[1]
    return EVIDENCE_ANGLES[index + 1] if index + 1 < len(EVIDENCE_ANGLES) else None


def supports_determination(batch_key: str, snippet: str) -> Sufficiency:
    """Does this text support a determination, or merely mention the CVE?"""
    cve, _, component = batch_key.partition("|")
    text = (snippet or "").strip()

    if not text:
        return Sufficiency(False, 0.0, "nothing was retrieved", next_angle=EVIDENCE_ANGLES[1])

    lowered = text.lower()
    mentions_cve = bool(_CVE.search(text)) and cve.lower() in lowered

    if not mentions_cve:
        return Sufficiency(
            False,
            0.0,
            f"the retrieved text does not discuss {cve}",
            next_angle=EVIDENCE_ANGLES[1],
        )

    determination = [marker for marker in _DETERMINATION_MARKERS if marker in lowered]
    if not determination:
        # The distinction this whole module exists for.
        return Sufficiency(
            False,
            0.2,
            (
                f"the text mentions {cve} but states no affected-version range, fix "
                "or reachability condition — it proves the vulnerability exists, not "
                "whether this product is affected"
            ),
            next_angle=EVIDENCE_ANGLES[1],
        )

    confidence = 0.8 if len(determination) > 1 else 0.65
    return Sufficiency(
        True,
        confidence,
        f"the text states a determination ({', '.join(determination[:2])})",
    )


def gate(batch_key: str, retrieved: Retrieved) -> Sufficiency:
    return supports_determination(batch_key, retrieved.snippet or "")


@dataclass(slots=True)
class VexDraft:
    """A drafted justification and its evidence. **Carries no status decision.**

    `suggested_status` exists only to carry `under_investigation` where evidence
    was insufficient — the one honest default. It is never `not_affected` and
    never `fixed`; those are determinations, and this module does not make them.
    """

    cve_id: str
    component_ref: str | None
    justification: str | None
    evidence: list[Evidence]
    hops: int
    confidence: float
    #: Always UNDER_INVESTIGATION when evidence was insufficient; None otherwise,
    #: because a sufficient evidence set still does not decide the status.
    suggested_status: VexStatus | None

    @property
    def is_drafted(self) -> bool:
        return bool(self.justification)

    def as_row(self) -> dict[str, Any]:
        return {
            "cve_id": self.cve_id,
            "component_ref": self.component_ref,
            "justification": self.justification,
            # Deliberately absent: `status`. The analyst supplies it.
            "suggested_status": str(self.suggested_status) if self.suggested_status else None,
            "confidence": self.confidence,
            "hops": self.hops,
            "evidence": [
                {
                    "hop": item.hop,
                    "source_url": item.source_url,
                    "supports": item.supports,
                    "snippet": item.snippet[:200],
                }
                for item in self.evidence
            ],
            "status": None,  # never set by an agent
            "requires_analyst_determination": True,
        }


def _compose(cve_id: str, component: str | None, proposal: Proposal) -> str:
    """Assemble a justification from what was actually found.

    Written as a summary of evidence, not as a conclusion. The analyst reads it,
    checks the sources and decides — so it must not read as though the decision
    has been made.
    """
    supporting = proposal.supporting
    citations = [item.source_url for item in supporting if item.source_url]
    lead = f"Evidence assembled for {cve_id}"
    if component:
        lead += f" in {component}"

    findings = " ".join(item.snippet.strip() for item in supporting)[:600]
    sources = "; ".join(citations)
    return (
        f"{lead}. Retrieved across {proposal.hops} hop(s): {findings} "
        f"Sources: {sources}. "
        "This is assembled evidence, not a determination — the status remains for "
        "an analyst to set."
    )


async def draft_for(
    cve_id: str,
    *,
    component_ref: str | None,
    retriever: Retriever,
    max_hops: int | None = None,
) -> VexDraft:
    """Research one CVE/component pair and draft a justification."""
    batch_key = f"{cve_id}|{component_ref or ''}"

    def planner(key: str, angle: str | None) -> str:
        return plan_query(key, angle)

    def stepping_gate(key: str, retrieved: Retrieved) -> Sufficiency:
        verdict = gate(key, retrieved)
        if verdict.sufficient:
            return verdict
        # Walk to the next unexplored angle rather than repeating one.
        return Sufficiency(
            verdict.sufficient,
            verdict.confidence,
            verdict.reason,
            next_angle=_next_angle(verdict.next_angle),
        )

    result = await run_loop(
        batch_key=batch_key,
        planner=planner,
        retriever=retriever,
        gate=stepping_gate,
        max_hops=max_hops,
    )
    proposal = result.proposal

    if proposal.is_actionable:
        return VexDraft(
            cve_id=cve_id,
            component_ref=component_ref,
            justification=_compose(cve_id, component_ref, proposal),
            evidence=proposal.evidence,
            hops=proposal.hops,
            confidence=proposal.confidence,
            # Sufficient evidence still does not decide the status.
            suggested_status=None,
        )

    logger.info("vex_evidence_insufficient", cve_id=cve_id, reason=proposal.reason)
    return VexDraft(
        cve_id=cve_id,
        component_ref=component_ref,
        justification=None,
        evidence=proposal.evidence,
        hops=proposal.hops,
        confidence=0.0,
        # The one honest default. Never not_affected.
        suggested_status=default_status_for_insufficient_evidence(),
    )


async def draft_batch(
    pairs: list[tuple[str, str | None]],
    *,
    retriever: Retriever,
    max_hops: int | None = None,
) -> tuple[list[VexDraft], BatchReport]:
    drafts: list[VexDraft] = []
    raw: list[Proposal] = []
    total_hops = 0

    for cve_id, component_ref in pairs:
        draft = await draft_for(
            cve_id, component_ref=component_ref, retriever=retriever, max_hops=max_hops
        )
        drafts.append(draft)
        total_hops += draft.hops
        raw.append(
            Proposal(
                batch_key=f"{cve_id}|{component_ref or ''}",
                value=draft.justification,
                confidence=draft.confidence,
                hops=draft.hops,
                evidence=draft.evidence,
                verdict="resolved" if draft.is_drafted else "insufficient",
            )
            if draft.is_drafted
            else Proposal(
                batch_key=f"{cve_id}|{component_ref or ''}",
                value=None,
                confidence=0.0,
                hops=draft.hops,
                evidence=draft.evidence,
                verdict="insufficient",
            )
        )

    report = BatchReport(proposals=raw, total_hops=total_hops, components_covered=len(pairs))
    logger.info("vex_evidence_batch_complete", **report.as_table())
    return drafts, report
