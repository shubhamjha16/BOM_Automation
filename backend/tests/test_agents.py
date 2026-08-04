"""S10: the bounded agentic loop.

**What is tested here and what is not.** The loop's *control flow* is the part
that carries the §11 rules — the hop budget, the sufficiency gate, the evidence
requirement, batching per product — and it is fully tested, with a deterministic
retriever injected in place of a model.

Live model calls are **not** tested. The LLM keys in this environment are dev
placeholders, so nothing here proves a real model returns useful text. That is a
genuine gap and it is named rather than papered over: what these tests establish
is that whatever a model returns, an unevidenced or low-confidence answer cannot
become an assessment field.
"""

from __future__ import annotations

import pytest

from app.services.agents.enrichAgent import plan_query, resolve_batches
from app.services.agents.evidence import Evidence, Proposal, unresolved
from app.services.agents.loop import BatchReport, Retrieved, run_loop
from app.services.agents.sufficiency import (
    is_organisation,
    supports_lifecycle,
)


def _retriever(*responses: Retrieved):
    """A retriever that returns each response in turn, then repeats the last."""
    queue = list(responses)

    async def retrieve(query: str) -> Retrieved:
        return queue.pop(0) if len(queue) > 1 else queue[0]

    return retrieve


def _always(snippet: str, *, url: str | None = None, candidate=None):
    async def retrieve(query: str) -> Retrieved:
        return Retrieved(url=url, snippet=snippet, candidate=candidate)

    return retrieve


# --- the hop budget is a cap, not a target ----------------------------------


async def test_an_exhausted_hop_budget_reports_unresolved_never_a_guess():
    """The §S10 exit proof, and the rule that separates research from fabrication."""
    result = await run_loop(
        batch_key="obscure-lib",
        planner=plan_query,
        retriever=_always("a page that mentions obscure-lib but states no date"),
        gate=lambda key, r: supports_lifecycle(key, r.snippet),
        max_hops=3,
    )

    assert result.proposal.value is None
    assert result.proposal.verdict == "hop_budget_exhausted"
    assert result.proposal.hops == 3
    assert "rather than a plausible-looking guess" in result.proposal.reason
    assert not result.proposal.is_actionable


async def test_the_budget_is_honoured_exactly():
    for budget in (1, 2, 5):
        result = await run_loop(
            batch_key="x",
            planner=plan_query,
            retriever=_always("mentions x but no date"),
            gate=lambda key, r: supports_lifecycle(key, r.snippet),
            max_hops=budget,
        )
        assert result.proposal.hops == budget
        assert len(result.queries) == budget


async def test_the_loop_stops_early_when_there_is_no_new_angle():
    """Re-querying identically returns the same answer and spends budget to
    learn nothing."""
    result = await run_loop(
        batch_key="anything",
        planner=plan_query,
        retriever=_always(""),  # empty retrieval yields no next angle
        gate=lambda key, r: supports_lifecycle(key, r.snippet),
        max_hops=5,
    )
    assert result.proposal.hops == 1
    assert "no further angle" in result.proposal.reason


async def test_a_re_query_uses_a_different_angle():
    """The sufficiency gate's whole job is to redirect, not merely to reject."""
    seen: list[str] = []

    async def retrieve(query: str) -> Retrieved:
        seen.append(query)
        if len(seen) == 1:
            return Retrieved(url="https://a", snippet="acme is a library", candidate=None)
        return Retrieved(
            url="https://b",
            snippet="acme reaches end of life on 2030-01-01",
            candidate="2030-01-01",
        )

    result = await run_loop(
        batch_key="acme",
        planner=plan_query,
        retriever=retrieve,
        gate=lambda key, r: supports_lifecycle(key, r.snippet),
        max_hops=3,
    )
    assert result.proposal.is_actionable
    assert seen[0] != seen[1], "the loop re-queried from the same angle"


# --- nothing ships unevidenced ----------------------------------------------


def test_a_resolved_proposal_without_supporting_evidence_cannot_be_built():
    """Enforced at construction: unevidenced output does not ship."""
    with pytest.raises(ValueError, match="supporting piece of evidence"):
        Proposal(batch_key="x", value="2030-01-01", confidence=0.9, hops=1, evidence=[])


def test_supporting_evidence_must_carry_a_source_url():
    """An unsourced claim is a guess wearing a citation's clothes."""
    with pytest.raises(ValueError, match="must carry a source URL"):
        Evidence(hop=1, query="q", source_url=None, snippet="s", supports=True, confidence=0.9)


def test_non_supporting_evidence_is_retained():
    """A reviewer needs to see what was searched and rejected, or "we found
    nothing" is unfalsifiable."""
    proposal = unresolved(
        "x",
        hops=2,
        reason="nothing found",
        evidence=[
            Evidence(
                hop=1,
                query="a",
                source_url="https://a",
                snippet="s",
                supports=False,
                confidence=0.1,
            ),
            Evidence(
                hop=2, query="b", source_url=None, snippet="s", supports=False, confidence=0.0
            ),
        ],
    )
    assert len(proposal.evidence) == 2
    assert proposal.supporting == []


def test_confidence_must_be_a_probability():
    with pytest.raises(ValueError, match="confidence must be in"):
        Evidence(
            hop=1, query="q", source_url="https://a", snippet="s", supports=True, confidence=1.5
        )


async def test_a_resolved_answer_carries_its_evidence_chain():
    result = await run_loop(
        batch_key="acme",
        planner=plan_query,
        retriever=_always(
            "acme reaches end of life on 2030-01-01",
            url="https://vendor.example/eol",
            candidate="2030-01-01",
        ),
        gate=lambda key, r: supports_lifecycle(key, r.snippet),
    )
    proposal = result.proposal
    assert proposal.is_actionable
    assert proposal.supporting
    assert proposal.supporting[0].source_url == "https://vendor.example/eol"


# --- the confidence floor ---------------------------------------------------


async def test_an_answer_below_the_confidence_floor_is_reported_unresolved():
    """Sufficient in kind but not in strength. Reported rather than shipped with
    a caveat nobody reads."""
    from app.services.agents.sufficiency import Sufficiency

    result = await run_loop(
        batch_key="x",
        planner=plan_query,
        retriever=_always("something", url="https://a", candidate="2030-01-01"),
        gate=lambda key, r: Sufficiency(True, 0.3, "weakly supported"),
        min_confidence=0.6,
    )
    assert result.proposal.value is None
    assert result.proposal.verdict == "insufficient"
    assert "below the 0.60 confidence floor" in result.proposal.reason


# --- batching per product, never per component ------------------------------


async def test_batching_is_per_product_not_per_component():
    """The §S10 exit proof: a 50,000-component SBOM has ~40 unknown products."""
    proposals, report = await resolve_batches(
        ["maven/org.apache/tomcat", "pypi/django"],
        retriever=_always("nothing useful"),
        components_per_key={"maven/org.apache/tomcat": 4200, "pypi/django": 800},
    )

    table = report.as_table()
    assert table["batches"] == 2
    assert table["components_covered"] == 5000
    assert table["components_per_batch"] == 2500.0
    assert len(proposals) == 2


async def test_the_cost_table_reports_the_deterministic_versus_agentic_split():
    proposals, report = await resolve_batches(
        ["a", "b"],
        retriever=_always(
            "a reaches end of life on 2030-01-01", url="https://x", candidate="2030-01-01"
        ),
        components_per_key={"a": 10, "b": 10},
    )
    table = report.as_table()
    assert table["total_hops"] >= 2
    assert table["resolved"] + table["unresolved"] == table["batches"]


def test_an_empty_batch_report_does_not_divide_by_zero():
    assert BatchReport(proposals=[]).batching_ratio == 0.0


# --- results are proposals, never decisions ---------------------------------


async def test_every_agent_result_lands_in_a_review_queue():
    """§11: agents research; they never decide."""
    proposals, _ = await resolve_batches(
        ["acme"],
        retriever=_always(
            "acme reaches end of life on 2030-01-01", url="https://x", candidate="2030-01-01"
        ),
    )
    row = proposals[0].as_row()
    assert row["status"] == "needs_review"
    assert row["source"] == "agent"
    assert proposals[0].needs_review is True


async def test_an_unresolved_batch_carries_no_date_at_all():
    proposals, _ = await resolve_batches(["ghost"], retriever=_always("unrelated"))
    assert proposals[0].eol_date is None
    assert proposals[0].as_row()["eol_date"] is None


# --- the sufficiency gates --------------------------------------------------


@pytest.mark.parametrize(
    ("candidate", "accepted"),
    [
        ("Apache Software Foundation", True),
        ("Acme Technologies", True),
        ("The Linux Foundation", True),
        ("torvalds", False),
        ("github.com/sindresorhus", False),
        ("mirror of nginx", False),
        ("unofficial fork of redis", False),
        ("", False),
    ],
)
def test_the_supplier_gate_admits_organisations_and_refuses_handles(candidate, accepted):
    """The S11 exit proof, checked here because the gate is shared."""
    assert is_organisation(candidate).sufficient is accepted


def test_a_rejected_handle_gets_a_different_angle_to_try():
    verdict = is_organisation("torvalds")
    assert not verdict.sufficient
    assert verdict.next_angle
    assert "governance" in verdict.next_angle


def test_a_date_near_a_product_name_is_not_an_eol_date():
    """The exact failure a search box makes and a sufficiency gate prevents."""
    verdict = supports_lifecycle("django", "django 4.2 was released on 2023-04-03")
    assert not verdict.sufficient
    assert "nothing marks it as an end-of-life" in verdict.reason


def test_text_that_does_not_mention_the_product_is_refused():
    verdict = supports_lifecycle("django", "flask reaches end of life on 2030-01-01")
    assert not verdict.sufficient
    assert "does not mention" in verdict.reason


def test_a_real_eol_statement_is_accepted():
    verdict = supports_lifecycle(
        "django", "Django 3.2 reaches end of life on 2024-04-01 per the roadmap"
    )
    assert verdict.sufficient
    assert verdict.confidence >= 0.6
