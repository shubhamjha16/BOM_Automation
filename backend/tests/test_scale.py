"""S21: a 50,000-component SBOM within a stated budget, and p95 per lane.

The budget is deliberately loose against the measured figure — 30s against a
measured 6.5s, 1 GB against a measured 210 MB. A budget set at the measurement
fails on a slow CI runner, gets marked flaky, and is deleted; one set at four times
the measurement still catches the regressions that matter, which are the
algorithmic ones. `dist/scale-report.md` carries the actual numbers.

The concurrency case exists to answer one question honestly: **does the fan-out
hold, or does it serialise?** The lane intervals overlap, which is what the
isolation properties depend on. It is not a speedup, and the test says so — five
lanes of pure-Python scoring hold the GIL, so twenty concurrent assessments finish
in about the time twenty in series would take. Concurrency means no client waits
behind another client's whole queue; it does not mean the machine does more work.
"""

from __future__ import annotations

import time

import pytest

from app.configs.envConfig import ALL_LANES
from app.scripts.scaleProfile import (
    BUDGET_PEAK_MB,
    BUDGET_SECONDS,
    LARGEST_SBOM,
    measure_concurrency,
    measure_largest,
    peak_mb,
    render,
    synthetic_aibom,
    synthetic_cbom,
    synthetic_hbom,
    synthetic_sbom,
)
from app.services.assessmentService import run_assessment
from app.services.graph.nodes.sbomLane import score_sbom
from app.services.graph.state import SubmissionDocument

pytestmark = pytest.mark.anyio


# --- the largest single document ---------------------------------------------


async def test_a_fifty_thousand_component_sbom_scores_within_budget():
    """The §S21 exit proof."""
    result = await measure_largest(LARGEST_SBOM)

    assert result["within_budget"], (
        f"{result['seconds']}s / {result['peak_mb']} MB against a budget of "
        f"{BUDGET_SECONDS}s / {BUDGET_PEAK_MB} MB"
    )
    assert result["seconds"] <= BUDGET_SECONDS
    assert result["peak_mb"] <= BUDGET_PEAK_MB


async def test_nothing_is_dropped_at_fifty_thousand_components():
    """§11: parsed + rejected must equal the input count, at every size. A
    silently truncated document scores as a complete one."""
    result = await measure_largest(LARGEST_SBOM)
    assert result["entities_scored"] == LARGEST_SBOM


def test_scoring_cost_is_linear_in_component_count():
    """The regression this actually guards against.

    A wall-clock budget catches a machine getting slower; it does not catch an
    accidental O(n²) — a nested lookup over the entity list would sit inside the
    budget at 5,000 components and blow through it at 50,000. Comparing the
    per-component cost across a tenfold range does catch it.
    """
    timings = {}
    for count in (2_000, 20_000):
        documents = [
            SubmissionDocument(
                lane="sbom", format="CycloneDX", payload=synthetic_sbom(count)
            )
        ]
        score_sbom(documents)  # warm: first call imports the catalogue
        started = time.perf_counter()
        score_sbom(documents)
        timings[count] = (time.perf_counter() - started) / count

    # Generous: a tenfold size increase must not triple the per-component cost.
    # Quadratic growth would multiply it by ten.
    assert timings[20_000] < timings[2_000] * 3, timings


def test_the_synthetic_document_is_not_the_easy_case():
    """A document whose fields are all absent short-circuits every probe on its
    first path and measures nothing worth measuring."""
    document = synthetic_sbom(3)
    component = document["components"][0]

    assert component["licenses"]
    assert component["supplier"]["name"]
    assert component["hashes"][0]["content"]
    assert document["metadata"]["authors"]
    assert document["metadata"]["timestamp"]


# --- concurrency, and what the overlap does and does not mean ----------------


async def test_twenty_concurrent_five_lane_assessments_hold():
    result = await measure_concurrency(count=20, components=500)

    assert result["assessments"] == 20
    assert set(result["per_lane"]) == set(ALL_LANES)
    for lane, stats in result["per_lane"].items():
        assert stats["n"] == 20, f"{lane} produced {stats['n']} samples of 20"
        assert stats["p50"] <= stats["p95"] <= stats["max"]


async def test_the_lane_intervals_genuinely_overlap():
    """The fan-out holds rather than serialising. Asserted with real work in every
    lane — with documents in one lane only, four lanes return immediately and
    "the intervals overlap" would be true of nothing."""
    result = await measure_concurrency(count=5, components=500)
    assert result["overlap_proven"]


async def test_the_overlap_is_not_claimed_as_a_speedup():
    """Five lanes of pure-Python scoring hold the GIL. A five-lane assessment
    costs about what five sequential lanes cost, and reporting the overlap as a
    performance win would be the kind of unfounded figure §11 exists to prevent.

    Asserted on the report text, because the claim is what ships.
    """
    largest = await measure_largest(1_000)
    concurrency = await measure_concurrency(count=3, components=200)
    report = render(largest, concurrency)

    assert "It is not a speedup" in report
    assert "GIL" in report
    assert "shares the throughput rather than adding to it" in report


async def test_every_concurrent_assessment_is_reconstructable_from_the_logs():
    """The S21 observability condition, under load rather than in isolation.
    Twenty assessments share one log stream, which is the normal case."""
    result = await measure_concurrency(count=10, components=200)
    assert result["traces_whole"]


async def test_per_lane_percentiles_are_reported_rather_than_one_aggregate():
    """An aggregate hides the number that answers the question: the slowest
    lane's p95 against the assessment's own."""
    result = await measure_concurrency(count=5, components=200)
    assert len(result["per_lane"]) == 5
    assert "seconds_each" in result


# --- repo generation is reported separately ---------------------------------


def test_repo_generation_is_not_folded_into_these_figures():
    """It takes minutes rather than seconds (S17) — it resolves a repository's
    dependencies in a sandbox — so averaging it into an assessment latency would
    make every figure here meaningless. It is metered separately (S21 quotas) and
    reported separately."""
    from app.services.quota.plans import PLAN_LIMITS, Plan

    limits = PLAN_LIMITS[Plan.PRACTICE]
    assert limits.repo_generations_per_month != limits.submissions_per_month


# --- the report ---------------------------------------------------------------


async def test_the_report_states_the_budget_and_the_measurement():
    largest = await measure_largest(1_000)
    concurrency = await measure_concurrency(count=3, components=200)
    report = render(largest, concurrency)

    assert f"{BUDGET_SECONDS:.0f}s" in report
    assert str(largest["seconds"]) in report
    assert str(largest["peak_mb"]) in report
    for lane in ALL_LANES:
        assert f"| {lane} |" in report


async def test_cost_is_reported_as_cpu_seconds_not_as_currency():
    """A currency figure depends on an instance price and a utilisation
    assumption. One this repository invented would be quoted back at it."""
    largest = await measure_largest(1_000)
    concurrency = await measure_concurrency(count=3, components=200)
    report = render(largest, concurrency)

    assert "CPU-seconds" in report
    assert largest["cpu_seconds"] > 0
    assert "₹" not in report and "$" not in report


def test_peak_memory_is_read_in_the_right_unit_for_this_platform():
    """`ru_maxrss` is kilobytes on Linux and bytes on macOS. Getting it wrong by
    1024× would either pass the budget always or fail it always."""
    assert 1.0 < peak_mb() < BUDGET_PEAK_MB * 8


def test_the_other_lanes_get_documents_they_can_actually_score():
    """A synthetic document the parser rejects would score zero and measure the
    rejection path rather than the scoring path."""
    for builder, lane in (
        (synthetic_aibom, "aibom"),
        (synthetic_cbom, "cbom"),
        (synthetic_hbom, "hbom"),
    ):
        assert builder(3)["components"], lane
        assert len(builder(3)["components"]) == 3


async def test_a_five_lane_assessment_scores_every_lane_it_was_given():
    """Guards the measurement itself: if a synthetic document stopped parsing, the
    p95 table would fill with lane_absent rows and still look healthy."""
    summary = await run_assessment(
        org_id="scale",
        submission_id="five-lane",
        documents=[
            SubmissionDocument(lane="sbom", format="CycloneDX", payload=synthetic_sbom(20)),
            SubmissionDocument(lane="aibom", format="CycloneDX", payload=synthetic_aibom(5)),
            SubmissionDocument(lane="cbom", format="CycloneDX", payload=synthetic_cbom(10)),
            SubmissionDocument(lane="qbom", format="CycloneDX", payload=synthetic_cbom(5)),
            SubmissionDocument(lane="hbom", format="CycloneDX", payload=synthetic_hbom(10)),
        ],
        requested_lanes=list(ALL_LANES),
    )

    scored = {result.lane: result.entity_count for result in summary.lane_results}
    for lane in ALL_LANES:
        assert scored[lane] > 0, f"{lane} scored nothing; the p95 table would be a lie"
