"""The S1 exit proof: two lanes run concurrently in one job.

The parallelism assertion is deliberately about overlapping wall-clock intervals
rather than total elapsed time. A "fast enough" assertion passes on a machine
that happens to be quick and tells you nothing about whether the graph fanned
out; overlapping intervals can only happen if it did.
"""

from __future__ import annotations

import asyncio

import pytest

from app.configs.jobTypes import JobStatus, LaneVerdict
from app.services.assessmentService import lane_rollup, run_assessment
from app.services.graph.nodes.intake import EmptySubmission
from app.services.graph.state import SubmissionDocument
from tests.conftest import component, cyclonedx_document, model_component


async def test_sbom_and_aibom_run_concurrently_in_one_job(sbom_document, aibom_document):
    summary = await run_assessment(
        org_id="org-a",
        submission_id="sub-1",
        documents=[sbom_document, aibom_document],
    )

    assert summary.status is JobStatus.SUCCEEDED
    # One job, five lane results — every lane reports, none is silently skipped.
    assert len(summary.lane_results) == 5

    scored = {result.lane for result in summary.lane_results if result.score is not None}
    assert scored == {"sbom", "aibom"}

    lane_runs = [run for run in summary.node_runs if run.lane is not None]
    assert len(lane_runs) == 5
    assert summary.parallelism_proven, (
        "no two lane runs overlapped in wall-clock time; the fan-out serialised"
    )


async def test_overlap_is_between_the_two_implemented_lanes(sbom_document, aibom_document):
    summary = await run_assessment(
        org_id="org-a", submission_id="sub-2", documents=[sbom_document, aibom_document]
    )
    runs = {run.lane: run for run in summary.node_runs if run.lane is not None}
    assert runs["sbom"].overlaps(runs["aibom"])


async def test_unimplemented_lanes_report_absent_not_a_score(sbom_document):
    summary = await run_assessment(
        org_id="org-a", submission_id="sub-3", documents=[sbom_document]
    )
    rollup = lane_rollup(summary)
    for lane in ("cbom", "qbom", "hbom"):
        assert rollup[lane]["verdict"] == LaneVerdict.LANE_ABSENT
        assert rollup[lane]["score"] is None, "an unimplemented lane must not emit a score"
        assert rollup[lane]["is_finding"] is True


async def test_disabled_lane_is_not_applicable_and_leaves_the_overall_score(
    sbom_document, aibom_document
):
    """lane_not_applicable is excluded from the overall score; lane_absent is not."""
    both = await run_assessment(
        org_id="org-a",
        submission_id="sub-4a",
        documents=[sbom_document, aibom_document],
        requested_lanes=["sbom", "aibom"],
    )
    rollup = lane_rollup(both)
    assert rollup["cbom"]["verdict"] == LaneVerdict.LANE_NOT_APPLICABLE
    assert rollup["cbom"]["counts_toward_overall"] is False
    assert rollup["cbom"]["is_finding"] is False

    # The overall score is the mean of the two lanes that ran, untouched by the three
    # the engagement did not enable.
    expected = round(
        (
            next(r.score for r in both.lane_results if r.lane == "sbom")
            + next(r.score for r in both.lane_results if r.lane == "aibom")
        )
        / 2,
        2,
    )
    assert both.overall_score == expected


async def test_absent_lane_does_drag_the_overall_score(sbom_document):
    """A client with cryptography and no CBOM has failed to declare it."""
    summary = await run_assessment(
        org_id="org-a",
        submission_id="sub-5",
        documents=[sbom_document],
        requested_lanes=["sbom", "cbom"],
    )
    rollup = lane_rollup(summary)
    assert rollup["cbom"]["verdict"] == LaneVerdict.LANE_ABSENT
    assert rollup["cbom"]["counts_toward_overall"] is True


async def test_a_lane_that_raises_does_not_fail_the_submission(monkeypatch, sbom_document):
    """Lanes fail independently (§11)."""
    from app.services.graph.nodes import sbomLane

    def explode(_documents):
        raise RuntimeError("catalogue unavailable")

    monkeypatch.setattr(sbomLane, "score_sbom", explode)
    summary = await run_assessment(
        org_id="org-a", submission_id="sub-6", documents=[sbom_document]
    )

    assert summary.status is JobStatus.SUCCEEDED, "one lane failing crashed the assessment"
    sbom = next(result for result in summary.lane_results if result.lane == "sbom")
    assert sbom.verdict is LaneVerdict.FAIL
    assert "catalogue unavailable" in sbom.detail
    assert any("catalogue unavailable" in error for error in summary.errors)


async def test_a_lane_that_hangs_times_out_while_the_others_complete(
    monkeypatch, sbom_document, aibom_document
):
    import app.services.graph.laneRunner as runner
    from app.services.graph.nodes import sbomLane

    monkeypatch.setattr(runner.settings, "LANE_TIMEOUT_SECONDS", 1)

    def hang(_documents):
        import time

        time.sleep(5)
        raise AssertionError("unreachable")

    monkeypatch.setattr(sbomLane, "score_sbom", hang)
    summary = await asyncio.wait_for(
        run_assessment(
            org_id="org-a", submission_id="sub-7", documents=[sbom_document, aibom_document]
        ),
        timeout=15,
    )

    rollup = lane_rollup(summary)
    assert rollup["sbom"]["verdict"] == LaneVerdict.LANE_TIMEOUT
    assert rollup["sbom"]["counts_toward_overall"] is False, (
        "a timeout is an infrastructure outcome, not a supplier defect"
    )
    assert rollup["aibom"]["score"] is not None, "the hung lane blocked a healthy one"
    assert any("timed out" in error for error in summary.errors)


async def test_empty_submission_is_refused():
    with pytest.raises(EmptySubmission):
        await run_assessment(org_id="org-a", submission_id="sub-8", documents=[])


async def test_single_lane_submission_produces_zero_correlation_findings(sbom_document):
    """Correlation with nothing to correlate against invents findings."""
    summary = await run_assessment(
        org_id="org-a", submission_id="sub-9", documents=[sbom_document]
    )
    assert summary.gate_reason is None
    assert summary.status is JobStatus.SUCCEEDED


async def test_lane_results_are_not_double_counted_by_the_reducer(sbom_document):
    """Five lanes, five results — never six because a lane appended twice."""
    documents = [
        sbom_document,
        SubmissionDocument(
            lane="sbom",
            format="CycloneDX",
            payload=cyclonedx_document([component("guava", "32.0.0")]),
        ),
    ]
    summary = await run_assessment(
        org_id="org-a", submission_id="sub-10", documents=documents
    )
    lanes = [result.lane for result in summary.lane_results]
    assert len(lanes) == len(set(lanes)) == 5
    sbom = next(result for result in summary.lane_results if result.lane == "sbom")
    assert sbom.entity_count == 2, "both documents in the lane should be scored together"


async def test_aibom_lane_scores_only_model_components():
    mixed = cyclonedx_document([model_component(), component("numpy", "1.26.0")])
    summary = await run_assessment(
        org_id="org-a",
        submission_id="sub-11",
        documents=[SubmissionDocument(lane="aibom", format="CycloneDX", payload=mixed)],
    )
    aibom = next(result for result in summary.lane_results if result.lane == "aibom")
    assert aibom.entity_count == 1
    assert "1 non-model entry" in aibom.detail, "the dropped entry must be reported"
