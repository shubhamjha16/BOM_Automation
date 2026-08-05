"""S21: one `submission_id` reconstructs all five lane lifecycles.

Read the exit condition literally, because the literal reading is the hard one:
**one identifier, one query, five lifecycles — including the lanes that did
nothing.** A lane that was not enabled for the engagement, or that received no
document, does no work and has nothing interesting to say, so it is exactly the
lane that never makes it into the logs. Then a client asks why their CBOM was not
assessed and nobody can answer from the record.

Every test here reads the **rendered** log stream — JSON lines through the real
processor chain, redaction included — rather than intercepting event dicts before
the processors run. The pipeline being tested is the deployed one, and the two
questions are inseparable: does it emit enough to rebuild a submission, and little
enough to be safe to keep? Logs outlive engagements.
"""

from __future__ import annotations

import io
import json
import logging
import uuid

import pytest

from app.configs.envConfig import ALL_LANES
from app.services.assessmentService import run_assessment
from app.services.graph.state import SubmissionDocument
from app.services.observability.trace import (
    LANE_COMPLETE,
    LANE_STARTED,
    assessment_context,
    latency_percentiles,
    parse_lines,
    reconstruct,
)
from app.utils.logger import configure_logging, get_logger
from tests.conftest import component, cyclonedx_document, model_component


@pytest.fixture
def captured():
    """Point the real logging pipeline at a buffer and hand back its lines."""
    stream = io.StringIO()
    configure_logging(json_output=True, level=logging.INFO, stream=stream, force=True)
    yield stream
    configure_logging(force=True)


def _cbom_document() -> dict:
    return cyclonedx_document(
        [
            {
                "name": "RSA-2048",
                "type": "cryptographic-asset",
                "cryptoProperties": {
                    "assetType": "algorithm",
                    "algorithmProperties": {"primitive": "signature"},
                },
            }
        ]
    )


async def _assess(submission_id: str, *, lanes: list[str] | None = None):
    model = model_component()
    return await run_assessment(
        org_id="org-1",
        submission_id=submission_id,
        documents=[
            SubmissionDocument(
                lane="sbom",
                format="CycloneDX",
                payload=cyclonedx_document([component("express", "4.18.0")]),
            ),
            SubmissionDocument(
                lane="aibom", format="CycloneDX", payload=cyclonedx_document([model])
            ),
            SubmissionDocument(lane="cbom", format="CycloneDX", payload=_cbom_document()),
        ],
        requested_lanes=lanes if lanes is not None else list(ALL_LANES),
    )


# --- the exit proof ----------------------------------------------------------


async def test_a_submission_id_alone_reconstructs_all_five_lane_lifecycles(captured):
    """The §S21 exit proof. No database, no job row, no in-memory state — at the
    point somebody needs this, the process that ran the assessment is gone."""
    submission_id = str(uuid.uuid4())
    await _assess(submission_id)

    trace = reconstruct(captured.getvalue().splitlines(), submission_id)

    assert trace.missing == []
    assert trace.incomplete == []
    assert trace.is_whole
    assert set(trace.lanes) == set(ALL_LANES)


async def test_each_lifecycle_carries_its_verdict_and_latency(captured):
    submission_id = str(uuid.uuid4())
    await _assess(submission_id)

    trace = reconstruct(captured.getvalue().splitlines(), submission_id)
    for lane in ALL_LANES:
        cycle = trace.lanes[lane]
        assert cycle.started, f"{lane} never logged a start"
        assert cycle.terminal_event == LANE_COMPLETE
        assert cycle.verdict, f"{lane} ended without a verdict in the logs"
        assert cycle.latency_ms is not None


async def test_a_lane_that_did_no_work_still_has_a_lifecycle(captured):
    """QBOM and HBOM received nothing here. They are the lanes a client asks
    about, and the lanes that would otherwise be absent from the trace."""
    submission_id = str(uuid.uuid4())
    await _assess(submission_id)

    trace = reconstruct(captured.getvalue().splitlines(), submission_id)
    for lane in ("qbom", "hbom"):
        assert trace.lanes[lane].complete
        assert trace.lanes[lane].verdict == "lane_absent"


async def test_a_disabled_lane_is_reconstructable_and_distinguishable(captured):
    """`lane_not_applicable` is not `lane_absent` (§11), and the distinction has
    to survive into the logs — it is the difference between "you had nothing to
    declare" and "you failed to declare it"."""
    submission_id = str(uuid.uuid4())
    await _assess(submission_id, lanes=["sbom", "aibom"])

    trace = reconstruct(captured.getvalue().splitlines(), submission_id)
    assert trace.lanes["qbom"].verdict == "lane_not_applicable"
    assert trace.lanes["sbom"].verdict != "lane_not_applicable"
    assert trace.missing == []


async def test_the_trace_of_one_submission_excludes_another(captured):
    """Concurrency is the normal case: twenty assessments share a log stream."""
    first, second = str(uuid.uuid4()), str(uuid.uuid4())
    await _assess(first)
    await _assess(second, lanes=["sbom"])

    lines = captured.getvalue().splitlines()
    one = reconstruct(lines, first)
    two = reconstruct(lines, second)

    assert one.lanes["aibom"].verdict != two.lanes["aibom"].verdict
    assert one.line_count and two.line_count
    assert one.line_count + two.line_count <= len(parse_lines(lines))


async def test_the_correlation_keys_reach_lines_emitted_inside_the_lane_threads(captured):
    """The lanes run through `asyncio.to_thread`, which copies the context. If it
    did not, every lane line would be missing its `submission_id` and the
    reconstruction above would find nothing — so this is the mechanism the exit
    proof rests on, asserted directly."""
    submission_id = str(uuid.uuid4())
    await _assess(submission_id)

    records = [
        record
        for record in parse_lines(captured.getvalue().splitlines())
        if record.get("event") in (LANE_STARTED, LANE_COMPLETE)
    ]
    assert records
    assert all(record.get("submission_id") == submission_id for record in records)
    assert all(record.get("job_id") for record in records)


# --- the shapes a reconstruction has to distinguish --------------------------


def test_a_started_lane_that_never_ended_reads_as_incomplete_not_missing():
    """The shape a hung lane leaves behind. "Never reached" and "never returned"
    are different incidents and must not collapse into one."""
    lines = [
        json.dumps({"event": LANE_STARTED, "submission_id": "s1", "lane": "sbom"}),
        json.dumps({"event": LANE_STARTED, "submission_id": "s1", "lane": "cbom"}),
        json.dumps(
            {
                "event": LANE_COMPLETE,
                "submission_id": "s1",
                "lane": "sbom",
                "verdict": "pass",
                "latency_ms": 12.0,
            }
        ),
    ]
    trace = reconstruct(lines, "s1")

    assert trace.incomplete == ["cbom"]
    assert "qbom" in trace.missing
    assert not trace.is_whole


def test_a_lane_that_raised_keeps_the_error_and_still_completes():
    """§11: a lane fails independently and never crashes the assessment, so a
    `lane_failed` line is followed by a completion with a FAIL verdict."""
    lines = [
        json.dumps({"event": LANE_STARTED, "submission_id": "s1", "lane": "sbom"}),
        json.dumps(
            {"event": "lane_failed", "submission_id": "s1", "lane": "sbom",
             "exception": "ValueError: bad payload"}
        ),
        json.dumps(
            {"event": LANE_COMPLETE, "submission_id": "s1", "lane": "sbom",
             "verdict": "fail", "latency_ms": 4.0}
        ),
    ]
    trace = reconstruct(lines, "s1")

    assert trace.lanes["sbom"].complete
    assert trace.lanes["sbom"].verdict == "fail"
    assert "ValueError" in trace.lanes["sbom"].errors[0]


def test_lines_from_libraries_that_never_heard_of_structlog_are_skipped():
    """A reconstruction tool that dies on the first uvicorn line is useless at
    exactly the moment it is needed."""
    lines = [
        "INFO:     127.0.0.1:0 - GET /health 200",
        "{not json at all",
        json.dumps({"event": LANE_STARTED, "submission_id": "s1", "lane": "sbom"}),
        json.dumps(["a", "list", "not", "a", "record"]),
    ]
    assert len(parse_lines(lines)) == 1
    assert reconstruct(lines, "s1").lanes["sbom"].started


def test_an_unknown_submission_id_reconstructs_nothing_rather_than_everything():
    lines = [json.dumps({"event": LANE_STARTED, "submission_id": "s1", "lane": "sbom"})]
    trace = reconstruct(lines, "s2")

    assert trace.lanes == {}
    assert trace.line_count == 0
    assert sorted(trace.missing) == sorted(ALL_LANES)


# --- redaction still applies -------------------------------------------------


async def test_no_bom_content_reaches_the_log_stream(captured):
    """Logs outlive engagements and a BOM is an architecture disclosure. The
    reconstruction above must be possible from lines that are safe to retain."""
    submission_id = str(uuid.uuid4())
    await run_assessment(
        org_id="org-1",
        submission_id=submission_id,
        documents=[
            SubmissionDocument(
                lane="sbom",
                format="CycloneDX",
                payload=cyclonedx_document(
                    [component("internal-billing-svc", "1.0.0")]
                ),
            )
        ],
        requested_lanes=["sbom"],
    )

    raw = captured.getvalue()
    assert submission_id in raw
    assert "internal-billing-svc" not in raw


async def test_the_context_is_released_after_the_assessment(captured):
    """A leaked binding attributes the next request's lines to the last
    submission, which is worse than no correlation at all."""
    submission_id = str(uuid.uuid4())
    await _assess(submission_id, lanes=["sbom"])

    get_logger(__name__).info("unrelated_event")
    tail = json.loads(
        [line for line in captured.getvalue().splitlines() if "unrelated_event" in line][-1]
    )
    assert "submission_id" not in tail


def test_the_context_manager_restores_a_previous_binding():
    with assessment_context(submission_id="outer"):
        with assessment_context(submission_id="inner"):
            pass
        import structlog

        assert structlog.contextvars.get_contextvars()["submission_id"] == "outer"


# --- per-lane percentiles ----------------------------------------------------


async def test_percentiles_are_reported_per_lane_not_as_one_aggregate(captured):
    """The number that answers "does the fan-out hold or is it serialising?" is
    the slowest lane's p95 against the assessment's own. An aggregate hides it."""
    ids = [str(uuid.uuid4()) for _ in range(3)]
    for submission_id in ids:
        await _assess(submission_id)

    lines = captured.getvalue().splitlines()
    summary = latency_percentiles(reconstruct(lines, sid) for sid in ids)

    assert set(summary) == set(ALL_LANES)
    for lane, stats in summary.items():
        assert stats["n"] == 3.0, f"{lane} produced {stats['n']} samples"
        assert stats["p50"] <= stats["p95"] <= stats["max"]


def test_percentiles_of_nothing_are_not_an_error():
    assert latency_percentiles([]) == {}
