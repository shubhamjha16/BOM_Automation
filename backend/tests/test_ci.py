"""S18: the CI conformance gate, signed webhooks and per-lane progress.

**What this file does not establish.** Posting a check run to a real pull request
needs GitHub App credentials this environment does not have, so the round-trip
against GitHub is unproven. What is tested is the payload a developer would see
and the signature a consumer would verify — both fully offline, and both the
parts that carry the rules.
"""

from __future__ import annotations

import json

import pytest

from app.services.ci.checkRun import build
from app.services.ci.policy import GateMode, GatePolicy
from app.services.progressStream import ProgressEvent, event_for_node_run, summary_event
from app.services.webhookService import (
    MAX_SKEW_SECONDS,
    SIGNATURE_HEADER,
    SignatureInvalid,
    reference_implementation,
    sign,
    verify,
)


class _Lane:
    def __init__(self, lane, score, verdict, rows):
        self.lane, self.score, self.verdict, self.field_results = lane, score, verdict, rows


def _rows():
    return [
        {
            "element_key": "license",
            "label": "Licence",
            "clause": "4.2(5)",
            "verdict": "absent",
            "tier": "critical",
            "populated": 0,
            "total": 40,
        },
        {
            "element_key": "origin",
            "label": "Origin",
            "clause": "4.2(6)",
            "verdict": "absent",
            "tier": "standard",
            "populated": 2,
            "total": 40,
        },
    ]


def _lanes():
    return [_Lane("sbom", 62.0, "fail", _rows())]


# --- the gate defaults to warn ------------------------------------------------


def test_the_default_mode_is_warn():
    """A gate that blocks on day one is disabled on day two, and a disabled gate
    reports nothing at all."""
    assert GatePolicy().mode is GateMode.WARN


def test_warn_mode_reports_the_finding_without_failing_the_build():
    """The §S18 exit proof."""
    check = build(overall_score=62.0, lane_results=_lanes(), policy=GatePolicy())

    assert check.conclusion == "success"
    assert "not blocking" in check.summary
    assert "below the 85.0% threshold" in check.summary
    # The finding is still visible on the pull request.
    assert "4.2(5)" in check.text


def test_block_mode_fails_the_check():
    check = build(
        overall_score=62.0, lane_results=_lanes(), policy=GatePolicy(mode=GateMode.BLOCK)
    )
    assert check.conclusion == "failure"
    assert "conformance check failed" in check.summary


def test_an_unlicensed_dependency_names_the_clause_and_the_component():
    """The §S18 exit proof: visible without leaving GitHub."""
    check = build(
        overall_score=62.0,
        lane_results=_lanes(),
        policy=GatePolicy(mode=GateMode.BLOCK),
        offending_components={"license": ["express@4.18.0", "left-pad@1.3.0"]},
    )

    assert "4.2(5)" in check.text
    assert "express@4.18.0" in check.text
    assert "4.2(5)" in check.summary


def test_a_critical_gap_fails_at_any_score_when_blocking():
    """The same rule as the lane verdict."""
    passed, summary = GatePolicy(mode=GateMode.BLOCK).decide(
        score=99.0, critical_gaps=["4.2(2) Version"], failing_clauses=[]
    )
    assert passed is False
    assert "critical gap" in summary


def test_off_mode_is_recorded_as_a_choice():
    """A silent pipeline should be a decision, not an accident."""
    passed, summary = GatePolicy(mode=GateMode.OFF).decide(
        score=10.0, critical_gaps=["x"], failing_clauses=[]
    )
    assert passed is True
    assert "gate is off" in summary


def test_a_clean_submission_passes_in_every_mode():
    for mode in (GateMode.WARN, GateMode.BLOCK):
        passed, summary = GatePolicy(mode=mode).decide(
            score=95.0, critical_gaps=[], failing_clauses=[]
        )
        assert passed is True
        assert "passed" in summary


def test_the_check_payload_matches_the_github_shape():
    payload = build(overall_score=62.0, lane_results=_lanes(), policy=GatePolicy()).as_payload()

    assert payload["name"] == "CERT-In conformance"
    assert payload["status"] == "completed"
    assert set(payload["output"]) == {"title", "summary", "text"}


def test_named_blocking_clauses_fail_even_above_the_threshold():
    """An organisation names its own non-negotiables."""
    passed, summary = GatePolicy(
        mode=GateMode.BLOCK, minimum_score=50.0, blocking_clauses=frozenset({"4.2(5)"})
    ).decide(score=90.0, critical_gaps=[], failing_clauses=["4.2(5)"])

    assert passed is False
    assert "4.2(5)" in summary


# --- signed webhooks ----------------------------------------------------------


def _body() -> bytes:
    return json.dumps(
        {"event": "assessment.completed", "submission_id": "sub-1", "score": 43.9},
        sort_keys=True,
        separators=(",", ":"),
    ).encode()


def test_an_authentic_delivery_verifies():
    body = _body()
    signature, timestamp = sign(body, "shared-secret")
    verify(body, signature, timestamp, "shared-secret")


def test_a_one_character_tamper_is_rejected():
    """The §S18 exit proof."""
    body = _body()
    signature, timestamp = sign(body, "shared-secret")

    with pytest.raises(SignatureInvalid, match="does not match"):
        verify(body.replace(b"43.9", b"93.9"), signature, timestamp, "shared-secret")


def test_a_replayed_delivery_is_rejected():
    """A signature over the body alone is replayable forever; the timestamp is
    inside what is signed precisely to close that."""
    body = _body()
    signature, timestamp = sign(body, "shared-secret", timestamp=1_000_000)

    with pytest.raises(SignatureInvalid, match="beyond the"):
        verify(body, signature, str(1_000_000), "shared-secret", now=1_000_000 + 600)


def test_a_delivery_within_the_window_still_verifies():
    body = _body()
    signature, timestamp = sign(body, "shared-secret", timestamp=1_000_000)
    verify(body, signature, timestamp, "shared-secret", now=1_000_000 + MAX_SKEW_SECONDS - 1)


def test_the_wrong_secret_is_rejected():
    body = _body()
    signature, timestamp = sign(body, "shared-secret")
    with pytest.raises(SignatureInvalid):
        verify(body, signature, timestamp, "a-different-secret")


def test_a_malformed_timestamp_is_rejected_rather_than_crashing():
    body = _body()
    signature, _ = sign(body, "shared-secret")
    with pytest.raises(SignatureInvalid, match="not an integer"):
        verify(body, signature, "not-a-number", "shared-secret")


def test_the_signature_is_versioned():
    signature, _ = sign(_body(), "s")
    assert signature.startswith("v1=")


def test_the_reference_implementation_verifies_our_own_signatures():
    """Published rather than described: a consumer inferring the scheme from
    prose will get the timestamp handling wrong, and a verifier that wrongly
    accepts everything is worse than none."""
    namespace: dict = {}
    exec(reference_implementation(), namespace)  # noqa: S102 - the published snippet

    body = _body()
    signature, timestamp = sign(body, "shared-secret")

    assert namespace["verify"](body, signature, timestamp, "shared-secret") is True
    assert (
        namespace["verify"](body.replace(b"43.9", b"1.0"), signature, timestamp, "shared-secret")
        is False
    )


def test_the_signature_header_is_named():
    assert SIGNATURE_HEADER == "X-BOM-Signature"


# --- per-lane progress ---------------------------------------------------------


class _Run:
    def __init__(self, lane, node, status, latency=1.0):
        self.lane, self.node, self.status = lane, node, status
        self.latency_ms, self.error = latency, None


def test_each_lane_produces_its_own_event():
    """Five lanes should read as five tracks, not one spinner."""
    events = [
        event_for_node_run(_Run("sbom", "sbomLane", "succeeded")),
        event_for_node_run(_Run("cbom", "cbomLane", "timeout")),
    ]
    assert [event.lane for event in events] == ["sbom", "cbom"]
    assert "sbom: scored" in events[0].message
    assert "cbom: timed out" in events[1].message


def test_a_hung_lane_is_visible_while_others_are_still_running():
    event = event_for_node_run(_Run("cbom", "cbomLane", "timeout", latency=120000.0))
    assert event.event == "lane"
    assert "timed out" in event.message


def test_a_non_lane_node_is_reported_separately():
    event = event_for_node_run(_Run(None, "correlate", "succeeded"))
    assert event.event == "node"
    assert event.lane is None


def test_an_sse_frame_is_terminated_by_a_blank_line():
    """Omitting it leaves the client waiting for a frame that never arrives."""
    frame = ProgressEvent("lane", "sbom", "sbom: scored", {}).to_sse()
    assert frame.startswith("event: lane\ndata: ")
    assert frame.endswith("\n\n")


def test_the_completion_event_carries_every_lane():
    class _Summary:
        status = "succeeded"
        overall_score = 43.9
        lane_results = [_Lane("sbom", 43.9, "fail", []), _Lane("cbom", None, "lane_absent", [])]

    data = json.loads(summary_event(_Summary()).to_sse().split("data: ")[1])
    assert set(data["lanes"]) == {"sbom", "cbom"}
    assert data["overall_score"] == 43.9
