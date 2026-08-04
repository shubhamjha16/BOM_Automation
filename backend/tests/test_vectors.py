"""Every vector must match the engine **to the field**, not just on the total.

The total is the weakest possible check: two compensating errors give the right
percentage from the wrong verdicts, and a reader who sees only "87%" cannot tell.
So each vector asserts a verdict per element, and one disagreement fails.

`vectors/README.md` states the provenance honestly — these encode the rules in
§11 and have not yet been signed off by a practising assessor.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from app.services.catalogue.loader import get_catalogue
from app.services.ingest.normalize import ingest_document
from app.services.score.documentChecks import check_all, document_metadata
from app.services.score.verdict import lane_verdict
from app.services.score.weighting import lane_score

VECTORS = sorted((Path(__file__).resolve().parent / "vectors").glob("*.json"))


def _load(path: Path) -> dict:
    return json.loads(path.read_text())


def _score(vector: dict):
    """Run a vector through the real ingestion and scoring path."""
    lane = vector["lane"]
    parsed = ingest_document(vector["document"], lane=lane)
    documents = [
        document_metadata(
            author=parsed.doc_author,
            timestamp=parsed.doc_timestamp,
            spec_version=parsed.spec_version,
        )
    ]
    results = check_all(get_catalogue(lane), parsed.entities, documents)
    score = lane_score(results)
    verdict, detail = lane_verdict(score, results)
    return {result.element_key: result for result in results}, score, verdict, detail


def test_the_vector_set_is_present():
    """An empty directory would make every parametrised test vacuously pass."""
    assert len(VECTORS) >= 7, f"expected the hand-scored vectors, found {len(VECTORS)}"


@pytest.mark.parametrize("path", VECTORS, ids=lambda p: p.stem)
def test_every_vector_states_why(path):
    """A vector without a rationale is an assertion nobody can review."""
    vector = _load(path)
    assert vector.get("rationale"), f"{path.name} has no rationale"
    assert vector.get("expected", {}).get("fields"), f"{path.name} asserts no fields"


@pytest.mark.parametrize("path", VECTORS, ids=lambda p: p.stem)
def test_every_field_matches_the_hand_scored_expectation(path):
    vector = _load(path)
    results, score, verdict, detail = _score(vector)
    expected = vector["expected"]

    for key, want in expected["fields"].items():
        assert key in results, f"{path.name}: the catalogue has no element {key!r}"
        got = str(results[key].verdict)
        assert got == want, (
            f"{path.name}: {key} ({results[key].clause}) — expected {want}, got {got}. "
            f"Engine said: {results[key].detail}"
        )


@pytest.mark.parametrize("path", VECTORS, ids=lambda p: p.stem)
def test_coverage_counts_match_where_the_vector_states_them(path):
    vector = _load(path)
    results, *_ = _score(vector)

    for key, (populated, total) in vector["expected"].get("coverage", {}).items():
        coverage = results[key].coverage
        assert (coverage.populated, coverage.total) == (populated, total), (
            f"{path.name}: {key} coverage — expected {populated}/{total}, "
            f"got {coverage.populated}/{coverage.total}"
        )


@pytest.mark.parametrize("path", VECTORS, ids=lambda p: p.stem)
def test_lane_verdicts_match_where_stated(path):
    vector = _load(path)
    _, score, verdict, detail = _score(vector)

    if (want := vector["expected"].get("verdict")) is not None:
        assert str(verdict) == want, f"{path.name}: expected {want}, got {verdict} ({detail})"


# --- the headline case, asserted directly as well ---------------------------


def test_the_twelve_of_four_hundred_case_scores_three_percent():
    """§11, verbatim: licences on 12 of 400 components has not met 4.2(5)."""
    vector = _load(next(p for p in VECTORS if "12-of-400" in p.stem))
    results, *_ = _score(vector)

    licence = results["license"]
    assert licence.coverage.percent == 3.0
    assert str(licence.verdict) == "absent"
    assert "does not meet 4.2(5)" in licence.detail


def test_consumer_determinations_never_reach_the_supplier_score():
    for path in VECTORS:
        results, *_ = _score(_load(path))
        for result in results.values():
            if str(result.verdict) == "not_determinable":
                assert not result.counts_toward_supplier_score
                assert result.consumer_action, (
                    f"{result.element_key} is not determinable but names no consumer "
                    "action; the reader will assume it passed"
                )
