"""State merge functions. Nothing outside this module merges concurrent writes.

``operator.add`` is the baseline, but a bare add would let a retried lane append a
second result for the same lane and quietly double-count it in the overall score.
These reducers are add-with-a-rule.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:  # pragma: no cover - import cycle: state imports these reducers
    from app.services.graph.state import LaneResult, NodeRun


def merge_lane_results(left: list[LaneResult], right: list[LaneResult]) -> list[LaneResult]:
    """Append lane results, last write per lane winning.

    A lane may legitimately be recomputed — ``enrich`` re-scores after the feeds
    answer (S10). What must never happen is two results for one lane reaching the
    overall score, so the later result replaces the earlier one in place.
    """
    merged = list(left)
    index = {result.lane: position for position, result in enumerate(merged)}
    for result in right:
        position = index.get(result.lane)
        if position is None:
            index[result.lane] = len(merged)
            merged.append(result)
        else:
            merged[position] = result
    return merged


def merge_node_runs(left: list[NodeRun], right: list[NodeRun]) -> list[NodeRun]:
    """Append every node run, unconditionally.

    Retries, timeouts and failures are all kept: the run log is the audit trail
    and the evidence of parallelism, so deduplicating it would erase the proof.
    """
    return [*left, *right]


def merge_unique[T](left: list[T], right: list[T]) -> list[T]:
    """Append, dropping values already present, preserving first-seen order."""
    merged = list(left)
    for item in right:
        if item not in merged:
            merged.append(item)
    return merged
