"""The shared lane wrapper: timing, timeout, isolation and the node-run record.

Every lane node is this function plus a scoring body. Three things it guarantees:

* **The scoring body runs off the event loop.** Field scoring is deterministic CPU
  work over what may be 50,000 components; running it inline would block the loop
  and stall every other lane's timeout clock along with it.

  **What ``to_thread`` does and does not buy, measured.** Scoring is pure Python,
  so it holds the GIL: two CPU-bound lanes interleave rather than run truly in
  parallel. Measured on 4,000 components + 3,000 models — 173 ms and 124 ms alone,
  263 ms run back to back, 281 ms through the fan-out. The lane intervals overlap
  genuinely, and the isolation properties below all hold, but there is no CPU
  speedup and the small overhead is thread scheduling.

  That is the right trade today and is worth stating rather than discovering
  under load at S21. The isolation is what the fan-out is actually for: a hung or
  crashed lane cannot take the others with it. Throughput arrives when the lanes
  stop being pure CPU — S10's enrichment is network-bound and releases the GIL,
  where this concurrency pays directly. If CPU-bound scoring of very large BOMs
  later needs real parallelism, the change is this call site alone: a
  ``ProcessPoolExecutor`` behind ``run_in_executor``, which the lane bodies are
  already shaped for because they are pure, synchronous and take only their
  documents.
* **A lane cannot fail the submission.** Any exception becomes a lane verdict and
  an error string. Lanes fail independently (§11).
* **A lane cannot hang the submission.** ``LANE_TIMEOUT_SECONDS`` bounds it and
  records ``lane_timeout``, which is reported, not silently dropped.
"""

from __future__ import annotations

import asyncio
from collections.abc import Callable
from datetime import UTC, datetime

from app.configs.envConfig import Lane, settings
from app.configs.jobTypes import LaneVerdict
from app.configs.laneConfig import LANE_SPECS, is_implemented
from app.configs.scoringConfig import ENGINE_VERSION
from app.services.graph.state import GraphState, LaneResult, NodeRun, SubmissionDocument
from app.utils.logger import get_logger

logger = get_logger(__name__)

#: A lane body takes the documents submitted for that lane and returns its result.
#: It is synchronous and pure by design — no I/O, no LLM, no clock (§11).
LaneBody = Callable[[list[SubmissionDocument]], LaneResult]


def documents_for(state: GraphState, lane: Lane) -> list[SubmissionDocument]:
    return [document for document in state.get("documents", []) if document.lane == lane]


async def run_lane(state: GraphState, lane: Lane, body: LaneBody) -> GraphState:
    """Run one lane and return the partial state the reducers will merge."""
    started_at = datetime.now(UTC)
    documents = documents_for(state, lane)
    errors: list[str] = []
    status = "succeeded"

    if lane not in state.get("lanes_to_run", []):
        result = LaneResult(
            lane=lane,
            verdict=LaneVerdict.LANE_NOT_APPLICABLE,
            detail="not enabled for this engagement; excluded from the overall score",
            engine_version=ENGINE_VERSION,
        )
    elif not is_implemented(lane):
        spec = LANE_SPECS[lane]
        result = LaneResult(
            lane=lane,
            verdict=LaneVerdict.LANE_ABSENT,
            detail=f"{spec.label} scoring is not yet implemented; nothing was scored",
            engine_version=ENGINE_VERSION,
        )
        if documents:
            # Never let a submitted document disappear into an unimplemented lane.
            errors.append(
                f"{lane}: {len(documents)} document(s) received but the lane is not "
                f"implemented — stored, not scored"
            )
    elif not documents:
        result = LaneResult(
            lane=lane,
            verdict=LaneVerdict.LANE_ABSENT,
            detail=f"no {lane.upper()} document in this submission",
            engine_version=ENGINE_VERSION,
        )
    else:
        try:
            # to_thread is what lets the five lanes genuinely overlap.
            result = await asyncio.wait_for(
                asyncio.to_thread(body, documents),
                timeout=settings.LANE_TIMEOUT_SECONDS,
            )
        except TimeoutError:
            status = "timeout"
            result = LaneResult(
                lane=lane,
                verdict=LaneVerdict.LANE_TIMEOUT,
                detail=f"exceeded LANE_TIMEOUT_SECONDS={settings.LANE_TIMEOUT_SECONDS}",
                engine_version=ENGINE_VERSION,
            )
            errors.append(f"{lane}: timed out after {settings.LANE_TIMEOUT_SECONDS}s")
        except Exception as error:  # noqa: BLE001 - a lane never fails the submission
            status = "failed"
            logger.exception("lane_failed", lane=lane, job_id=state.get("job_id"))
            result = LaneResult(
                lane=lane,
                verdict=LaneVerdict.FAIL,
                detail=f"lane raised {type(error).__name__}: {error}",
                engine_version=ENGINE_VERSION,
            )
            errors.append(f"{lane}: {type(error).__name__}: {error}")

    finished_at = datetime.now(UTC)
    node_run = NodeRun(
        node=f"{lane}Lane",
        lane=lane,
        status=status,  # type: ignore[arg-type]
        started_at=started_at,
        finished_at=finished_at,
        error=errors[0] if errors else None,
    )
    logger.info(
        "lane_complete",
        lane=lane,
        verdict=result.verdict,
        entity_count=result.entity_count,
        latency_ms=round(node_run.latency_ms, 2),
        job_id=state.get("job_id"),
    )
    return GraphState(lane_results=[result], node_runs=[node_run], errors=errors)
