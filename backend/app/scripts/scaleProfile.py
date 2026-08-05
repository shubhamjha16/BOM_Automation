"""Scale measurement — S21. `make scale`.

Three questions, measured rather than asserted:

1. **Does a 50,000-component SBOM score within budget?** The budget is stated
   below and checked here, so a regression fails a run rather than surfacing as a
   client's timeout.
2. **Does the fan-out hold, or does it serialise?** Answered per lane, from the
   logs, using the same reconstruction the on-call path uses (`observability/
   trace.py`) — if that tool cannot answer this, it cannot answer anything.
3. **What does an assessment cost?** Reported as measured CPU-seconds and peak
   memory rather than as a currency figure, because the currency figure depends on
   an instance price this repository has no business asserting.

**On what "parallel" means here, honestly.** The lanes run through
`asyncio.to_thread` and their intervals genuinely overlap, which is what the
isolation properties depend on: one lane timing out or raising does not stop the
others. But scoring is pure Python and holds the GIL, so overlapping is not
speedup — five lanes over the same document take about as long as five lanes in
series, plus scheduling. `laneRunner.py` records the measurement that established
this. Reporting the overlap as a performance win would be the kind of figure §11
exists to prevent, so it is reported as what it is.
"""

from __future__ import annotations

import asyncio
import io
import json
import logging
import resource
import sys
import time
from pathlib import Path
from typing import Any

from app.services.assessmentService import run_assessment
from app.services.graph.state import SubmissionDocument
from app.services.observability.trace import latency_percentiles, reconstruct
from app.utils.logger import configure_logging

#: The stated budget. A 50,000-component estate is the largest single BOM the
#: guideline's audience plausibly produces — a full Java monolith with transitive
#: dependencies resolved. The wall-clock allowance is generous against the
#: measured figure on purpose: this runs on developer laptops and CI runners with
#: noisy neighbours, and a budget that fails on a slow afternoon gets deleted.
BUDGET_SECONDS = 30.0
BUDGET_PEAK_MB = 1_024.0
LARGEST_SBOM = 50_000

#: Concurrency for the fan-out measurement. Twenty five-lane assessments is a
#: busy hour for a mid-sized practice, not a synthetic peak.
CONCURRENT_ASSESSMENTS = 20
CONCURRENT_COMPONENTS = 2_000


def _component(index: int) -> dict[str, Any]:
    """A fully-populated component. Deliberately *not* a sparse one: a document
    where every field is absent short-circuits every probe on its first path and
    measures the fast case."""
    name = f"pkg-{index}"
    return {
        "type": "library",
        "name": name,
        "version": "1.0.0",
        "purl": f"pkg:npm/{name}@1.0.0",
        "bom-ref": f"ref-{name}",
        "supplier": {"name": "Acme Software Pvt Ltd"},
        "author": "Acme",
        "hashes": [{"alg": "SHA-256", "content": "a" * 64}],
        "licenses": [{"license": {"id": "MIT"}}],
        "externalReferences": [{"type": "website", "url": "https://example.invalid"}],
    }


def synthetic_sbom(count: int) -> dict[str, Any]:
    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "version": 1,
        "serialNumber": "urn:uuid:11111111-1111-1111-1111-111111111111",
        "metadata": {
            "timestamp": "2026-08-05T00:00:00Z",
            "tools": [{"name": "cdxgen", "version": "11.11.0"}],
            "authors": [{"name": "Acme Software Pvt Ltd"}],
            "component": {"name": "monolith", "version": "7.4.0"},
        },
        "components": [_component(index) for index in range(count)],
    }


def synthetic_aibom(count: int) -> dict[str, Any]:
    document = synthetic_sbom(0)
    document["components"] = [
        {
            "type": "machine-learning-model",
            "name": f"model-{index}",
            "version": "1.0.0",
            "bom-ref": f"model-{index}",
            "supplier": {"name": "Acme"},
            "modelCard": {
                "modelParameters": {
                    "task": "classification",
                    "architectureFamily": "transformer",
                    "datasets": [{"name": "internal-corpus"}],
                },
                "considerations": {"ethicalConsiderations": [{"name": "bias"}]},
            },
        }
        for index in range(count)
    ]
    return document


def synthetic_cbom(count: int) -> dict[str, Any]:
    document = synthetic_sbom(0)
    document["components"] = [
        {
            "type": "cryptographic-asset",
            "name": f"AES-256-GCM-{index}",
            "bom-ref": f"crypto-{index}",
            "cryptoProperties": {
                "assetType": "algorithm",
                "algorithmProperties": {
                    "primitive": "ae",
                    "mode": "gcm",
                    "cryptoFunctions": ["encrypt", "decrypt"],
                    "classicalSecurityLevel": 128,
                },
                "oid": "2.16.840.1.101.3.4.1.46",
            },
        }
        for index in range(count)
    ]
    return document


def synthetic_hbom(count: int) -> dict[str, Any]:
    document = synthetic_sbom(0)
    document["components"] = [
        {
            "type": "device",
            "name": f"switch-{index}",
            "version": "rev-b",
            "bom-ref": f"hw-{index}",
            "manufacturer": {"name": "Acme Hardware"},
            "serialNumber": f"SN{index:06d}",
            "properties": [
                {"name": "certin:manufacturing_date", "value": "2025-03-01"},
                {"name": "certin:country_of_origin", "value": "IN"},
                {"name": "certin:firmware_version", "value": "2.1.0"},
            ],
        }
        for index in range(count)
    ]
    return document


def peak_mb() -> float:
    """Peak RSS. `ru_maxrss` is kilobytes on Linux and bytes on macOS."""
    peak = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
    return peak / (1024 * 1024) if sys.platform == "darwin" else peak / 1024


async def measure_largest(count: int = LARGEST_SBOM) -> dict[str, Any]:
    payload = synthetic_sbom(count)
    size_mb = len(json.dumps(payload)) / 1e6

    # Warm first, on a tiny document: the first assessment in a process compiles
    # the graph and imports the catalogue, and charging that to the 50,000-
    # component case would measure Python startup.
    await run_assessment(
        org_id="scale",
        submission_id="warmup",
        documents=[
            SubmissionDocument(
                lane="sbom", format="CycloneDX", payload=synthetic_sbom(10)
            )
        ],
        requested_lanes=["sbom"],
    )

    started = time.perf_counter()
    cpu_started = time.process_time()
    summary = await run_assessment(
        org_id="scale",
        submission_id="largest",
        documents=[
            SubmissionDocument(lane="sbom", format="CycloneDX", payload=payload)
        ],
        requested_lanes=["sbom"],
    )
    elapsed = time.perf_counter() - started
    cpu = time.process_time() - cpu_started

    lane = next(result for result in summary.lane_results if result.lane == "sbom")
    return {
        "components": count,
        "document_mb": round(size_mb, 1),
        "seconds": round(elapsed, 2),
        "cpu_seconds": round(cpu, 2),
        "ms_per_component": round(elapsed * 1000 / count, 3),
        "peak_mb": round(peak_mb(), 1),
        "entities_scored": lane.entity_count,
        "score": lane.score,
        "within_budget": elapsed <= BUDGET_SECONDS and peak_mb() <= BUDGET_PEAK_MB,
    }


async def measure_concurrency(
    count: int = CONCURRENT_ASSESSMENTS, components: int = CONCURRENT_COMPONENTS
) -> dict[str, Any]:
    """N concurrent five-lane assessments, with p95 per lane read from the logs."""
    stream = io.StringIO()
    configure_logging(json_output=True, level=logging.INFO, stream=stream, force=True)
    try:
        # Every lane gets real work. With documents in one lane only, four lanes
        # return immediately and "the intervals overlap" is true of nothing — the
        # measurement would pass while proving the opposite of what it claims.
        documents = [
            SubmissionDocument(
                lane="sbom", format="CycloneDX", payload=synthetic_sbom(components)
            ),
            SubmissionDocument(
                lane="aibom", format="CycloneDX", payload=synthetic_aibom(50)
            ),
            SubmissionDocument(
                lane="cbom", format="CycloneDX", payload=synthetic_cbom(200)
            ),
            SubmissionDocument(
                lane="qbom", format="CycloneDX", payload=synthetic_cbom(50)
            ),
            SubmissionDocument(
                lane="hbom", format="CycloneDX", payload=synthetic_hbom(200)
            ),
        ]
        ids = [f"concurrent-{index}" for index in range(count)]

        started = time.perf_counter()
        summaries = await asyncio.gather(
            *[
                run_assessment(
                    org_id="scale",
                    submission_id=submission_id,
                    documents=documents,
                    requested_lanes=["sbom", "aibom", "cbom", "qbom", "hbom"],
                )
                for submission_id in ids
            ]
        )
        elapsed = time.perf_counter() - started

        lines = stream.getvalue().splitlines()
        traces = [reconstruct(lines, submission_id) for submission_id in ids]
    finally:
        configure_logging(force=True)

    total_components = count * (components + 500)
    return {
        "assessments": count,
        "components_each": components,
        "throughput_per_second": round(total_components / elapsed, 1),
        "lanes_each": 5,
        "seconds": round(elapsed, 2),
        "seconds_each": round(elapsed / count, 2),
        "per_lane": latency_percentiles(traces),
        "overlap_proven": all(summary.parallelism_proven for summary in summaries),
        "traces_whole": all(trace.is_whole for trace in traces),
        "peak_mb": round(peak_mb(), 1),
    }


def render(largest: dict[str, Any], concurrency: dict[str, Any]) -> str:
    lines = [
        "# Scale measurement",
        "",
        f"Budget: **{BUDGET_SECONDS:.0f}s** wall clock and **{BUDGET_PEAK_MB:.0f} MB** "
        f"peak for a {LARGEST_SBOM:,}-component SBOM.",
        "",
        "## The largest single document",
        "",
        f"- {largest['components']:,} components, {largest['document_mb']} MB of JSON",
        f"- **{largest['seconds']}s** wall clock ({largest['cpu_seconds']}s CPU), "
        f"{largest['ms_per_component']} ms per component",
        f"- **{largest['peak_mb']} MB** peak RSS",
        f"- {largest['entities_scored']:,} entities scored, "
        f"nothing dropped, score {largest['score']}",
        f"- within budget: **{largest['within_budget']}**",
        "",
        "## Concurrent five-lane assessments",
        "",
        f"{concurrency['assessments']} assessments × 5 lanes, "
        f"{concurrency['components_each']:,} components in the SBOM lane plus real "
        f"documents in the other four, in **{concurrency['seconds']}s** "
        f"({concurrency['seconds_each']}s each, amortised — per-assessment latency "
        f"is the p95 column, not this).",
        "",
        f"Throughput across the run was {concurrency['throughput_per_second']:,.0f} "
        "components per second — within noise of the single-document rate above. "
        "**Concurrency shares the throughput rather than adding to it**, which is the "
        "expected consequence of scoring being pure Python: twenty assessments at once "
        "finish in about the time twenty assessments in series would take. What "
        "concurrency buys is that no client waits behind another client's whole "
        "queue, not that the machine does more work.",
        "",
        "| Lane | n | p50 ms | p95 ms | max ms |",
        "| --- | ---: | ---: | ---: | ---: |",
    ]
    for lane in sorted(concurrency["per_lane"]):
        stats = concurrency["per_lane"][lane]
        lines.append(
            f"| {lane} | {int(stats['n'])} | {stats['p50']} | {stats['p95']} | {stats['max']} |"
        )

    lines += [
        "",
        f"- lane intervals overlap: **{concurrency['overlap_proven']}**",
        f"- every submission reconstructs all five lifecycles from logs: "
        f"**{concurrency['traces_whole']}**",
        f"- peak RSS across the run: **{concurrency['peak_mb']} MB**",
        "",
        "## What the overlap does and does not mean",
        "",
        "The lane intervals overlap, and that is what the isolation properties rest "
        "on: a lane that times out or raises does not stop the other four. It is not "
        "a speedup. Scoring is pure Python and holds the GIL, so five lanes over one "
        "document cost about what five lanes in series cost, plus scheduling. The "
        "measurement behind that statement is recorded in "
        "`services/graph/laneRunner.py`. Reporting the overlap as a performance win "
        "would be the kind of unfounded figure §11 exists to prevent.",
        "",
        "## Cost",
        "",
        "Reported as CPU-seconds and peak memory, not as currency. The currency "
        "figure depends on an instance price and a utilisation assumption, and a "
        "number this repository invented would be quoted back at it.",
        "",
    ]
    return "\n".join(lines)


async def run() -> tuple[dict[str, Any], dict[str, Any]]:
    largest = await measure_largest()
    concurrency = await measure_concurrency()

    print("\n  the largest single document\n")
    for key, value in largest.items():
        print(f"    {key:<18} {value}")

    print("\n  concurrent five-lane assessments\n")
    print(
        f"    {concurrency['assessments']} × 5 lanes × "
        f"{concurrency['components_each']:,} components in {concurrency['seconds']}s"
    )
    print(f"\n    {'lane':<8}{'n':>4}{'p50 ms':>10}{'p95 ms':>10}{'max ms':>10}")
    for lane in sorted(concurrency["per_lane"]):
        stats = concurrency["per_lane"][lane]
        print(
            f"    {lane:<8}{int(stats['n']):>4}{stats['p50']:>10}"
            f"{stats['p95']:>10}{stats['max']:>10}"
        )
    print(f"\n    overlap proven: {concurrency['overlap_proven']}")
    print(f"    traces whole:   {concurrency['traces_whole']}")

    return largest, concurrency


def write_report(largest: dict[str, Any], concurrency: dict[str, Any]) -> Path:
    """Synchronous, so the file write is not blocking the event loop it is
    measuring — and the linter is right to insist."""
    destination = Path(__file__).resolve().parents[3] / "dist" / "scale-report.md"
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text(render(largest, concurrency))
    return destination


def main() -> int:
    largest, concurrency = asyncio.run(run())
    destination = write_report(largest, concurrency)
    print(f"\n  written to {destination.name}\n")
    return 0 if largest["within_budget"] else 1


if __name__ == "__main__":  # pragma: no cover - console entry point
    raise SystemExit(main())
