"""Score this repository's own SBOM with this repository's own engine.

A conformance tool that is itself non-conformant has no standing to issue an
assessment, and it is the first thing a reviewer checks. S13 turns the reported
score into a CI gate at ``SELF_CONFORMANCE_MIN``; until the enrichment (S10) and
identifier (S11) work can actually populate the fields the score depends on,
gating would only prove that unimplemented sprints score badly.

Run: ``uv run python -m app.services.self.selfScore dist/bom-automation.cdx.json``
"""

from __future__ import annotations

import asyncio
import json
import sys
from pathlib import Path

from app.configs.envConfig import settings
from app.services.assessmentService import run_assessment
from app.services.graph.state import SubmissionDocument


async def score_self(payload: dict, name: str) -> int:
    summary = await run_assessment(
        org_id="self",
        submission_id=f"self-bom:{name}",
        documents=[SubmissionDocument(lane="sbom", format="CycloneDX", payload=payload)],
        requested_lanes=["sbom"],
    )
    result = next(item for item in summary.lane_results if item.lane == "sbom")

    print(
        f"self-conformance: {result.score}% ({result.verdict}) "
        f"over {result.entity_count} components"
    )
    print(f"  {result.detail}")
    print(f"  threshold for the S13 gate: {settings.SELF_CONFORMANCE_MIN}%")
    if result.score is not None and result.score < settings.SELF_CONFORMANCE_MIN:
        print("  NOT YET GATING — reported only until S10/S11 populate the enriched fields")
    return 0


def emit_self_boms(destination: Path) -> dict[str, Path]:
    """Write our own AIBOM and CBOM beside the generated SBOM.

    Written rather than generated: 9.3(15)-(16) are governance declarations and
    a CBOM is not derivable from a dependency scan. Both are the honest form of
    "we ship what we ask for".
    """
    from app.services.self import aibom, cbom

    destination.mkdir(parents=True, exist_ok=True)
    written: dict[str, Path] = {}
    for name, builder in (("aibom", aibom.build), ("cbom", cbom.build)):
        path = destination / f"bom-automation.{name}.cdx.json"
        path.write_text(json.dumps(builder(), indent=2) + "\n")
        written[name] = path
    return written


def main() -> int:
    if len(sys.argv) != 2:
        print("usage: python -m app.services.self.selfScore <sbom.cdx.json>", file=sys.stderr)
        return 2
    path = Path(sys.argv[1])
    if not path.exists():
        print(f"no such SBOM: {path}; run `make self-bom` first", file=sys.stderr)
        return 2
    # Read before entering the loop: this is a CLI, not a request path.
    return asyncio.run(score_self(json.loads(path.read_text()), path.name))


if __name__ == "__main__":
    raise SystemExit(main())
