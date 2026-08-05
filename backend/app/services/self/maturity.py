"""Assess our own SSDLC maturity, and publish it — gaps included.

**A maturity tool that reports only its own strengths is not evidence of
anything.** So this runs the same engine over this repository, and the published
scorecard names what we do not do. The activities we fail are the interesting
part of the output, not an embarrassment to be trimmed.

Run: ``uv run python -m app.services.self.maturity``
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

from app.services.maturity.evidence import (
    PlatformSignals,
    Verdict,
    attested,
    derive,
    observe_repository,
)
from app.services.maturity.roadmap import attestable
from app.services.maturity.scorecard import Scorecard

#: Our own answers to the three questions the platform cannot observe. Recorded
#: as attestations and rendered as attestations — never as evidence.
OUR_ATTESTATIONS: dict[str, tuple[Verdict, str]] = {
    "procurement_clauses": (
        # PARTIAL, deliberately, and the distinction is the honest part: clause
        # 3.3.1.4 covers procurement *contracts* with suppliers. We have written
        # the dependency-adoption half of it and have no commercial procurement
        # contracts at all, so claiming MET would be reading our own policy as
        # something it is not.
        Verdict.PARTIAL,
        "SECURITY.md carries a dependency-adoption policy requiring a pinned "
        "lockfile, an identifiable licence, a resolvable supplying organisation "
        "and a passing audit. We hold no commercial procurement contracts, so the "
        "contractual half of 3.3.1.4 is not applicable rather than met.",
    ),
    "training": (
        Verdict.NOT_MET,
        "No SSDLC training programme is run. This is a single-repository project "
        "with no development team to train.",
    ),
    "governance_body": (
        Verdict.NOT_MET,
        "No accountable governance body exists. There is no board, no chair and no "
        "terms of reference.",
    ),
}


def _our_vex_statements() -> list:
    """Our own published determinations, counted as evidence."""
    from app.services.self.vexProcess import statements

    return statements()


def build(root: Path | None = None) -> Scorecard:
    repository = Path(root or Path(__file__).resolve().parents[4])
    signals = observe_repository(repository)

    scorecard = Scorecard(
        verdicts=derive(
            signals,
            PlatformSignals(
                # Honest: this deployment has assessed only its own submissions,
                # and has authored no VEX statements.
                # We now publish VEX statements for our own dependencies, so
                # this is evidenced rather than aspirational.
                vex_statements=len(_our_vex_statements()),
                submissions=0,
                distinct_periods=0,
                releases_assessed=0,
                releases_total=0,
                boms_access_controlled=True,
            ),
        )
    )
    for activity in attestable():
        verdict, answer = OUR_ATTESTATIONS[activity.key]
        scorecard.verdicts.append(attested(activity, verdict, answer=answer))
    return scorecard


def main() -> int:
    scorecard = build()
    report = scorecard.as_report()

    print("BOM Factory — SSDLC maturity, self-assessed\n")
    print(f"  position: {report['position']}")
    print(f"  {report['evidenced']} evidenced, {report['attested']} attested\n")

    for phase in report["phases"]:
        print(
            f"  {phase['phase']:<9} {phase['met']}/{phase['total']} met "
            f"({phase['completion']}%)  evidenced={phase['evidenced']} "
            f"attested={phase['attested']}"
        )

    print("\n  what we do not do:")
    for gap in report["gaps"]:
        marker = "attested" if gap["basis"] == "attested" else "evidenced"
        print(f"    [{marker:<9}] {gap['clause']:<10} {gap['label']}")
        print(f"                  {gap['detail'][:96]}")

    destination = Path(__file__).resolve().parents[4] / "dist" / "maturity-scorecard.json"
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text(json.dumps(report, indent=2) + "\n")
    print(f"\n  written to {destination.name}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
