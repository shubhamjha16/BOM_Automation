"""Per-engagement CI thresholds. **The gate defaults to warn.**

A gate that blocks builds on day one is disabled by the platform team on day two,
and a disabled gate reports nothing at all. So `warn` is the default, blocking is
a decision an organisation takes *after* it has seen its own scores, and the
setting lives per engagement rather than globally — a supplier onboarding
engagement and a mature continuous one have earned different treatment.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum


class GateMode(StrEnum):
    #: Report the finding; never fail the build. The default, deliberately.
    WARN = "warn"
    #: Fail the check when the threshold is not met.
    BLOCK = "block"
    #: Report nothing. Recorded so a silent pipeline is a choice, not an accident.
    OFF = "off"


@dataclass(frozen=True, slots=True)
class GatePolicy:
    mode: GateMode = GateMode.WARN
    minimum_score: float = 85.0
    #: Clauses that fail the check regardless of score, when blocking. Empty by
    #: default: an organisation names its own non-negotiables.
    blocking_clauses: frozenset[str] = frozenset()
    #: A critical gap fails at any score — the same rule as the lane verdict.
    block_on_critical_gap: bool = True

    def decide(
        self, *, score: float | None, critical_gaps: list[str], failing_clauses: list[str]
    ) -> tuple[bool, str]:
        """Return (passed, summary). `passed` is what the check reports.

        In `warn` mode this always returns True — the finding is still reported
        in the check's body, which is the point: visible without leaving the pull
        request, and not blocking anyone's afternoon.
        """
        problems: list[str] = []
        if score is None:
            problems.append("no score was produced")
        elif score < self.minimum_score:
            problems.append(f"scored {score}%, below the {self.minimum_score}% threshold")
        if self.block_on_critical_gap and critical_gaps:
            problems.append(f"critical gap(s): {', '.join(critical_gaps)}")
        if named := sorted(set(failing_clauses) & self.blocking_clauses):
            problems.append(f"blocking clause(s) unmet: {', '.join(named)}")

        if self.mode is GateMode.OFF:
            return True, "conformance gate is off for this engagement"
        if not problems:
            return True, f"conformance check passed: scored {score}%"

        summary = "; ".join(problems)
        if self.mode is GateMode.WARN:
            # Reported, not enforced. The team sees it and the build proceeds.
            return True, f"conformance findings (warn mode, not blocking): {summary}"
        return False, f"conformance check failed: {summary}"
