"""Phase position from activity verdicts.

**A phase is claimed only when its activities are actually met** — and the
position is the *highest fully-met phase*, not an average. Averaging would let a
strong ADVANCE showing paper over an unmet START activity, which inverts the
roadmap: s.3.3's phases are sequential because the later ones depend on the
earlier.

The scorecard reports evidenced and attested counts separately at every level. A
reader must be able to see how much of a position rests on observation and how
much on somebody's word.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from app.services.maturity.evidence import ActivityVerdict, Basis, Verdict
from app.services.maturity.roadmap import ACTIVITIES, PHASE_ORDER, Phase, by_key


@dataclass(frozen=True, slots=True)
class PhaseResult:
    phase: Phase
    met: int
    partial: int
    not_met: int
    unknown: int
    total: int
    evidenced: int
    attested: int

    @property
    def is_complete(self) -> bool:
        """Every activity met. Partial does not count: a phase is a floor."""
        return self.total > 0 and self.met == self.total

    @property
    def completion(self) -> float:
        if not self.total:
            return 0.0
        # Partial counts as half — enough to show movement, never enough to
        # complete a phase.
        return round((self.met + self.partial * 0.5) / self.total * 100, 1)

    def as_row(self) -> dict[str, Any]:
        return {
            "phase": str(self.phase),
            "met": self.met,
            "partial": self.partial,
            "not_met": self.not_met,
            "unknown": self.unknown,
            "total": self.total,
            "completion": self.completion,
            "complete": self.is_complete,
            "evidenced": self.evidenced,
            "attested": self.attested,
        }


@dataclass(slots=True)
class Scorecard:
    verdicts: list[ActivityVerdict] = field(default_factory=list)

    @property
    def by_activity(self) -> dict[str, ActivityVerdict]:
        return {verdict.activity_key: verdict for verdict in self.verdicts}

    def phase(self, phase: Phase) -> PhaseResult:
        keys = {activity.key for activity in ACTIVITIES if activity.phase is phase}
        rows = [verdict for verdict in self.verdicts if verdict.activity_key in keys]
        counts = {outcome: 0 for outcome in Verdict}
        for row in rows:
            counts[row.verdict] += 1

        return PhaseResult(
            phase=phase,
            met=counts[Verdict.MET],
            partial=counts[Verdict.PARTIAL],
            not_met=counts[Verdict.NOT_MET],
            unknown=counts[Verdict.UNKNOWN],
            total=len(keys),
            evidenced=sum(1 for row in rows if row.basis is Basis.EVIDENCED),
            attested=sum(1 for row in rows if row.basis is Basis.ATTESTED),
        )

    @property
    def position(self) -> Phase | None:
        """The highest phase whose activities are all met.

        None when even START is incomplete — reported as such rather than
        rounded up to START, because claiming a phase nobody reached is the
        maturity equivalent of scoring an empty BOM as compliant.
        """
        reached: Phase | None = None
        for phase in sorted(Phase, key=lambda item: PHASE_ORDER[item]):
            if self.phase(phase).is_complete:
                reached = phase
            else:
                break
        return reached

    @property
    def evidenced_count(self) -> int:
        return sum(1 for verdict in self.verdicts if verdict.is_evidenced)

    @property
    def attested_count(self) -> int:
        return sum(1 for verdict in self.verdicts if not verdict.is_evidenced)

    @property
    def gaps(self) -> list[ActivityVerdict]:
        """What is not met, earliest phase first — the work queue."""
        unmet = [
            verdict
            for verdict in self.verdicts
            if verdict.verdict in (Verdict.NOT_MET, Verdict.PARTIAL, Verdict.UNKNOWN)
        ]
        return sorted(unmet, key=lambda row: PHASE_ORDER[by_key(row.activity_key).phase])

    def as_report(self) -> dict[str, Any]:
        return {
            "position": str(self.position) if self.position else "below start",
            "phases": [self.phase(phase).as_row() for phase in Phase],
            # Reported separately at the top level too: a reader must see how
            # much of this rests on observation.
            "evidenced": self.evidenced_count,
            "attested": self.attested_count,
            "activities": [verdict.as_row() for verdict in self.verdicts],
            "gaps": [verdict.as_row() for verdict in self.gaps],
        }
