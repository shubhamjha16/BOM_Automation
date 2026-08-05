"""The s.3.3 SSDLC maturity roadmap, encoded as data with its clauses.

Encoded the same way the minimum-element catalogue is, and for the same reason:
these activities are the factual basis of a maturity scorecard, and one wrong
clause discredits it entirely. The S20 catalogue audit covers this table too.

**The `observable` flag is the sprint's whole design.** Section 3.3 mixes two
kinds of activity: things a platform can *see* — an SBOM step in a pipeline,
pinned dependencies, a VEX history — and things it can only *ask about*, like
whether a governance body exists or whether procurement contracts carry SBOM
clauses. Conflating them produces a scorecard that looks evidence-based and is
half questionnaire, which is precisely the thing this sprint claims to replace.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum


class Phase(StrEnum):
    START = "start"
    PROGRESS = "progress"
    ADVANCE = "advance"


PHASE_ORDER: dict[Phase, int] = {Phase.START: 0, Phase.PROGRESS: 1, Phase.ADVANCE: 2}


@dataclass(frozen=True, slots=True)
class Activity:
    key: str
    phase: Phase
    label: str
    clause: str
    #: True when the platform can observe this from a repository, a pipeline or
    #: its own submission history. False means it can only be asked.
    observable: bool
    #: What the platform looks for, when observable.
    signal: str = ""
    #: What is asked, when not. Rendered beside the verdict, so a reader can see
    #: exactly what was put to whom.
    question: str = ""

    def __post_init__(self) -> None:
        if self.observable and not self.signal:
            raise ValueError(
                f"{self.key}: an observable activity must name the signal it is "
                "derived from, or 'evidenced' means nothing"
            )
        if not self.observable and not self.question:
            raise ValueError(
                f"{self.key}: an attested activity must carry the question that was "
                "asked — an attestation without its question is unreviewable"
            )


ACTIVITIES: tuple[Activity, ...] = (
    # --- START (3.3.1) ----------------------------------------------------
    Activity(
        key="inventory_dependencies",
        phase=Phase.START,
        label="Maintain an inventory of third-party dependencies",
        clause="3.3.1.1",
        observable=True,
        signal="a dependency manifest is present in the repository",
    ),
    Activity(
        key="pin_dependencies",
        phase=Phase.START,
        label="Pin dependencies to exact versions",
        clause="3.3.1.2",
        observable=True,
        signal="a lockfile is present, so builds resolve to exact versions",
    ),
    Activity(
        key="generate_sbom",
        phase=Phase.START,
        label="Generate an SBOM for each product",
        clause="3.3.1.3",
        observable=True,
        signal="an SBOM generation step or artifact exists in the repository",
    ),
    Activity(
        key="procurement_clauses",
        phase=Phase.START,
        label="Require SBOMs in procurement contracts",
        clause="3.3.1.4",
        observable=False,
        question=(
            "Do your procurement contracts and dependency-adoption policy require "
            "suppliers to provide an SBOM? Please provide the clause."
        ),
    ),
    # --- PROGRESS (3.3.2) --------------------------------------------------
    Activity(
        key="secure_installation",
        phase=Phase.PROGRESS,
        label="Publish a secure installation and operation checklist",
        clause="3.3.2.1",
        observable=True,
        signal="installation or hardening documentation is present",
    ),
    Activity(
        key="vulnerability_scanning",
        phase=Phase.PROGRESS,
        label="Scan dependencies for known vulnerabilities",
        clause="3.3.2.2",
        observable=True,
        signal="a dependency-audit step runs in the pipeline",
    ),
    Activity(
        key="sbom_in_pipeline",
        phase=Phase.PROGRESS,
        label="Integrate SBOM generation into each SSDLC phase",
        clause="3.3.2.5",
        observable=True,
        signal="an SBOM step runs in CI, not only on a developer's machine",
    ),
    Activity(
        key="access_controls_on_boms",
        phase=Phase.PROGRESS,
        label="Apply access controls to stored BOMs",
        clause="3.3.2.6",
        observable=True,
        signal="stored BOMs are tenant-scoped and access-controlled in the platform",
    ),
    Activity(
        key="training",
        phase=Phase.PROGRESS,
        label="Train development teams on SSDLC practice",
        clause="7.2.15",
        observable=False,
        question=(
            "Is SSDLC and supply-chain security training delivered to development "
            "teams, and how often? Please provide the most recent attendance record."
        ),
    ),
    # --- ADVANCE (3.3.3) ---------------------------------------------------
    Activity(
        key="vex_history",
        phase=Phase.ADVANCE,
        label="Maintain a VEX history for disclosed vulnerabilities",
        clause="3.3.3.1",
        observable=True,
        signal="VEX statements exist in the platform for this organisation",
    ),
    Activity(
        key="incident_playbook",
        phase=Phase.ADVANCE,
        label="Operate a VEX and incident-response playbook",
        clause="3.3.3.2",
        observable=True,
        signal="a security policy or disclosure route is published in the repository",
    ),
    Activity(
        key="release_cadence",
        phase=Phase.ADVANCE,
        label="Re-assess on every release, update and patch",
        clause="2.3",
        observable=True,
        signal="submission cadence in the platform matches release cadence",
    ),
    Activity(
        key="continuous_monitoring",
        phase=Phase.ADVANCE,
        label="Monitor supplier conformance continuously",
        clause="3.3.3.3",
        observable=True,
        signal="the organisation has submissions across multiple periods",
    ),
    Activity(
        key="governance_body",
        phase=Phase.ADVANCE,
        label="Establish an accountable governance body",
        clause="5.1(d)",
        observable=False,
        question=(
            "Which body is accountable for software supply-chain security, who "
            "chairs it, and how often does it meet? Please provide its terms of "
            "reference."
        ),
    ),
)


def by_phase(phase: Phase) -> list[Activity]:
    return [activity for activity in ACTIVITIES if activity.phase is phase]


def by_key(key: str) -> Activity:
    for activity in ACTIVITIES:
        if activity.key == key:
            return activity
    raise KeyError(f"no maturity activity {key!r}")


def observable() -> list[Activity]:
    return [activity for activity in ACTIVITIES if activity.observable]


def attestable() -> list[Activity]:
    """Activities the platform cannot observe. Asked, never inferred."""
    return [activity for activity in ACTIVITIES if not activity.observable]


def catalogue() -> list[dict[str, object]]:
    """The roadmap, inspectable — as the minimum elements are."""
    return [
        {
            "key": activity.key,
            "phase": str(activity.phase),
            "label": activity.label,
            "clause": activity.clause,
            "observable": activity.observable,
            "signal": activity.signal or None,
            "question": activity.question or None,
        }
        for activity in ACTIVITIES
    ]
