"""The s.3.3 SSDLC maturity roadmap, encoded as data with its clauses.

s.3.3 of the guideline lists 14 activities in three phases (START 3.3.1.1 to 3.3.1.4, PROGRESS
3.3.2.1 to 3.3.2.6, ADVANCE 3.3.3.1 to 3.3.3.4). Each is encoded here, with the exact clause the
guideline gives it, plus four activities from elsewhere in the guideline (2.3, 5.1(d), 7.1.6,
7.2.15).
Two activities this product measures that the guideline does not list (an inventory of
dependencies and pinned dependencies) are kept as the product's own practices: they carry no
clause and do not count toward a phase being complete. An earlier version of this table cited
s.3.3 clauses that belong to other activities.

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
    #: False for an activity this product measures that the guideline does not list.
    #: Such an activity has no clause, is shown as the product's own practice, and does
    #: not count toward a phase being complete.
    guideline: bool = True

    def __post_init__(self) -> None:
        if self.guideline and not self.clause:
            raise ValueError(f"{self.key}: a guideline activity must cite its clause")
        if not self.guideline and self.clause:
            raise ValueError(
                f"{self.key}: an activity the guideline does not list must not carry a clause; "
                "a clause reference is a claim that the guideline says this"
            )
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
        key="critical_assets_plan",
        phase=Phase.START,
        label="Identify critical assets and develop a project plan",
        clause="3.3.1.1",
        observable=False,
        question=(
            "Have you identified your critical software assets and written an SBOM project "
            "plan that defines roles, responsibilities, timelines and resources, with the "
            "change management needed to bring stakeholders on board? Please provide the plan."
        ),
    ),
    Activity(
        key="sbom_format_requirements",
        phase=Phase.START,
        label="Determine the SBOM format and minimum requirements",
        clause="3.3.1.2",
        observable=False,
        question=(
            "Which SBOM format (SPDX or CycloneDX) and which minimum data requirements have "
            "you defined, and where are they documented?"
        ),
    ),
    Activity(
        key="secure_storage_tooling",
        phase=Phase.START,
        label="Identify security requirements, secure storage and tooling",
        clause="3.3.1.3",
        observable=False,
        question=(
            "How are SBOMs classified and handled under your security policies, where are "
            "they stored (for example dedicated repositories), and which tooling is used? "
            "Please provide the policy."
        ),
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
    # The product's own practices, which the guideline does not list.
    Activity(
        key="inventory_dependencies",
        phase=Phase.START,
        label="Maintain an inventory of third-party dependencies",
        clause="",
        observable=True,
        signal="a dependency manifest is present in the repository",
        guideline=False,
    ),
    Activity(
        key="pin_dependencies",
        phase=Phase.START,
        label="Pin dependencies to exact versions",
        clause="",
        observable=True,
        signal="a lockfile is present, so builds resolve to exact versions",
        guideline=False,
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
        key="unique_identifiers",
        phase=Phase.PROGRESS,
        label="Assign unique identifiers to each component",
        clause="3.3.2.2",
        observable=False,
        question=(
            "Do you assign a unique identifier to each component (for example the "
            "pkg:supplier/... form of the guideline's Table 3), and how do you map a "
            "supplier or component rename to its earlier names?"
        ),
    ),
    Activity(
        key="supplier_sbom_mapping",
        phase=Phase.PROGRESS,
        label="Map the supplier's SBOM to the consumer's internal SBOM",
        clause="3.3.2.3",
        observable=False,
        question=(
            "Do you build an internal SBOM from each supplier's SBOM, recording the author "
            "and a timestamp of the consumer organisation? Please provide an example."
        ),
    ),
    Activity(
        key="generate_sbom",
        phase=Phase.PROGRESS,
        label="Prepare an SBOM for each product",
        clause="3.3.2.4",
        observable=True,
        signal="an SBOM generation step or artifact exists in the repository",
    ),
    Activity(
        key="sbom_in_pipeline",
        phase=Phase.PROGRESS,
        label="Integrate SBOM in each phase of the secure software development lifecycle",
        clause="3.3.2.5",
        observable=True,
        signal="an SBOM step runs in CI, not only on a developer's machine",
    ),
    Activity(
        key="access_controls_on_boms",
        phase=Phase.PROGRESS,
        label="Establish secure configuration management (access controls on stored BOMs)",
        clause="3.3.2.6",
        observable=True,
        signal=(
            "stored BOMs are tenant-scoped and access-controlled in the platform. This is the "
            "access-control part of 3.3.2.6 only; encryption and periodic audits are not observed"
        ),
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
        key="vulnerability_scanning",
        phase=Phase.ADVANCE,
        label="Enhance vulnerability tracking processes (dependency scanning)",
        clause="3.3.3.1",
        observable=True,
        signal="a dependency-audit step runs in the pipeline",
    ),
    Activity(
        key="incident_playbook",
        phase=Phase.ADVANCE,
        label="Enhance the incident-response process",
        clause="3.3.3.2",
        observable=True,
        signal="a security policy or disclosure route is published in the repository",
    ),
    Activity(
        key="continuous_monitoring",
        phase=Phase.ADVANCE,
        label="Periodic analysis and review for updating existing SBOMs",
        clause="3.3.3.3",
        observable=True,
        signal="the organisation has submissions across multiple periods",
    ),
    Activity(
        key="emerging_awareness",
        phase=Phase.ADVANCE,
        label="Maintain awareness of emerging software components and industry advancements",
        clause="3.3.3.4",
        observable=False,
        question=(
            "Do you run an SBOM awareness programme, alone or with third parties, to keep up "
            "with new SBOM formats, data elements and implementation challenges?"
        ),
    ),
    Activity(
        key="vex_history",
        phase=Phase.ADVANCE,
        label="Maintain a VEX history for disclosed vulnerabilities",
        clause="7.1.6",
        observable=True,
        signal="VEX statements exist in the platform for this organisation",
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

#: Every guideline activity's clause was checked against the published text of s.3.3 (the
#: fourteen numbered activities), s.2.3 (SBOM implementation), s.5.1(d) (establish governance),
#: s.7.1.6 (the VEX recommendation) and s.7.2.15 (training and awareness).
ANCHORED_CLAUSES: frozenset[str] = frozenset(
    activity.clause for activity in ACTIVITIES if activity.guideline
)


def guideline_activities() -> list[Activity]:
    """The activities the guideline lists, which are the ones that count toward a phase."""
    return [activity for activity in ACTIVITIES if activity.guideline]


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
            "guideline": activity.guideline,
            "observable": activity.observable,
            "signal": activity.signal or None,
            "question": activity.question or None,
        }
        for activity in ACTIVITIES
    ]
