"""Job types and the enumerations the graph and the console agree on.

`frontend/src/shared/constants/jobTypes.ts` mirrors this file. The two are checked
against each other in CI once `packages/api-types` generation lands (S3).
"""

from __future__ import annotations

from enum import StrEnum


class JobType(StrEnum):
    # Assessment: the deterministic conformance path.
    ASSESS_SUBMISSION = "assess_submission"
    RESCORE_SUBMISSION = "rescore_submission"
    # Narrative: the drafted, critiqued, healed prose path.
    NARRATIVE_GAP_REPORT = "narrative_gap_report"
    NARRATIVE_ROADMAP = "narrative_roadmap"
    NARRATIVE_ADVISORY = "narrative_advisory"
    # VEX: authored by an analyst, evidenced by an agent (S12).
    VEX_DRAFT_JUSTIFICATION = "vex_draft_justification"
    VEX_CSAF_EXPORT = "vex_csaf_export"
    # Generation from a connected repository (S17). A job rather than a bare
    # service call because it takes minutes, is metered separately from
    # submissions (S21) and is re-run on every release per s.2.3 — all three need
    # a durable record, and a synchronous call leaves none.
    GENERATE_FROM_REPO = "generate_from_repo"


ASSESSMENT_TYPES: frozenset[JobType] = frozenset(
    {JobType.ASSESS_SUBMISSION, JobType.RESCORE_SUBMISSION}
)
NARRATIVE_TYPES: frozenset[JobType] = frozenset(
    {JobType.NARRATIVE_GAP_REPORT, JobType.NARRATIVE_ROADMAP, JobType.NARRATIVE_ADVISORY}
)
VEX_TYPES: frozenset[JobType] = frozenset(
    {JobType.VEX_DRAFT_JUSTIFICATION, JobType.VEX_CSAF_EXPORT}
)
GENERATION_TYPES: frozenset[JobType] = frozenset({JobType.GENERATE_FROM_REPO})
ALL_JOB_TYPES: frozenset[JobType] = (
    ASSESSMENT_TYPES | NARRATIVE_TYPES | VEX_TYPES | GENERATION_TYPES
)


class JobStatus(StrEnum):
    QUEUED = "queued"
    RUNNING = "running"
    SUCCEEDED = "succeeded"
    FAILED = "failed"
    # The conformance gate (S8) terminates here. It is not a failure of the job;
    # it is a refusal to render an assessment that could not be traced to a clause.
    BLOCKED_CONFORMANCE = "blocked_conformance"


TERMINAL_STATUSES: frozenset[JobStatus] = frozenset(
    {JobStatus.SUCCEEDED, JobStatus.FAILED, JobStatus.BLOCKED_CONFORMANCE}
)


class LaneVerdict(StrEnum):
    PASS = "pass"
    CONDITIONAL = "conditional"
    FAIL = "fail"
    # The lane was expected and is not here — a finding against the supplier.
    LANE_ABSENT = "lane_absent"
    # The lane exceeded LANE_TIMEOUT_SECONDS. Reported, never silently dropped.
    LANE_TIMEOUT = "lane_timeout"
    # The engagement does not enable this lane — excluded from the overall score.
    # This is not the same thing as LANE_ABSENT. See §11.
    LANE_NOT_APPLICABLE = "lane_not_applicable"


SCORED_LANE_VERDICTS: frozenset[LaneVerdict] = frozenset(
    {LaneVerdict.PASS, LaneVerdict.CONDITIONAL, LaneVerdict.FAIL, LaneVerdict.LANE_ABSENT}
)
"""Verdicts that contribute to the overall submission score.

LANE_NOT_APPLICABLE is excluded: a client with no quantum hardware should not carry a
zero-scoring empty lane. LANE_TIMEOUT is excluded because it is an infrastructure
outcome, not a supplier one, and is reported explicitly instead.
"""


class FieldVerdict(StrEnum):
    PRESENT = "present"
    ABSENT = "absent"
    # Cannot be established from a BOM artifact at all → consumer action,
    # excluded from the supplier score, never rendered as compliant.
    NOT_DETERMINABLE = "not_determinable"


class Tier(StrEnum):
    CRITICAL = "critical"
    STANDARD = "standard"
    CONTEXTUAL = "contextual"


class Determinability(StrEnum):
    AUTO = "auto"
    ENRICH = "enrich"
    HUMAN = "human"
