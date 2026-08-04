"""Persisted enumerations.

Separate from `configs/jobTypes.py` because these become Postgres enum types: a
value here is a schema object with a migration behind it, whereas the config
enums are free to change with the code. Where the two overlap — job status —
this module re-exports rather than redefines, so they cannot drift.
"""

from __future__ import annotations

from enum import StrEnum

from app.configs.jobTypes import (
    Determinability,
    FieldVerdict,
    JobStatus,
    JobType,
    LaneVerdict,
    Tier,
)

__all__ = [
    "BomFormat",
    "Determinability",
    "FieldVerdict",
    "LaneVerdict",
    "Tier",
    "DocumentStatus",
    "EngagementKind",
    "EngagementStatus",
    "JobStatus",
    "JobType",
    "Role",
    "Sector",
    "SubmissionStatus",
]


class Role(StrEnum):
    PARTNER = "partner"
    MANAGER = "manager"
    ASSESSOR = "assessor"
    READONLY = "readonly"
    #: A client user sees their own engagement and provably nothing else (S16).
    CLIENT = "client"


class Sector(StrEnum):
    """Recommendation 7.1.2 bites hardest on the first three."""

    GOVT = "govt"
    PSU = "psu"
    ESSENTIAL = "essential"
    PRIVATE = "private"


class EngagementKind(StrEnum):
    PROCUREMENT_REVIEW = "procurement_review"
    SUPPLIER_ONBOARDING = "supplier_onboarding"
    ESTATE_ASSESSMENT = "estate_assessment"
    CONTINUOUS = "continuous"


class EngagementStatus(StrEnum):
    ACTIVE = "active"
    PAUSED = "paused"
    CLOSED = "closed"


class SubmissionStatus(StrEnum):
    """The submission lifecycle.

    `returned` is a first-class state, not an error: returning a submission to
    the supplier with its gap register attached is the workflow this product
    exists to support (S13).
    """

    RECEIVED = "received"
    PARSED = "parsed"
    SCORED = "scored"
    ASSESSED = "assessed"
    RETURNED = "returned"
    ACCEPTED = "accepted"


class BomFormat(StrEnum):
    CYCLONEDX = "CycloneDX"
    SPDX = "SPDX"


class DocumentStatus(StrEnum):
    RECEIVED = "received"
    PARSED = "parsed"
    #: The document could not be read at all. Never silently an empty component
    #: list, because an empty list renders a green assessment (rec. 7.1.5).
    REJECTED = "rejected"
