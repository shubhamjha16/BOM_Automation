"""Persisted enumerations.

Separate from `configs/jobTypes.py` because these become Postgres enum types: a
value here is a schema object with a migration behind it, whereas the config
enums are free to change with the code. Where the two overlap — job status —
this module re-exports rather than redefines, so they cannot drift.
"""

from __future__ import annotations

from enum import StrEnum

from app.configs.jobTypes import JobStatus, JobType

__all__ = ["EngagementKind", "EngagementStatus", "JobStatus", "JobType", "Role", "Sector"]


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
