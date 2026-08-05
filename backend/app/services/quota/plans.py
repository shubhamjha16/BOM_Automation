"""Per-plan limits.

Held as data, and **unlimited is written as `None` rather than as a large
number.** A sentinel like 999_999 eventually gets compared, logged and displayed,
and then somebody asks a client to explain why they are approaching a limit that
does not exist.

The numbers themselves are commercial policy rather than engineering, so they live
in one table that a non-engineer can read and an engineer can change without
touching a code path.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum


class Plan(StrEnum):
    STARTER = "starter"
    PRACTICE = "practice"
    FIRM = "firm"
    ENTERPRISE = "enterprise"


class Quota(StrEnum):
    """The four things that cost us money to serve."""

    SUBMISSIONS = "submissions_per_month"
    COMPONENTS = "components_per_submission"
    REPO_GENERATIONS = "repo_generations_per_month"
    REQUESTS = "requests_per_minute"


@dataclass(frozen=True, slots=True)
class Limits:
    submissions_per_month: int | None
    components_per_submission: int | None
    repo_generations_per_month: int | None
    requests_per_minute: int | None

    def of(self, quota: Quota) -> int | None:
        return getattr(self, str(quota))


PLAN_LIMITS: dict[Plan, Limits] = {
    Plan.STARTER: Limits(
        submissions_per_month=25,
        components_per_submission=5_000,
        # Generation resolves dependencies in a sandbox and takes minutes rather
        # than seconds (S17), so it is metered separately and far more tightly.
        repo_generations_per_month=5,
        requests_per_minute=120,
    ),
    Plan.PRACTICE: Limits(
        submissions_per_month=250,
        components_per_submission=50_000,
        repo_generations_per_month=50,
        requests_per_minute=600,
    ),
    Plan.FIRM: Limits(
        submissions_per_month=2_000,
        components_per_submission=50_000,
        repo_generations_per_month=400,
        requests_per_minute=1_200,
    ),
    Plan.ENTERPRISE: Limits(
        submissions_per_month=None,
        components_per_submission=None,
        repo_generations_per_month=None,
        requests_per_minute=None,
    ),
}


def limits_for(plan: str) -> Limits:
    """The limits for a plan name from the database.

    An unrecognised plan gets the **most restrictive** limits, not the most
    generous. A typo in a plan column must not silently grant unlimited service,
    and the failure is visible to the client as a 429 they can query rather than
    invisible to us as a bill.
    """
    try:
        return PLAN_LIMITS[Plan(plan)]
    except ValueError:
        return PLAN_LIMITS[Plan.STARTER]
