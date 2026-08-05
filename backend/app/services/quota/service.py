"""Quota decisions. **A refusal is a 429 with a way forward, never a 500.**

The exit condition §S21 sets is about the shape of the answer, not about the
counting: an exhausted quota is a *state the client is in*, which the console
renders as a state. A 500 says we broke; a bare 429 says stop with no indication
of what or for how long. So every refusal carries the quota that bound, the limit,
the usage, when it resets and what to do — enough for the UI to render a screen
rather than a toast, and enough for a support conversation to start from fact.

Counting is scoped by the repository layer like everything else. A quota query
that reached across tenants would be a slow leak of one client's volume to
another's bill.
"""

from __future__ import annotations

import time
import uuid
from collections import deque
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any, Protocol

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.configs.jobTypes import JobType
from app.models.job import Job
from app.models.org import Org
from app.models.submission import Submission
from app.services.quota.plans import Limits, Quota, limits_for


class OrgScoped(Protocol):
    """The two columns a quota count needs. Narrower than `Base` on purpose —
    `_count` reads nothing else, and saying so keeps it honest."""

    org_id: Any
    created_at: Any


class QuotaExceeded(RuntimeError):
    """A quota bound. Carries everything the 429 body and the UI state need."""

    def __init__(
        self,
        *,
        quota: Quota,
        limit: int,
        used: int,
        plan: str,
        resets_at: datetime | None,
        retry_after: int,
        remedy: str,
    ) -> None:
        self.quota = quota
        self.limit = limit
        self.used = used
        self.plan = plan
        self.resets_at = resets_at
        self.retry_after = retry_after
        self.remedy = remedy
        super().__init__(
            f"{quota} limit of {limit} reached on the {plan} plan ({used} used). {remedy}"
        )

    def as_body(self) -> dict[str, object]:
        return {
            "detail": str(self),
            "quota": str(self.quota),
            "limit": self.limit,
            "used": self.used,
            "plan": self.plan,
            "resets_at": self.resets_at.isoformat() if self.resets_at else None,
            "retry_after_seconds": self.retry_after,
            "remedy": self.remedy,
        }


def month_start(now: datetime | None = None) -> datetime:
    moment = now or datetime.now(UTC)
    return moment.replace(day=1, hour=0, minute=0, second=0, microsecond=0)


def next_month_start(now: datetime | None = None) -> datetime:
    start = month_start(now)
    return (
        start.replace(year=start.year + 1, month=1)
        if start.month == 12
        else start.replace(month=start.month + 1)
    )


@dataclass(slots=True)
class Usage:
    """What a tenant has consumed this period, and what remains."""

    plan: str
    limits: Limits
    submissions: int
    repo_generations: int

    def remaining(self, quota: Quota) -> int | None:
        limit = self.limits.of(quota)
        if limit is None:
            return None
        used = self.submissions if quota is Quota.SUBMISSIONS else self.repo_generations
        return max(0, limit - used)

    def as_report(self) -> dict[str, object]:
        return {
            "plan": self.plan,
            "period_start": month_start().isoformat(),
            "period_end": next_month_start().isoformat(),
            "quotas": [
                {
                    "quota": str(quota),
                    "limit": self.limits.of(quota),
                    "used": (
                        self.submissions if quota is Quota.SUBMISSIONS else self.repo_generations
                    ),
                    "remaining": self.remaining(quota),
                    "unlimited": self.limits.of(quota) is None,
                }
                for quota in (Quota.SUBMISSIONS, Quota.REPO_GENERATIONS)
            ],
            "components_per_submission": self.limits.components_per_submission,
            "requests_per_minute": self.limits.requests_per_minute,
        }


def declared_entry_count(payload: dict[str, object]) -> int:
    """How many entries a document declares, across both serialisations.

    CycloneDX calls them ``components``, SPDX calls them ``packages``, and the
    quota is about volume rather than about either vocabulary. Counted from the
    declaration rather than after parsing because the check runs before the parse:
    a document is refused before we pay to read it.
    """
    total = 0
    for key in ("components", "packages"):
        entries = payload.get(key)
        if isinstance(entries, list):
            total += len(entries)
    return total


class QuotaService:
    """Reads usage and decides. Constructed with an org scope, as repositories are."""

    def __init__(self, session: AsyncSession, org_id: uuid.UUID) -> None:
        self.session = session
        self.org_id = org_id

    async def plan(self) -> str:
        org = await self.session.get(Org, self.org_id)
        return org.plan if org else "starter"

    async def usage(self) -> Usage:
        plan = await self.plan()
        since = month_start()
        submissions = await self._count(Submission, since)
        generations = await self._count(Job, since, job_type=JobType.GENERATE_FROM_REPO)
        return Usage(
            plan=plan,
            limits=limits_for(plan),
            submissions=submissions,
            repo_generations=generations,
        )

    async def _count(
        self, model: type[OrgScoped], since: datetime, **filters: object
    ) -> int:
        query = (
            select(func.count())
            .select_from(model)
            .where(model.org_id == self.org_id)
            .where(model.created_at >= since)
        )
        for column, value in filters.items():
            query = query.where(getattr(model, column) == value)
        result = await self.session.execute(query)
        return int(result.scalar_one())

    async def check_submission(self) -> Usage:
        """Called before a submission is created, not after.

        Refusing after the upload has been stored and parsed would charge us for
        the work and still tell the client no.
        """
        usage = await self.usage()
        limit = usage.limits.submissions_per_month
        if limit is not None and usage.submissions >= limit:
            reset = next_month_start()
            raise QuotaExceeded(
                quota=Quota.SUBMISSIONS,
                limit=limit,
                used=usage.submissions,
                plan=usage.plan,
                resets_at=reset,
                retry_after=max(1, int((reset - datetime.now(UTC)).total_seconds())),
                remedy=(
                    "The allowance resets at the start of next month. Assessments "
                    "already submitted remain available, and a plan change takes "
                    "effect immediately."
                ),
            )
        return usage

    async def check_repo_generation(self) -> Usage:
        usage = await self.usage()
        limit = usage.limits.repo_generations_per_month
        if limit is not None and usage.repo_generations >= limit:
            reset = next_month_start()
            raise QuotaExceeded(
                quota=Quota.REPO_GENERATIONS,
                limit=limit,
                used=usage.repo_generations,
                plan=usage.plan,
                resets_at=reset,
                retry_after=max(1, int((reset - datetime.now(UTC)).total_seconds())),
                remedy=(
                    "Generation resolves a repository's dependencies in a sandbox and "
                    "is metered separately from submissions. Uploading a BOM your own "
                    "build produced does not consume this allowance."
                ),
            )
        return usage

    async def check_components(self, count: int) -> Usage:
        """Checked against the parsed entry count before scoring runs.

        The limit is refused rather than truncated. Silently scoring the first
        5,000 components of a 40,000-component estate would produce a conformance
        figure that looks complete and describes an eighth of the software — the
        partial-coverage failure §11 forbids, arriving through the billing system.
        """
        usage = await self.usage()
        limit = usage.limits.components_per_submission
        if limit is not None and count > limit:
            raise QuotaExceeded(
                quota=Quota.COMPONENTS,
                limit=limit,
                used=count,
                plan=usage.plan,
                resets_at=None,
                # No point telling them to wait: nothing about this resets.
                retry_after=0,
                remedy=(
                    f"This document declares {count:,} components against a limit of "
                    f"{limit:,}. It is refused rather than truncated: a score over part "
                    "of an estate would read as a score over all of it. Split the "
                    "submission or change plan."
                ),
            )
        return usage


class RateLimiter:
    """A per-org sliding window. **In-process, and that is a stated limitation.**

    Two API instances therefore allow twice the configured rate. The honest fix is
    Redis, which this deployment already runs for arq; it is not used here because
    a rate limiter that fails closed when Redis blips would turn a cache outage
    into an outage, and one that fails open is the same as this with more moving
    parts. The limit exists to stop a runaway client script, and for that purpose
    per-process is enough.
    """

    def __init__(self) -> None:
        self._hits: dict[str, deque[float]] = {}

    def check(self, key: str, *, limit: int | None, plan: str, window: float = 60.0) -> None:
        if limit is None:
            return
        now = time.monotonic()
        hits = self._hits.setdefault(key, deque())
        while hits and now - hits[0] > window:
            hits.popleft()

        if len(hits) >= limit:
            retry_after = max(1, int(window - (now - hits[0])) + 1)
            raise QuotaExceeded(
                quota=Quota.REQUESTS,
                limit=limit,
                used=len(hits),
                plan=plan,
                resets_at=None,
                retry_after=retry_after,
                remedy=(
                    f"More than {limit} requests in {int(window)} seconds. Retry after "
                    f"{retry_after}s; if this is a batch job, submit sequentially rather "
                    "than in parallel."
                ),
            )
        hits.append(now)

    def reset(self) -> None:
        """For tests. A shared limiter across tests would make them order-dependent."""
        self._hits.clear()


#: One limiter per process, deliberately module-level: a per-request instance
#: would forget every hit and enforce nothing.
limiter = RateLimiter()
