"""Job persistence, and the terminal-finality guard.

**The guard is a conditional UPDATE, not a read-then-write.** Checking
`job.terminal_at is None` in Python and then writing is a race: a lane finishing
at the same moment as a timeout handler produces two writers who both read
`None`, and the loser overwrites a terminal verdict. `WHERE terminal_at IS NULL`
in the statement itself makes the database the arbiter, and `rowcount` tells us
which writer lost.

This matters beyond tidiness. A late write-back that flips a completed
`blocked_conformance` job to `succeeded` would let an assessment the gate refused
to issue become issuable.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime
from typing import cast

from sqlalchemy import CursorResult, Select, update

from app.configs.jobTypes import TERMINAL_STATUSES, JobStatus, JobType
from app.models.job import Job, NodeRun
from app.repositories.base import TenantScopedRepository
from app.utils.logger import get_logger

logger = get_logger(__name__)


class TerminalJobWriteRejected(RuntimeError):
    """A write to a job that has already reached a terminal status."""


class JobRepository(TenantScopedRepository[Job]):
    model = Job

    async def create(
        self,
        *,
        job_type: JobType,
        user_id: uuid.UUID | None = None,
        engagement_id: uuid.UUID | None = None,
        submission_id: uuid.UUID | None = None,
        instructions: dict | None = None,
        idempotency_key: str | None = None,
    ) -> Job:
        """Insert a queued job.

        The row exists before any work starts. That is the whole point: a worker
        killed mid-fan-out leaves a visible, queryable, reconcilable row rather
        than a vanished job.
        """
        job = Job(
            org_id=self.org_id,
            user_id=user_id,
            engagement_id=engagement_id,
            submission_id=submission_id,
            job_type=job_type,
            status=JobStatus.QUEUED,
            instructions=instructions,
            idempotency_key=idempotency_key,
        )
        return await self.add(job)

    async def find_by_idempotency_key(self, key: str) -> Job | None:
        """The same document set submitted twice returns one job (S4)."""
        result = await self.session.execute(
            self.scoped().where(Job.idempotency_key == key)
        )
        return result.scalar_one_or_none()

    async def mark_running(self, job_id: uuid.UUID) -> Job:
        return await self._transition(job_id, JobStatus.RUNNING)

    async def mark_terminal(
        self, job_id: uuid.UUID, status: JobStatus, *, error: str | None = None
    ) -> Job:
        """Move a job to a terminal status, setting `terminal_at` in the same
        statement so the row can never be terminal-without-a-timestamp."""
        if status not in TERMINAL_STATUSES:
            raise ValueError(
                f"{status} is not terminal; terminal statuses are "
                f"{sorted(str(item) for item in TERMINAL_STATUSES)}"
            )
        return await self._transition(job_id, status, error=error, terminal=True)

    async def _transition(
        self,
        job_id: uuid.UUID,
        status: JobStatus,
        *,
        error: str | None = None,
        terminal: bool = False,
    ) -> Job:
        values: dict = {"status": status}
        if error is not None:
            values["error"] = error
        if terminal:
            values["terminal_at"] = datetime.now(UTC)

        statement = (
            update(Job)
            .where(Job.id == job_id)
            .where(Job.org_id == self.org_id)
            # The guard. Tenancy and finality in one atomic predicate.
            .where(Job.terminal_at.is_(None))
            .values(**values)
        )
        # rowcount IS the guard: a DML statement returns a CursorResult, and zero
        # matched rows means the WHERE terminal_at IS NULL predicate rejected it.
        result = cast(CursorResult, await self.session.execute(statement))

        if result.rowcount == 0:
            # Distinguish "already finished" from "does not exist / not yours"
            # only in the log. The caller gets one exception either way.
            existing = await self.get(job_id)
            if existing is None:
                raise TerminalJobWriteRejected(
                    f"job {job_id} does not exist within org {self.org_id}"
                )
            logger.warning(
                "terminal_job_write_rejected",
                job_id=str(job_id),
                org_id=str(self.org_id),
                current_status=str(existing.status),
                attempted_status=str(status),
                terminal_at=existing.terminal_at.isoformat() if existing.terminal_at else None,
            )
            raise TerminalJobWriteRejected(
                f"job {job_id} reached {existing.status} at {existing.terminal_at}; "
                f"refusing to write {status}. A terminal job is immutable."
            )

        await self.session.flush()
        refreshed = await self.get(job_id)
        assert refreshed is not None  # noqa: S101 - the UPDATE above just matched it
        await self.session.refresh(refreshed)
        return refreshed

    # --- crash recovery ----------------------------------------------------

    def live(self) -> Select[tuple[Job]]:
        """Jobs that have not finished. Backed by the `ix_jobs_live` partial index."""
        return self.scoped().where(Job.terminal_at.is_(None))

    async def find_stale(self, *, older_than: datetime) -> list[Job]:
        """Non-terminal jobs older than a cutoff — the reconciler's input.

        After a `kill -9` mid-fan-out these are the jobs left in `running` with
        no process behind them. They are visible and actionable precisely because
        the row was written before the work began.
        """
        result = await self.session.execute(
            self.live().where(Job.created_at < older_than).order_by(Job.created_at)
        )
        return list(result.scalars().all())

    async def reconcile_stale(self, *, older_than: datetime, reason: str) -> list[uuid.UUID]:
        """Fail orphaned jobs, so nothing sits in `running` forever.

        Deliberately marks them `failed` rather than requeueing: whether re-running
        is safe depends on what the job had already written, and a reconciler that
        silently retries an assessment could issue a second one.
        """
        stale = await self.find_stale(older_than=older_than)
        reconciled = []
        for job in stale:
            try:
                await self.mark_terminal(job.id, JobStatus.FAILED, error=reason)
                reconciled.append(job.id)
            except TerminalJobWriteRejected:
                # Finished between the scan and the write; the guard did its job.
                continue
        if reconciled:
            logger.info("jobs_reconciled", count=len(reconciled), reason=reason)
        return reconciled

    # --- node runs ---------------------------------------------------------

    async def record_node_runs(self, job_id: uuid.UUID, runs: list[dict]) -> int:
        """Persist the graph's node runs.

        Written for a terminal job too: the run log is the audit trail and the
        evidence of parallelism, and it is normally written *as* the job
        finishes. The finality guard covers `status`, not history.
        """
        for run in runs:
            self.session.add(NodeRun(job_id=job_id, **run))
        await self.session.flush()
        return len(runs)
