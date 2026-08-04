"""Repository guards: terminal finality and tenancy.

Run against SQLite via aiosqlite. These are logic tests — a conditional UPDATE's
`rowcount` and a `WHERE org_id` clause behave identically on both dialects — and
running them without a live database is what keeps them running at all.

What SQLite does *not* cover is stated plainly at the bottom of this file.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta

import pytest
from sqlalchemy import select
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

from app.configs.jobTypes import JobStatus, JobType

# Import from the package, never individual modules: app/models/__init__.py is
# what guarantees Base.metadata is complete (see tests/test_models.py).
from app.models import Base, Client, Engagement, Job, Org, Role, User
from app.repositories.jobRepository import JobRepository, TerminalJobWriteRejected


@pytest.fixture
async def session():
    engine = create_async_engine("sqlite+aiosqlite:///:memory:")
    async with engine.begin() as connection:
        await connection.run_sync(Base.metadata.create_all)
    factory = async_sessionmaker(engine, expire_on_commit=False)
    async with factory() as session:
        yield session
    await engine.dispose()


@pytest.fixture
async def orgs(session):
    """Two tenants. Every tenancy test needs a second org to be meaningful."""
    a = Org(id=uuid.uuid4(), name="Firm A")
    b = Org(id=uuid.uuid4(), name="Firm B")
    session.add_all([a, b])
    await session.flush()
    return a, b


# --- terminal finality ------------------------------------------------------


async def test_a_late_write_to_a_completed_job_is_rejected(session, orgs):
    """The §S2 exit proof: a late write-back is rejected and logged."""
    org, _ = orgs
    repo = JobRepository(session, org.id)
    job = await repo.create(job_type=JobType.ASSESS_SUBMISSION)

    await repo.mark_running(job.id)
    await repo.mark_terminal(job.id, JobStatus.SUCCEEDED)

    with pytest.raises(TerminalJobWriteRejected, match="terminal job is immutable"):
        await repo.mark_terminal(job.id, JobStatus.FAILED, error="late worker write-back")

    settled = await repo.get(job.id)
    assert settled.status is JobStatus.SUCCEEDED
    assert settled.error is None


async def test_a_blocked_job_cannot_be_flipped_to_succeeded(session, orgs):
    """The case that matters most: the gate refused to issue this assessment."""
    org, _ = orgs
    repo = JobRepository(session, org.id)
    job = await repo.create(job_type=JobType.ASSESS_SUBMISSION)
    await repo.mark_terminal(
        job.id, JobStatus.BLOCKED_CONFORMANCE, error="clause 4.2(99) does not resolve"
    )

    with pytest.raises(TerminalJobWriteRejected):
        await repo.mark_terminal(job.id, JobStatus.SUCCEEDED)

    assert (await repo.get(job.id)).status is JobStatus.BLOCKED_CONFORMANCE


async def test_running_is_not_terminal_and_stays_writable(session, orgs):
    org, _ = orgs
    repo = JobRepository(session, org.id)
    job = await repo.create(job_type=JobType.ASSESS_SUBMISSION)

    running = await repo.mark_running(job.id)
    assert running.terminal_at is None
    assert running.is_terminal is False

    finished = await repo.mark_terminal(job.id, JobStatus.SUCCEEDED)
    assert finished.terminal_at is not None
    assert finished.is_terminal is True


async def test_terminal_at_is_set_in_the_same_statement_as_the_status(session, orgs):
    """A row can never be terminal-without-a-timestamp, or the guard has a hole."""
    org, _ = orgs
    repo = JobRepository(session, org.id)
    job = await repo.create(job_type=JobType.ASSESS_SUBMISSION)
    finished = await repo.mark_terminal(job.id, JobStatus.FAILED, error="lane crashed")

    assert finished.status is JobStatus.FAILED
    assert finished.terminal_at is not None
    assert finished.error == "lane crashed"


async def test_marking_a_non_terminal_status_as_terminal_is_refused(session, orgs):
    org, _ = orgs
    repo = JobRepository(session, org.id)
    job = await repo.create(job_type=JobType.ASSESS_SUBMISSION)

    with pytest.raises(ValueError, match="is not terminal"):
        await repo.mark_terminal(job.id, JobStatus.RUNNING)


# --- tenancy ----------------------------------------------------------------


async def test_org_b_cannot_read_org_a_s_job(session, orgs):
    a, b = orgs
    job = await JobRepository(session, a.id).create(job_type=JobType.ASSESS_SUBMISSION)

    # Not an error, not a 403 — simply nothing, so existence does not leak.
    assert await JobRepository(session, b.id).get(job.id) is None


async def test_org_b_cannot_list_org_a_s_jobs(session, orgs):
    a, b = orgs
    await JobRepository(session, a.id).create(job_type=JobType.ASSESS_SUBMISSION)

    assert await JobRepository(session, b.id).list() == []
    assert await JobRepository(session, b.id).count() == 0
    assert len(await JobRepository(session, a.id).list()) == 1


async def test_org_b_cannot_write_to_org_a_s_job(session, orgs):
    a, b = orgs
    job = await JobRepository(session, a.id).create(job_type=JobType.ASSESS_SUBMISSION)

    with pytest.raises(TerminalJobWriteRejected, match="does not exist within org"):
        await JobRepository(session, b.id).mark_terminal(job.id, JobStatus.SUCCEEDED)

    assert (await JobRepository(session, a.id).get(job.id)).status is JobStatus.QUEUED


async def test_org_b_cannot_find_org_a_s_job_by_idempotency_key(session, orgs):
    """The key is globally unique, so this is the one path that could cross."""
    a, b = orgs
    await JobRepository(session, a.id).create(
        job_type=JobType.ASSESS_SUBMISSION, idempotency_key="shared-key"
    )

    assert await JobRepository(session, a.id).find_by_idempotency_key("shared-key") is not None
    assert await JobRepository(session, b.id).find_by_idempotency_key("shared-key") is None


async def test_writing_a_row_for_another_org_through_a_scoped_repo_is_refused(session, orgs):
    a, b = orgs
    foreign = Job(org_id=b.id, job_type=JobType.ASSESS_SUBMISSION, status=JobStatus.QUEUED)

    with pytest.raises(ValueError, match="refusing to write"):
        await JobRepository(session, a.id).add(foreign)


# --- crash recovery ---------------------------------------------------------


async def test_a_job_survives_a_crash_and_is_reconcilable(session, orgs):
    """`kill -9` mid-fan-out: the row was written before the work began, so the
    job is visible and actionable rather than vanished."""
    org, _ = orgs
    repo = JobRepository(session, org.id)
    job = await repo.create(job_type=JobType.ASSESS_SUBMISSION)
    await repo.mark_running(job.id)
    # ... process dies here. Nothing else writes.

    # A fresh repository — as a restarted worker would construct.
    restarted = JobRepository(session, org.id)
    survivor = await restarted.get(job.id)
    assert survivor is not None
    assert survivor.status is JobStatus.RUNNING
    assert survivor.terminal_at is None

    stale = await restarted.find_stale(older_than=datetime.now(UTC) + timedelta(seconds=1))
    assert [item.id for item in stale] == [job.id]

    reconciled = await restarted.reconcile_stale(
        older_than=datetime.now(UTC) + timedelta(seconds=1), reason="worker lost"
    )
    assert reconciled == [job.id]
    assert (await restarted.get(job.id)).status is JobStatus.FAILED


async def test_reconciliation_never_touches_a_finished_job(session, orgs):
    org, _ = orgs
    repo = JobRepository(session, org.id)
    done = await repo.create(job_type=JobType.ASSESS_SUBMISSION)
    await repo.mark_terminal(done.id, JobStatus.SUCCEEDED)

    reconciled = await repo.reconcile_stale(
        older_than=datetime.now(UTC) + timedelta(seconds=1), reason="sweep"
    )
    assert reconciled == []
    assert (await repo.get(done.id)).status is JobStatus.SUCCEEDED


async def test_reconciliation_is_scoped_to_one_org(session, orgs):
    a, b = orgs
    other = await JobRepository(session, b.id).create(job_type=JobType.ASSESS_SUBMISSION)

    reconciled = await JobRepository(session, a.id).reconcile_stale(
        older_than=datetime.now(UTC) + timedelta(seconds=1), reason="sweep"
    )
    assert reconciled == []
    assert (await JobRepository(session, b.id).get(other.id)).status is JobStatus.QUEUED


async def test_node_runs_persist_the_evidence_of_parallelism(session, orgs):
    """Overlapping lane intervals are the audit trail; they must outlive the process."""
    org, _ = orgs
    repo = JobRepository(session, org.id)
    job = await repo.create(job_type=JobType.ASSESS_SUBMISSION)
    start = datetime.now(UTC)

    written = await repo.record_node_runs(
        job.id,
        [
            {
                "lane": "sbom",
                "node": "sbomLane",
                "status": "succeeded",
                "started_at": start,
                "finished_at": start + timedelta(milliseconds=146),
                "latency_ms": 146.0,
            },
            {
                "lane": "aibom",
                "node": "aibomLane",
                "status": "succeeded",
                "started_at": start + timedelta(milliseconds=1),
                "finished_at": start + timedelta(milliseconds=8),
                "latency_ms": 7.0,
            },
        ],
    )
    assert written == 2

    from app.models.job import NodeRun

    rows = (await session.execute(select(NodeRun).where(NodeRun.job_id == job.id))).scalars().all()
    assert {row.lane for row in rows} == {"sbom", "aibom"}


async def test_node_runs_are_writable_after_the_job_is_terminal(session, orgs):
    """The guard covers `status`, not history — runs are written as a job finishes."""
    org, _ = orgs
    repo = JobRepository(session, org.id)
    job = await repo.create(job_type=JobType.ASSESS_SUBMISSION)
    await repo.mark_terminal(job.id, JobStatus.SUCCEEDED)

    assert await repo.record_node_runs(job.id, [{"node": "join", "status": "succeeded"}]) == 1


# --- schema shape -----------------------------------------------------------


async def test_the_foundation_tables_exist_with_their_tenancy_column(session, orgs):
    a, _ = orgs
    client = Client(org_id=a.id, name="Ministry of X")
    session.add(client)
    await session.flush()

    session.add(
        Engagement(
            org_id=a.id,
            client_id=client.id,
            title="FY26 procurement review",
            enabled_lanes=["sbom", "aibom"],
        )
    )
    session.add(User(org_id=a.id, email="assessor@firm-a.example", role=Role.ASSESSOR))
    await session.flush()

    stored = (await session.execute(select(Engagement))).scalar_one()
    assert stored.enabled_lanes == ["sbom", "aibom"]
    assert stored.org_id == a.id


async def test_email_is_unique_per_org_not_globally(session, orgs):
    """The same person may hold an account at two firms using this platform."""
    a, b = orgs
    session.add(User(org_id=a.id, email="shared@example.com", role=Role.ASSESSOR))
    session.add(User(org_id=b.id, email="shared@example.com", role=Role.MANAGER))
    await session.flush()

    assert len((await session.execute(select(User))).scalars().all()) == 2


# --- what SQLite does not cover ---------------------------------------------
#
# Deliberately not asserted here, because the dialect cannot express it:
#
#   * `ix_jobs_live` as a genuine PARTIAL index — SQLite supports partial indexes
#     but the migration builds it with `postgresql_where`, so only Postgres gets
#     the real one. Verify with `\d jobs` after `alembic upgrade head`.
#   * `enabled_lanes` as a real `text[]` — here it is a JSON list via the variant
#     in `models/base.py`.
#   * `instructions` as `JSONB` rather than `JSON`.
#   * Native enum types, and therefore the `DROP TYPE` calls in `downgrade()`.
#   * Concurrent writers actually racing the finality guard. The conditional
#     UPDATE is what makes that safe, and it is the same statement on both
#     dialects, but only Postgres proves it under real concurrency.
#
# `alembic upgrade head`, `downgrade -1` and the round-trip need a live Postgres
# and are this sprint's deferred exit proofs.


# --- the full loop: a real assessment lands in the job table -----------------


async def test_an_assessment_run_persists_its_job_and_its_parallelism_evidence(session, orgs):
    """End to end: run the graph, persist it, and the overlapping lane intervals
    survive the process that produced them."""
    from app.models.job import NodeRun
    from app.services.assessmentService import run_assessment
    from app.services.graph.state import SubmissionDocument
    from app.services.jobService import persist_summary
    from tests.conftest import component, cyclonedx_document, model_component

    org, _ = orgs
    repo = JobRepository(session, org.id)
    job = await repo.create(job_type=JobType.ASSESS_SUBMISSION)
    await repo.mark_running(job.id)

    summary = await run_assessment(
        org_id=str(org.id),
        submission_id=str(uuid.uuid4()),
        documents=[
            SubmissionDocument(
                lane="sbom",
                format="CycloneDX",
                payload=cyclonedx_document([component(f"lib-{i}") for i in range(200)]),
            ),
            SubmissionDocument(
                lane="aibom",
                format="CycloneDX",
                payload=cyclonedx_document([model_component()]),
            ),
        ],
    )
    await persist_summary(repo, job.id, summary)

    settled = await repo.get(job.id)
    assert settled.status is JobStatus.SUCCEEDED
    assert settled.is_terminal

    rows = (await session.execute(select(NodeRun).where(NodeRun.job_id == job.id))).scalars().all()
    lanes = {row.lane for row in rows if row.lane}
    assert lanes == {"sbom", "cbom", "qbom", "aibom", "hbom"}, "every lane must be recorded"

    # The evidence of parallelism, read back from the database rather than memory.
    sbom = next(row for row in rows if row.lane == "sbom")
    aibom = next(row for row in rows if row.lane == "aibom")
    assert sbom.started_at < aibom.finished_at and aibom.started_at < sbom.finished_at, (
        "persisted lane intervals do not overlap; the fan-out evidence was lost"
    )


async def test_a_blocked_assessment_persists_as_blocked_not_failed(session, orgs):
    """`blocked_conformance` is a refusal to issue, not a crash. Retrying it would
    correctly refuse again, so it must not read as a transient failure."""
    from app.services.assessmentService import AssessmentSummary
    from app.services.jobService import persist_summary

    org, _ = orgs
    repo = JobRepository(session, org.id)
    job = await repo.create(job_type=JobType.ASSESS_SUBMISSION)

    blocked = AssessmentSummary(
        job_id=str(job.id),
        submission_id=str(uuid.uuid4()),
        status=JobStatus.BLOCKED_CONFORMANCE,
        overall_score=None,
        lane_results=[],
        node_runs=[],
        errors=[],
        gate_reason="clause 4.2(99) does not resolve in guideline version 2.0",
    )
    await persist_summary(repo, job.id, blocked)

    settled = await repo.get(job.id)
    assert settled.status is JobStatus.BLOCKED_CONFORMANCE
    assert "4.2(99)" in settled.error
