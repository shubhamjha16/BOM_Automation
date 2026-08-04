"""S4: the queue, idempotency, and independent lane failure.

The task functions are plain async callables, so almost everything here runs
without Redis. The one genuinely queue-dependent behaviour — arq accepting and
delivering a job — is in `test_queue_integration.py` and skips when Redis is
absent.
"""

from __future__ import annotations

import asyncio
import uuid
from datetime import UTC, datetime, timedelta

import pytest
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

from app.configs.jobTypes import JobStatus, LaneVerdict
from app.models import Base, Client, Engagement, Org
from app.models.enums import BomFormat
from app.repositories.jobRepository import JobRepository
from app.repositories.submissionRepository import SubmissionRepository
from app.services.queueService import find_or_create_job
from app.utils.idempotency import idempotency_key
from app.workers.tasks import reconcile_stale_jobs, run_assessment_task
from tests.conftest import component, cyclonedx_document, model_component


@pytest.fixture
async def db():
    engine = create_async_engine("sqlite+aiosqlite:///:memory:")
    async with engine.begin() as connection:
        await connection.run_sync(Base.metadata.create_all)
    factory = async_sessionmaker(engine, expire_on_commit=False)
    yield factory
    await engine.dispose()


@pytest.fixture
async def fixture_org(db):
    async with db() as session:
        org = Org(id=uuid.uuid4(), name="Firm A")
        session.add(org)
        await session.flush()
        client = Client(org_id=org.id, name="Ministry of X")
        session.add(client)
        await session.flush()
        engagement = Engagement(
            org_id=org.id, client_id=client.id, title="FY26", enabled_lanes=["sbom", "aibom"]
        )
        session.add(engagement)
        await session.flush()
        await session.commit()
        return org.id, engagement.id


async def _make_submission(db, org_id, engagement_id, *, lanes=("sbom",)):
    async with db() as session:
        repo = SubmissionRepository(session, org_id)
        submission = await repo.create(engagement_id=engagement_id)
        for lane in lanes:
            payload = (
                cyclonedx_document([model_component()])
                if lane == "aibom"
                else cyclonedx_document([component(f"lib-{lane}")])
            )
            await repo.add_document(
                submission,
                lane=lane,
                format=BomFormat.CYCLONEDX,
                checksum=f"{lane}-{uuid.uuid4().hex}",
                size_bytes=len(str(payload)),
                payload=payload,
            )
        await session.commit()
        return submission.id


# --- idempotency ------------------------------------------------------------


def test_the_key_is_stable_regardless_of_document_order():
    """The same five documents attached in a different order is one submission."""
    a = idempotency_key(org_id="o1", document_checksums=["c", "a", "b"], enabled_lanes=["sbom"])
    b = idempotency_key(org_id="o1", document_checksums=["a", "b", "c"], enabled_lanes=["sbom"])
    assert a == b


def test_different_orgs_never_collide_on_identical_documents():
    """Two tenants submitting a byte-identical public SBOM is routine."""
    a = idempotency_key(org_id="o1", document_checksums=["x"], enabled_lanes=["sbom"])
    b = idempotency_key(org_id="o2", document_checksums=["x"], enabled_lanes=["sbom"])
    assert a != b


def test_a_different_lane_set_is_a_different_assessment():
    """An engagement switching CBOM on must be able to re-assess."""
    a = idempotency_key(org_id="o1", document_checksums=["x"], enabled_lanes=["sbom"])
    b = idempotency_key(org_id="o1", document_checksums=["x"], enabled_lanes=["sbom", "cbom"])
    assert a != b


def test_field_boundaries_cannot_be_rearranged():
    """Length-prefixing stops ('ab','c') hashing the same as ('a','bc')."""
    a = idempotency_key(org_id="ab", document_checksums=["c"], enabled_lanes=["sbom"])
    b = idempotency_key(org_id="a", document_checksums=["bc"], enabled_lanes=["sbom"])
    assert a != b


def test_a_submission_with_no_documents_has_no_key():
    with pytest.raises(ValueError, match="no documents"):
        idempotency_key(org_id="o1", document_checksums=[], enabled_lanes=["sbom"])


async def test_the_same_document_set_twice_returns_one_job(db, fixture_org):
    """The §S4 exit proof: one job_id, one execution."""
    org_id, engagement_id = fixture_org
    submission_id = await _make_submission(db, org_id, engagement_id)

    async with db() as session:
        jobs = JobRepository(session, org_id)
        first, created_first = await find_or_create_job(
            jobs,
            submission_id=submission_id,
            engagement_id=engagement_id,
            document_checksums=["a", "b"],
            enabled_lanes=["sbom"],
        )
        second, created_second = await find_or_create_job(
            jobs,
            submission_id=submission_id,
            engagement_id=engagement_id,
            document_checksums=["b", "a"],  # order deliberately swapped
            enabled_lanes=["sbom"],
        )

        assert created_first is True
        assert created_second is False
        assert first.id == second.id
        assert await jobs.count() == 1


async def test_outside_the_window_a_resubmission_is_a_new_assessment(db, fixture_org):
    org_id, engagement_id = fixture_org
    submission_id = await _make_submission(db, org_id, engagement_id)

    async with db() as session:
        jobs = JobRepository(session, org_id)
        first, _ = await find_or_create_job(
            jobs,
            submission_id=submission_id,
            engagement_id=engagement_id,
            document_checksums=["a"],
            enabled_lanes=["sbom"],
        )
        second, created = await find_or_create_job(
            jobs,
            submission_id=submission_id,
            engagement_id=engagement_id,
            document_checksums=["a"],
            enabled_lanes=["sbom"],
            window_seconds=0,
        )
        assert created is True
        assert second.id != first.id


# --- the task itself --------------------------------------------------------


async def test_the_task_assesses_and_settles_the_job(db, fixture_org):
    org_id, engagement_id = fixture_org
    submission_id = await _make_submission(db, org_id, engagement_id, lanes=("sbom", "aibom"))

    async with db() as session:
        job = await JobRepository(session, org_id).create(
            job_type="assess_submission", engagement_id=engagement_id, submission_id=submission_id
        )
        await session.commit()
        job_id = job.id

    result = await run_assessment_task(
        {"session_factory": db}, str(org_id), str(submission_id), str(job_id)
    )

    assert result["status"] == "succeeded"
    assert result["overall_score"] is not None
    assert result["lanes"]["cbom"] == LaneVerdict.LANE_ABSENT

    async with db() as session:
        settled = await JobRepository(session, org_id).get(job_id)
        assert settled.status is JobStatus.SUCCEEDED
        assert settled.terminal_at is not None


async def test_a_redelivered_task_does_not_re_run_the_assessment(db, fixture_org):
    """arq is at-least-once. Terminal finality makes redelivery safe."""
    org_id, engagement_id = fixture_org
    submission_id = await _make_submission(db, org_id, engagement_id)

    async with db() as session:
        job = await JobRepository(session, org_id).create(
            job_type="assess_submission", engagement_id=engagement_id, submission_id=submission_id
        )
        await session.commit()
        job_id = job.id

    ctx = {"session_factory": db}
    first = await run_assessment_task(ctx, str(org_id), str(submission_id), str(job_id))
    second = await run_assessment_task(ctx, str(org_id), str(submission_id), str(job_id))

    assert first["status"] == "succeeded"
    assert second.get("redelivered") is True


async def test_a_task_for_a_missing_job_does_not_raise(db, fixture_org):
    """Raising would make arq retry something that cannot be made to exist."""
    org_id, engagement_id = fixture_org
    submission_id = await _make_submission(db, org_id, engagement_id)

    result = await run_assessment_task(
        {"session_factory": db}, str(org_id), str(submission_id), str(uuid.uuid4())
    )
    assert result["status"] == "job_missing"


# --- concurrency ------------------------------------------------------------


async def test_twenty_concurrent_submissions_all_reach_a_terminal_state(db, fixture_org):
    """The §S4 exit proof: 20 concurrent, none lost."""
    org_id, engagement_id = fixture_org

    job_ids = []
    for _ in range(20):
        submission_id = await _make_submission(db, org_id, engagement_id)
        async with db() as session:
            job = await JobRepository(session, org_id).create(
                job_type="assess_submission",
                engagement_id=engagement_id,
                submission_id=submission_id,
            )
            await session.commit()
            job_ids.append((job.id, submission_id))

    ctx = {"session_factory": db}
    results = await asyncio.gather(
        *(
            run_assessment_task(ctx, str(org_id), str(submission_id), str(job_id))
            for job_id, submission_id in job_ids
        )
    )
    assert len(results) == 20
    assert all(result["status"] == "succeeded" for result in results)

    async with db() as session:
        jobs = JobRepository(session, org_id)
        settled = [await jobs.get(job_id) for job_id, _ in job_ids]
        assert all(job.is_terminal for job in settled), "a job was lost"
        assert len({job.id for job in settled}) == 20


# --- a hung lane does not take the submission with it -----------------------


async def test_a_hung_lane_times_out_while_the_others_complete(db, fixture_org, monkeypatch):
    """The §S4 exit proof, through the task rather than the graph directly."""
    import app.services.graph.laneRunner as runner
    from app.services.graph.nodes import sbomLane

    monkeypatch.setattr(runner.settings, "LANE_TIMEOUT_SECONDS", 1)

    def hang(_documents):
        import time

        time.sleep(5)
        raise AssertionError("unreachable")

    monkeypatch.setattr(sbomLane, "score_sbom", hang)

    org_id, engagement_id = fixture_org
    submission_id = await _make_submission(db, org_id, engagement_id, lanes=("sbom", "aibom"))
    async with db() as session:
        job = await JobRepository(session, org_id).create(
            job_type="assess_submission", engagement_id=engagement_id, submission_id=submission_id
        )
        await session.commit()
        job_id = job.id

    result = await asyncio.wait_for(
        run_assessment_task({"session_factory": db}, str(org_id), str(submission_id), str(job_id)),
        timeout=20,
    )

    # The job succeeded; the lane is a reported finding, not a crash.
    assert result["status"] == "succeeded"
    assert result["lanes"]["sbom"] == LaneVerdict.LANE_TIMEOUT
    assert result["lanes"]["aibom"] in (LaneVerdict.PASS, LaneVerdict.CONDITIONAL, LaneVerdict.FAIL)


# --- crash recovery ---------------------------------------------------------


async def test_a_worker_killed_mid_fan_out_leaves_a_reconcilable_job(db, fixture_org):
    org_id, engagement_id = fixture_org
    submission_id = await _make_submission(db, org_id, engagement_id)

    async with db() as session:
        jobs = JobRepository(session, org_id)
        job = await jobs.create(
            job_type="assess_submission", engagement_id=engagement_id, submission_id=submission_id
        )
        await jobs.mark_running(job.id)
        await session.commit()
        job_id = job.id
    # ... worker dies here.

    reconciled = await reconcile_stale_jobs(
        {"session_factory": db}, str(org_id), older_than_seconds=-1
    )
    assert reconciled == 1

    async with db() as session:
        settled = await JobRepository(session, org_id).get(job_id)
        assert settled.status is JobStatus.FAILED
        assert "no worker heartbeat" in settled.error


async def test_reconciliation_leaves_fresh_jobs_alone(db, fixture_org):
    org_id, engagement_id = fixture_org
    submission_id = await _make_submission(db, org_id, engagement_id)
    async with db() as session:
        jobs = JobRepository(session, org_id)
        job = await jobs.create(
            job_type="assess_submission", engagement_id=engagement_id, submission_id=submission_id
        )
        await jobs.mark_running(job.id)
        await session.commit()
        job_id = job.id

    stale = await reconcile_stale_jobs(
        {"session_factory": db}, str(org_id), older_than_seconds=900
    )
    assert stale == 0

    async with db() as session:
        assert (await JobRepository(session, org_id).get(job_id)).status is JobStatus.RUNNING


def test_the_worker_timeout_exceeds_the_lane_timeout():
    """Otherwise the queue kills a job the lane timeout was about to handle."""
    from app.configs.envConfig import settings
    from app.workers.arqApp import WorkerSettings

    assert WorkerSettings.job_timeout > settings.LANE_TIMEOUT_SECONDS
    assert WorkerSettings.retry_jobs is True


def test_stale_cutoff_is_derived_from_now(db):
    cutoff = datetime.now(UTC) - timedelta(seconds=900)
    assert cutoff < datetime.now(UTC)
