"""arq against a real Redis. Skipped when none is reachable.

Everything else about the queue is tested without Redis in `test_queue.py` —
the task functions are plain callables. What only a real broker can show is that
arq accepts the job, that `_job_id` makes a duplicate enqueue a no-op, and that a
worker picks the job up and runs it to a terminal state.

Point `TEST_REDIS_URL` at any Redis to run these; the suite skips otherwise
rather than failing, because a missing broker is an environment fact, not a
defect in the code under test.
"""

from __future__ import annotations

import asyncio
import os
import uuid

import pytest
from arq import create_pool
from arq.connections import RedisSettings
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

from app.models import Base, Client, Engagement, Org
from app.models.enums import BomFormat
from app.repositories.jobRepository import JobRepository
from app.repositories.submissionRepository import SubmissionRepository
from tests.conftest import component, cyclonedx_document

REDIS_URL = os.environ.get("TEST_REDIS_URL", "redis://localhost:6399/0")


async def _redis_available() -> bool:
    try:
        pool = await asyncio.wait_for(
            create_pool(RedisSettings.from_dsn(REDIS_URL)), timeout=3
        )
    except Exception:
        return False
    await pool.aclose()
    return True


@pytest.fixture
async def pool():
    if not await _redis_available():
        pytest.skip(f"no Redis at {REDIS_URL}")
    connection = await create_pool(RedisSettings.from_dsn(REDIS_URL))
    await connection.flushdb()
    yield connection
    await connection.flushdb()
    await connection.aclose()


@pytest.fixture
async def db():
    engine = create_async_engine("sqlite+aiosqlite:///:memory:")
    async with engine.begin() as connection:
        await connection.run_sync(Base.metadata.create_all)
    yield async_sessionmaker(engine, expire_on_commit=False)
    await engine.dispose()


async def _seed(db):
    async with db() as session:
        org = Org(id=uuid.uuid4(), name="Firm A")
        session.add(org)
        await session.flush()
        client = Client(org_id=org.id, name="Ministry of X")
        session.add(client)
        await session.flush()
        engagement = Engagement(
            org_id=org.id, client_id=client.id, title="FY26", enabled_lanes=["sbom"]
        )
        session.add(engagement)
        await session.flush()

        submissions = SubmissionRepository(session, org.id)
        submission = await submissions.create(engagement_id=engagement.id)
        await submissions.add_document(
            submission,
            lane="sbom",
            format=BomFormat.CYCLONEDX,
            checksum=uuid.uuid4().hex,
            size_bytes=100,
            payload=cyclonedx_document([component("tomcat-catalina", "9.0.71")]),
        )
        job = await JobRepository(session, org.id).create(
            job_type="assess_submission",
            engagement_id=engagement.id,
            submission_id=submission.id,
        )
        await session.commit()
        return org.id, submission.id, job.id


async def test_arq_accepts_the_job(pool, db):
    org_id, submission_id, job_id = await _seed(db)

    enqueued = await pool.enqueue_job(
        "run_assessment_task",
        str(org_id),
        str(submission_id),
        str(job_id),
        _job_id=str(job_id),
    )
    assert enqueued is not None
    assert enqueued.job_id == str(job_id)


async def test_a_duplicate_enqueue_of_the_same_job_id_is_refused(pool, db):
    """Belt and braces over the database idempotency key: even if the same job is
    handed to the queue twice, arq itself will not schedule it twice."""
    org_id, submission_id, job_id = await _seed(db)

    first = await pool.enqueue_job(
        "run_assessment_task", str(org_id), str(submission_id), str(job_id), _job_id=str(job_id)
    )
    second = await pool.enqueue_job(
        "run_assessment_task", str(org_id), str(submission_id), str(job_id), _job_id=str(job_id)
    )

    assert first is not None
    assert second is None, "arq scheduled the same job id twice"


async def test_a_worker_runs_the_queued_job_to_a_terminal_state(pool, db):
    """End to end through a real broker: enqueue, run one worker burst, assert
    the job settled in Postgres — not merely that Redis accepted it."""
    from arq.worker import Worker

    from app.workers.tasks import run_assessment_task

    org_id, submission_id, job_id = await _seed(db)
    await pool.enqueue_job(
        "run_assessment_task", str(org_id), str(submission_id), str(job_id), _job_id=str(job_id)
    )

    worker = Worker(
        functions=[run_assessment_task],
        redis_settings=RedisSettings.from_dsn(REDIS_URL),
        burst=True,
        poll_delay=0.1,
        ctx={"session_factory": db},
    )
    try:
        await asyncio.wait_for(worker.async_run(), timeout=60)
    finally:
        await worker.close()

    async with db() as session:
        settled = await JobRepository(session, org_id).get(job_id)
        assert settled is not None
        assert settled.is_terminal, f"job did not settle: {settled.status}"
        assert str(settled.status) == "succeeded"
