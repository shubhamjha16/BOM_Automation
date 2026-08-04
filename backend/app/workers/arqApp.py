"""arq worker settings. `arq app.workers.arqApp.WorkerSettings`.

No `threading.Thread`, no `jobs.json`. The worker is a separate process from the
API, sharing only Postgres and Redis, so an assessment cannot take a web replica
down with it and either can be scaled independently.
"""

from __future__ import annotations

from typing import Any

from arq.connections import RedisSettings

from app.configs.dbConfig import get_sessionmaker
from app.configs.envConfig import settings
from app.utils.logger import configure_logging, get_logger
from app.workers.tasks import reconcile_stale_jobs, run_assessment_task

logger = get_logger(__name__)


async def startup(ctx: dict[str, Any]) -> None:
    configure_logging()
    # One session factory per worker process, put on the context so tasks do not
    # each build an engine and exhaust the connection pool.
    ctx["session_factory"] = get_sessionmaker()
    logger.info("worker_started", redis=settings.REDIS_URL.split("@")[-1])


async def shutdown(ctx: dict[str, Any]) -> None:
    from app.configs.dbConfig import get_engine

    await get_engine().dispose()
    logger.info("worker_stopped")


class WorkerSettings:
    functions = [run_assessment_task, reconcile_stale_jobs]
    on_startup = startup
    on_shutdown = shutdown

    redis_settings = RedisSettings.from_dsn(settings.REDIS_URL)

    #: Submissions run concurrently; the fan-out inside one is the graph's job.
    max_jobs = 10

    #: An assessment must outlive its slowest lane, or the queue would kill a job
    #: that the lane timeout was about to handle gracefully. Generous headroom
    #: over LANE_TIMEOUT_SECONDS, not equal to it.
    job_timeout = settings.LANE_TIMEOUT_SECONDS * 5

    #: Terminal-finality makes redelivery safe: a task that finds its job already
    #: terminal returns rather than re-running it.
    max_tries = 3
    retry_jobs = True

    #: Keep results long enough for a caller to poll; the durable record is the
    #: jobs table, not Redis.
    keep_result = 3600
