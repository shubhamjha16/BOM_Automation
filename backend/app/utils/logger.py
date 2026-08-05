"""structlog setup.

Every log line carries the keys a submission is reconstructed from — ``job_id``,
``submission_id``, ``lane``. S21 adds the redaction processor; until then nothing
in this repo logs BOM payload content, because a BOM is an architecture disclosure.
"""

from __future__ import annotations

import logging
import sys
from typing import Any

import structlog

from app.utils.redaction import redaction_processor

_configured = False


def configure_logging(
    *,
    json_output: bool | None = None,
    level: int = logging.INFO,
    stream: Any | None = None,
    force: bool = False,
) -> None:
    """Configure structlog once.

    ``stream`` and ``force`` exist so a test can capture the *rendered* lines
    rather than the pre-processor event dicts. `structlog.testing.capture_logs`
    intercepts before the processor chain, which would skip redaction and the
    JSON renderer — exactly the two things a log-reconstruction test needs to
    exercise, since the question is whether the deployed pipeline emits enough to
    rebuild a submission and little enough to be safe to keep.
    """
    global _configured
    if _configured and not force:
        return

    if json_output is None:
        json_output = True if stream is not None else not sys.stderr.isatty()

    renderer: Any = (
        structlog.processors.JSONRenderer()
        if json_output
        else structlog.dev.ConsoleRenderer(colors=True)
    )

    structlog.configure(
        processors=[
            structlog.contextvars.merge_contextvars,
            structlog.processors.add_log_level,
            structlog.processors.TimeStamper(fmt="iso", utc=True),
            structlog.processors.StackInfoRenderer(),
            structlog.processors.format_exc_info,
            # Last before rendering, so nothing a later processor adds escapes it.
            # A BOM is an architecture disclosure and logs outlive engagements.
            redaction_processor,
            renderer,
        ],
        wrapper_class=structlog.make_filtering_bound_logger(level),
        logger_factory=structlog.PrintLoggerFactory(file=stream or sys.stderr),
        # **Never cached.** Caching binds the configured logger into every
        # module-level `logger` on its first call, after which reconfiguration is
        # silently ignored — the log level cannot be changed at runtime and the
        # rendered stream cannot be captured. The optimisation is worth having
        # where logging is per-item; here it is per-lane and per-assessment, so
        # the cost is unmeasurable and the lost testability is not.
        cache_logger_on_first_use=False,
    )
    _configured = True


def get_logger(name: str | None = None) -> Any:
    configure_logging()
    return structlog.get_logger(name)
