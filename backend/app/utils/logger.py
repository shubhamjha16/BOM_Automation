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


def configure_logging(*, json_output: bool | None = None, level: int = logging.INFO) -> None:
    global _configured
    if _configured:
        return

    if json_output is None:
        json_output = not sys.stderr.isatty()

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
        logger_factory=structlog.PrintLoggerFactory(file=sys.stderr),
        cache_logger_on_first_use=True,
    )
    _configured = True


def get_logger(name: str | None = None) -> Any:
    configure_logging()
    return structlog.get_logger(name)
