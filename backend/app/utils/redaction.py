"""Keep BOM content out of log storage.

**A BOM is an architecture disclosure.** Component names are supplier-controlled
text; a dependency list names internal services; a file path names a deployment
layout. Logs are shipped to a third-party aggregator, retained for years, and
read by people with no relationship to the client whose architecture they
describe.

So the log pipeline carries identifiers — `job_id`, `submission_id`, `lane`,
counts, verdicts — and never payload content. This processor is the enforcement:
anything that looks like a host, a path, an email or a secret is replaced before
the line is rendered.

It is deliberately aggressive. A redacted log line that was harmless costs a
debugging session; an unredacted one that was not costs a client's architecture.
"""

from __future__ import annotations

import re
from collections.abc import Mapping, MutableMapping
from typing import Any

REDACTED = "[redacted]"

#: Absolute POSIX and Windows paths.
_PATH = re.compile(r"(?:/[\w.\-]+){2,}/?|[A-Za-z]:\\(?:[\w.\-]+\\?)+")
#: Internal hostnames: anything .local/.internal/.corp/.lan, or host:port.
_INTERNAL_HOST = re.compile(
    r"\b[\w\-]+(?:\.[\w\-]+)*\.(?:local|internal|corp|lan|intranet|svc|cluster)\b"
    r"|\b[\w\-]+(?:\.[\w\-]+)+:\d{2,5}\b",
    re.IGNORECASE,
)
_EMAIL = re.compile(r"\b[\w.+\-]+@[\w\-]+\.[\w.\-]+\b")
_IPV4 = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
#: Bearer tokens, API keys and anything that looks like one.
_SECRET = re.compile(
    r"\b(?:bearer\s+[\w.\-]{16,}|sk-[\w\-]{16,}|gsk_[\w\-]{16,}|[A-Za-z0-9_\-]{40,})\b",
    re.IGNORECASE,
)

#: Keys whose values are never safe to log, whatever they contain.
FORBIDDEN_KEYS = frozenset(
    {
        "payload",
        "document",
        "components",
        "packages",
        "snippet",
        "justification",
        "content",
        "password",
        "hashed_password",
        "token",
        "access_token",
        "refresh_token",
        "authorization",
        "api_key",
        "mfa_secret",
        "jwt_secret",
    }
)

#: Keys that are safe: identifiers, counts and verdicts. Everything the
#: observability requirement in S21 actually needs.
SAFE_KEYS = frozenset(
    {
        "job_id",
        "submission_id",
        "org_id",
        "lane",
        "event",
        "level",
        "timestamp",
        "status",
        "verdict",
        "score",
        "count",
        "hops",
        "clause",
    }
)


def redact_text(value: str) -> str:
    """Strip anything that could disclose architecture from a string."""
    redacted = _SECRET.sub(REDACTED, value)
    redacted = _EMAIL.sub(REDACTED, redacted)
    redacted = _INTERNAL_HOST.sub(REDACTED, redacted)
    redacted = _IPV4.sub(REDACTED, redacted)
    return _PATH.sub(REDACTED, redacted)


def redact_value(key: str, value: Any, *, depth: int = 0) -> Any:
    """Redact one log field, by key and by content."""
    if key.lower() in FORBIDDEN_KEYS:
        return REDACTED
    if key.lower() in SAFE_KEYS:
        return value

    if isinstance(value, str):
        return redact_text(value)
    if depth >= 4:
        # Deep structures are BOM payloads far more often than they are useful
        # context; truncating is safer than walking indefinitely.
        return REDACTED
    if isinstance(value, dict):
        return {k: redact_value(str(k), v, depth=depth + 1) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [redact_value(key, item, depth=depth + 1) for item in value][:20]
    return value


def redaction_processor(
    _logger: Any, _name: str, event_dict: MutableMapping[str, Any]
) -> Mapping[str, Any]:
    """structlog processor. Sits last, so nothing added later escapes it."""
    return {key: redact_value(str(key), value) for key, value in event_dict.items()}
