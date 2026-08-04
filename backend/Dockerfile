# syntax=docker/dockerfile:1.7
#
# Backend image. Serves both the API and the arq worker — same code, same
# dependencies, different start command, so the two can never drift apart in a
# way that lets a job enqueue against one schema and execute against another.

FROM python:3.12-slim AS base

# uv is the packaging tool for this repo; copying the binary from the official
# image avoids a pip bootstrap and pins the version explicitly.
COPY --from=ghcr.io/astral-sh/uv:0.11 /uv /uvx /bin/

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    UV_COMPILE_BYTECODE=1 \
    UV_LINK_MODE=copy \
    UV_PROJECT_ENVIRONMENT=/app/.venv \
    PATH="/app/.venv/bin:$PATH"

WORKDIR /app

# --- dependency layer -------------------------------------------------------
# Manifests only, so a source edit does not invalidate the dependency cache.
# --frozen refuses to silently resolve a different set than uv.lock pins: a
# supply-chain conformance tool that cannot reproduce its own build has no
# standing to assess anyone else's.
COPY pyproject.toml uv.lock ./
RUN --mount=type=cache,target=/root/.cache/uv \
    uv sync --frozen --no-install-project --no-dev

# --- application layer ------------------------------------------------------
COPY . .
RUN --mount=type=cache,target=/root/.cache/uv \
    uv sync --frozen --no-dev

# Never root. A BOM under assessment is untrusted input, and S17 will run
# dependency resolution over supplier repositories in this same image family.
RUN useradd --create-home --uid 10001 bom && chown -R bom:bom /app
USER bom

EXPOSE 8005

# Compose overrides this for the worker. Migrations are NOT run here — they are a
# pre-deploy step (§10), never inside the web process, or two replicas racing a
# schema change is a matter of timing.
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8005"]
