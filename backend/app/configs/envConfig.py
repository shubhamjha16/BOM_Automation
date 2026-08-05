"""Typed, fail-fast configuration.

The sibling repos use ``os.environ.get("GROQ_API_KEY", "")``, which lets a service
boot with no LLM key and fail once per request, in production, on a client's
submission. This module refuses to import instead, naming every variable that is
missing or malformed.
"""

from __future__ import annotations

from functools import lru_cache
from typing import Literal

from pydantic import Field, ValidationError, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

Lane = Literal["sbom", "cbom", "qbom", "aibom", "hbom"]
ALL_LANES: tuple[Lane, ...] = ("sbom", "cbom", "qbom", "aibom", "hbom")


class MissingConfiguration(RuntimeError):
    """Raised at import when required configuration is absent or malformed."""


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=(".env.local", ".env"),
        env_file_encoding="utf-8",
        case_sensitive=True,
        extra="ignore",
    )

    # --- required: no defaults, deliberately -------------------------------
    GROQ_API_KEY: str
    ANTHROPIC_API_KEY: str
    JWT_SECRET: str

    # --- infrastructure ----------------------------------------------------
    DATABASE_URL: str = "postgresql+asyncpg://bom:bom@localhost:5432/bom_automation"
    REDIS_URL: str = "redis://localhost:6379/0"
    PORT: int = 8005
    CORS_ORIGINS: str = "http://localhost:5173"
    SENTRY_DSN: str | None = None

    # --- auth (S5) ---------------------------------------------------------
    GOOGLE_CLIENT_ID: str | None = None
    GOOGLE_CLIENT_SECRET: str | None = None
    GOOGLE_REDIRECT_URI: str = "http://localhost:8005/api/v1/auth/google/callback"
    #: A BOM is an architecture disclosure and this system holds many suppliers'
    #: at once. MFA is on by default and turning it off is a deliberate act.
    MFA_REQUIRED: bool = True
    ACCESS_TOKEN_TTL_MINUTES: int = 30
    REFRESH_TOKEN_TTL_DAYS: int = 14
    JWT_ALGORITHM: str = "HS256"

    #: Run assessments in the request process instead of handing them to arq.
    #: For single-process development and tests only. It is a real setting rather
    #: than an implicit fallback because a production deployment silently running
    #: assessments inline — because Redis happened to be unreachable — would tie
    #: a 50,000-component scoring run to an HTTP timeout and look like a hang.
    JOBS_INLINE: bool = False

    # --- models ------------------------------------------------------------
    ROUTER_MODEL: str = "llama-3.3-70b-versatile"
    DRAFTER_MODEL: str = "claude-sonnet-4-5"

    # --- storage -----------------------------------------------------------
    S3_BUCKET: str | None = None
    AWS_REGION: str = "ap-south-1"
    KMS_KEY_ID: str | None = None
    PRESIGN_TTL_SECONDS: int = 900
    MAX_BOM_MB: int = 100

    # --- guideline pinning -------------------------------------------------
    GUIDELINE_VERSION: str = "2.0"
    GUIDELINE_DATE: str = "2025-07-09"

    # --- scoring / lanes ---------------------------------------------------
    ENABLED_LANES: str = "sbom,aibom,cbom,qbom,hbom"
    PASS_THRESHOLD: float = 85.0
    LANE_TIMEOUT_SECONDS: int = 120
    SELF_CONFORMANCE_MIN: float = 90.0

    # --- agents (S10–S12) --------------------------------------------------
    AGENTS_ENABLED: bool = True
    AGENT_MAX_HOPS: int = 3
    AGENT_BATCH_SIZE: int = 50
    AGENT_MIN_CONFIDENCE: float = Field(default=0.6, ge=0.0, le=1.0)

    # --- enrichment feeds (S10) --------------------------------------------
    #: Whether the enrich node may call the feeds live.
    #:
    #: On in production; off in tests, and that is not merely convenience. A
    #: suite that queries NVD on every run is flaky by construction and rude to a
    #: shared public service. The feed clients are verified against the live
    #: services separately; the graph is verified with the network switched off.
    ENRICHMENT_ONLINE: bool = True
    NVD_API_KEY: str | None = None
    KB_SYNC_CRON: str = "0 3 * * *"

    # --- narrative drafting (RAG) ------------------------------------------
    #: Whether a completion provider may be called to draft section prose.
    #:
    #: **Off by default, and that is the safe default rather than a timid one.**
    #: With it off, `NullGenerator` restates the engine's findings and marks the
    #: section undrafted — correct information in flat prose. Turning it on buys
    #: better wording and nothing else: every verdict, figure and clause still
    #: comes from `services/score/`, and `narrative/drafter.verify` refuses a
    #: draft asserting anything it was not supplied (§11).
    NARRATIVE_ENABLED: bool = False
    NARRATIVE_MODEL: str = "claude-opus-5"
    #: Drafting house prose from supplied facts is not an intelligence-critical
    #: task, and effort is the cost lever. `medium` is the balance point; raise it
    #: only if section quality actually warrants the spend.
    NARRATIVE_EFFORT: Literal["low", "medium", "high", "xhigh", "max"] = "medium"
    #: Caps thinking *and* response text together. A section is capped at a few
    #: hundred words, so the headroom here is almost entirely for thinking.
    NARRATIVE_MAX_TOKENS: int = 8000

    # --- retention ---------------------------------------------------------
    SUBMISSION_RETENTION_DAYS: int = 1095

    @field_validator("JWT_SECRET")
    @classmethod
    def _strong_signing_key(cls, raw: str) -> str:
        """RFC 7518 §3.2: an HMAC key below the hash output length weakens the
        signature. PyJWT warns; we refuse, because a short secret here means
        forgeable tokens across every tenant."""
        if len(raw.encode()) < 32:
            raise ValueError(
                f"must be at least 32 bytes for HS256 (got {len(raw.encode())}); "
                "generate one with `openssl rand -base64 48`"
            )
        return raw

    @field_validator("ENABLED_LANES")
    @classmethod
    def _known_lanes(cls, raw: str) -> str:
        lanes = [item.strip().lower() for item in raw.split(",") if item.strip()]
        if not lanes:
            raise ValueError("must name at least one lane")
        unknown = [lane for lane in lanes if lane not in ALL_LANES]
        if unknown:
            raise ValueError(f"unknown lane(s) {unknown}; valid lanes are {list(ALL_LANES)}")
        return ",".join(lanes)

    @property
    def enabled_lanes(self) -> tuple[Lane, ...]:
        """Deployment-wide default. An engagement narrows this; it never widens it."""
        return tuple(lane for lane in ALL_LANES if lane in self.ENABLED_LANES.split(","))

    @property
    def cors_origins(self) -> list[str]:
        return [origin.strip() for origin in self.CORS_ORIGINS.split(",") if origin.strip()]


def _describe(error: ValidationError) -> str:
    lines = []
    for detail in error.errors():
        name = ".".join(str(part) for part in detail["loc"]) or "<root>"
        if detail["type"] == "missing":
            lines.append(f"  {name}: required, not set in the environment or .env.local")
        else:
            lines.append(f"  {name}: {detail['msg']}")
    return "\n".join(lines)


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    try:
        return Settings()  # type: ignore[call-arg]
    except ValidationError as error:
        raise MissingConfiguration(
            "Configuration is incomplete; the service will not start.\n"
            f"{_describe(error)}\n"
            "See backend/.env.example for the full set."
        ) from error


settings = get_settings()
