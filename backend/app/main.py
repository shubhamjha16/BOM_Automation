"""create_app().

Configuration is validated at import of `envConfig`, so a missing required
variable fails the process here rather than per request in production.
"""

from __future__ import annotations

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from app.configs.envConfig import settings
from app.controllers.authController import AuthenticationFailed, MfaRequired
from app.routers import api_router
from app.services.access.authz import Forbidden
from app.utils.bodyLimit import BodySizeLimitMiddleware
from app.utils.logger import configure_logging, get_logger
from app.validators.submissionValidator import SubmissionInvalid, max_document_bytes

logger = get_logger(__name__)

DESCRIPTION = """
CERT-In conformance assessment for SBOM, CBOM, QBOM, AIBOM and HBOM.

**This is a conformance assessment, not a legal opinion.** Every export states so
and states what was not assessed.

Verdicts, scores and clause references are produced by the deterministic scoring
engine, never by a language model.
"""


def create_app() -> FastAPI:
    configure_logging()
    app = FastAPI(
        title="BOM Factory",
        version="0.1.0",
        description=DESCRIPTION,
        openapi_tags=[
            {"name": "health", "description": "Liveness and the pinned guideline version."},
            {"name": "elements", "description": "The encoded minimum-element catalogue."},
            {"name": "submissions", "description": "Receive and assess BOM submissions."},
            {"name": "jobs", "description": "Assessment job status and per-node run log."},
        ],
    )

    # Outermost: an oversized body is refused before anything reads it.
    app.add_middleware(BodySizeLimitMiddleware, max_bytes=max_document_bytes())
    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.cors_origins,
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    @app.exception_handler(SubmissionInvalid)
    async def _invalid_submission(_: Request, error: SubmissionInvalid) -> JSONResponse:
        """422 with every violation, not just the first.

        A supplier fixing a 100 MB upload one error at a time is a bad afternoon.
        """
        return JSONResponse(
            status_code=422,
            content={
                "detail": "submission rejected",
                "violations": [
                    {"field": violation.field, "message": violation.message}
                    for violation in error.violations
                ],
            },
        )

    @app.exception_handler(AuthenticationFailed)
    async def _auth_failed(_: Request, error: AuthenticationFailed) -> JSONResponse:
        """401 with a deliberately uninformative body.

        Without this the exception escapes as a 500, which is both a broken API
        and an oracle: a 500 on a real account and a 401 on an unknown one tells
        an attacker which addresses exist.
        """
        return JSONResponse(
            status_code=401,
            content={"detail": str(error)},
            headers={"WWW-Authenticate": "Bearer"},
        )

    @app.exception_handler(MfaRequired)
    async def _mfa_required(_: Request, error: MfaRequired) -> JSONResponse:
        """200 carrying a challenge, not an error.

        The password was correct; the caller has more to do. Signalling this as a
        4xx would make a normal step of sign-in look like a failure.
        """
        return JSONResponse(
            status_code=200,
            content={
                "mfa_required": True,
                "enrolled": error.enrolled,
                "pending_token": error.pending_token,
            },
        )

    @app.exception_handler(Forbidden)
    async def _forbidden(_: Request, error: Forbidden) -> JSONResponse:
        """403 is correct here and only here: the caller is inside their own org,
        so acknowledging the resource leaks nothing. Cross-tenant denials return
        404 instead, and that distinction is deliberate."""
        return JSONResponse(status_code=403, content={"detail": str(error)})

    app.include_router(api_router)

    logger.info(
        "app_created",
        guideline_version=settings.GUIDELINE_VERSION,
        enabled_lanes=list(settings.enabled_lanes),
        max_body_bytes=max_document_bytes(),
    )
    return app


app = create_app()
