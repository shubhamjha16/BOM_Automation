"""create_app().

Configuration is validated at import of `envConfig`, so a missing required
variable fails the process here rather than per request in production.
"""

from __future__ import annotations

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.configs.envConfig import settings
from app.routers import api_router
from app.utils.logger import configure_logging, get_logger

logger = get_logger(__name__)


def create_app() -> FastAPI:
    configure_logging()
    app = FastAPI(
        title="BOM Factory",
        version="0.1.0",
        description=(
            "CERT-In conformance assessment for SBOM, CBOM, QBOM, AIBOM and HBOM. "
            "This is a conformance assessment, not a legal opinion."
        ),
    )
    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.cors_origins,
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )
    app.include_router(api_router)

    logger.info(
        "app_created",
        guideline_version=settings.GUIDELINE_VERSION,
        enabled_lanes=list(settings.enabled_lanes),
    )
    return app


app = create_app()
