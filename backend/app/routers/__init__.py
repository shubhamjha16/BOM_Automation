"""Router aggregation under /api/v1.

Sprints add to this list; nothing else changes. `main.py` mounts exactly one
router.
"""

from __future__ import annotations

from fastapi import APIRouter

from app.routers import assessments, auth, elements, health, jobs, submissions

api_router = APIRouter(prefix="/api/v1")
api_router.include_router(health.router)
api_router.include_router(auth.router)
api_router.include_router(elements.router)
api_router.include_router(submissions.router)
api_router.include_router(jobs.router)
api_router.include_router(assessments.router)

__all__ = ["api_router"]
