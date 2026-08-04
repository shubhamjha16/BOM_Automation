"""Router aggregation under /api/v1.

Sprints add to this list; nothing else changes. `main.py` mounts exactly one
router.
"""

from __future__ import annotations

from fastapi import APIRouter

from app.routers import elements, health

api_router = APIRouter(prefix="/api/v1")
api_router.include_router(health.router)
api_router.include_router(elements.router)

__all__ = ["api_router"]
