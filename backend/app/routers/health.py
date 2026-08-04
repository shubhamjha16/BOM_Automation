"""Liveness and the pinned-guideline disclosure."""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter

from app.controllers.healthController import guideline_disclosure, liveness

router = APIRouter(tags=["health"])


@router.get("/health")
async def health() -> dict[str, Any]:
    return liveness()


@router.get("/health/guideline")
async def guideline() -> dict[str, Any]:
    return guideline_disclosure()
