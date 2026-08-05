"""SSDLC maturity endpoints."""

from __future__ import annotations

from fastapi import APIRouter, Query

from app.services.maturity.roadmap import Phase, catalogue
from app.services.self.maturity import build as build_self_scorecard

router = APIRouter(prefix="/maturity", tags=["maturity"])


@router.get("/activities")
async def activities(phase: Phase | None = Query(None)) -> dict:
    """The s.3.3 roadmap, inspectable — as the minimum elements are."""
    rows = catalogue()
    if phase is not None:
        rows = [row for row in rows if row["phase"] == str(phase)]
    return {"activities": rows, "count": len(rows)}


@router.get("/self")
async def self_scorecard() -> dict:
    """Our own SSDLC maturity, gaps included.

    Published because a maturity tool that reports only its own strengths is not
    evidence of anything.
    """
    return build_self_scorecard().as_report()
