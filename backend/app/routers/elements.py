"""The encoded catalogue, inspectable.

`GET /elements?lane=sbom` returns every minimum element with its clause, tier and
determinability so a client can check the encoding against the published PDF
themselves. A conformance engine whose rules cannot be read is asking to be
trusted rather than verified.
"""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, HTTPException, Query

from app.configs.envConfig import ALL_LANES, Lane
from app.controllers.elementController import list_elements

router = APIRouter(prefix="/elements", tags=["elements"])


@router.get("")
async def get_elements(lane: Lane = Query(..., description="BOM lane")) -> dict[str, Any]:
    if lane not in ALL_LANES:
        raise HTTPException(422, f"unknown lane {lane!r}; valid lanes are {list(ALL_LANES)}")
    return list_elements(lane)
