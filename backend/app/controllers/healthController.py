"""Health and guideline-disclosure read models. Routers stay thin."""

from __future__ import annotations

from typing import Any

from app.configs.envConfig import ALL_LANES, settings
from app.configs.laneConfig import LANE_SPECS
from app.configs.scoringConfig import ENGINE_VERSION
from app.services.catalogue.loader import catalogue_checksum, get_catalogue, guideline_ref


def liveness() -> dict[str, Any]:
    return {"status": "ok", "engine_version": ENGINE_VERSION}


def guideline_disclosure() -> dict[str, Any]:
    """What produced an assessment, and whether the catalogue has moved.

    Public on purpose: a client reading an assessment must be able to confirm the
    guideline version behind it, and the per-lane checksums make a silent edit to
    the minimum elements detectable from outside.
    """
    return {
        "guideline": guideline_ref(),
        "engine_version": ENGINE_VERSION,
        "pass_threshold": settings.PASS_THRESHOLD,
        "lanes": {
            lane: {
                "label": LANE_SPECS[lane].label,
                "clause_root": get_catalogue(lane).clause_root,
                "implemented": LANE_SPECS[lane].implemented,
                "enabled": lane in settings.enabled_lanes,
                "element_count": len(get_catalogue(lane).elements),
                "catalogue_checksum": catalogue_checksum(lane),
            }
            for lane in ALL_LANES
        },
    }
