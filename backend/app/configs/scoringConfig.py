"""Tier weights and thresholds. Numbers live here, never inline in the scorer.

S7 makes the catalogue itself versioned data in Postgres; these weights are the
arithmetic applied to it and are pinned alongside the engine version so an
assessment can always be reproduced.
"""

from __future__ import annotations

from app.configs.envConfig import settings
from app.configs.jobTypes import Tier

#: Bumped whenever scoring arithmetic changes. Written onto every lane_result so
#: a re-score can be distinguished from a drift in the engine.
ENGINE_VERSION = "0.1.0"

TIER_WEIGHTS: dict[Tier, float] = {
    Tier.CRITICAL: 3.0,
    Tier.STANDARD: 2.0,
    Tier.CONTEXTUAL: 1.0,
}

#: A lane passes at or above this; below CONDITIONAL_FLOOR it fails outright.
PASS_THRESHOLD: float = settings.PASS_THRESHOLD
CONDITIONAL_FLOOR: float = 60.0

#: A critical field at zero coverage fails the submission regardless of score (§11).
#: A BOM with no versions can score respectably on descriptive fields while being
#: useless for every purpose the guideline exists to serve.
CRITICAL_GAP_FAILS_SUBMISSION = True
