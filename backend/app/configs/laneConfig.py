"""Which lanes run, and what an unimplemented lane is allowed to say.

Lane enablement is config, not code (§4). All five lane modules exist from S1;
an engagement enables only the lanes its client actually has.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass

from app.configs.envConfig import ALL_LANES, Lane, settings


@dataclass(frozen=True, slots=True)
class LaneSpec:
    lane: Lane
    label: str
    #: Section of the guideline this lane's minimum-element table lives in.
    clause: str
    #: False until the lane's catalogue and scorer ship; an unimplemented lane
    #: reports lane_absent rather than silently scoring zero fields as a pass.
    implemented: bool


LANE_SPECS: dict[Lane, LaneSpec] = {
    "sbom": LaneSpec("sbom", "Software BOM", "4.2", implemented=True),
    "aibom": LaneSpec("aibom", "AI BOM", "9.3", implemented=True),
    "cbom": LaneSpec("cbom", "Cryptography BOM", "8.4", implemented=True),
    "qbom": LaneSpec("qbom", "Quantum BOM", "8.5", implemented=True),
    # S16 implements HBOM; its data is procurement data, not scanner output.
    "hbom": LaneSpec("hbom", "Hardware BOM", "10.2", implemented=False),
}


def resolve_lanes(engagement_lanes: Sequence[str] | None = None) -> tuple[Lane, ...]:
    """The lanes to fan out to.

    An engagement narrows the deployment default; it never widens it. A lane the
    deployment has switched off cannot be re-enabled per engagement, because the
    reason a deployment switches a lane off is that its catalogue is not trusted.
    """
    deployment = settings.enabled_lanes
    if engagement_lanes is None:
        return deployment
    requested = {lane.strip().lower() for lane in engagement_lanes}
    return tuple(lane for lane in ALL_LANES if lane in requested and lane in deployment)


def is_implemented(lane: Lane) -> bool:
    return LANE_SPECS[lane].implemented
