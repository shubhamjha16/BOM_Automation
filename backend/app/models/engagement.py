"""An engagement scopes a body of assessment work and — importantly — which
lanes run for it.

`enabled_lanes` is why `lane_not_applicable` exists as a distinct verdict: a
client with no quantum hardware has nothing to declare, and should not carry a
zero-scoring empty QBOM lane in their overall score.
"""

from __future__ import annotations

import uuid

from sqlalchemy import Enum, ForeignKey, String, Uuid
from sqlalchemy.orm import Mapped, mapped_column

from app.models.base import Base, Timestamped, UuidPrimaryKey, text_array
from app.models.enums import EngagementKind, EngagementStatus


class Engagement(UuidPrimaryKey, Timestamped, Base):
    __tablename__ = "engagements"

    org_id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True), ForeignKey("orgs.id", ondelete="CASCADE"), nullable=False, index=True
    )
    client_id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True), ForeignKey("clients.id", ondelete="CASCADE"), nullable=False
    )
    title: Mapped[str] = mapped_column(String(255), nullable=False)
    kind: Mapped[EngagementKind] = mapped_column(
        Enum(
            EngagementKind,
            name="engagement_kind",
            values_callable=lambda e: [i.value for i in e],
        ),
        nullable=False,
        default=EngagementKind.PROCUREMENT_REVIEW,
    )
    #: Narrows the deployment default; never widens it. See configs/laneConfig.py.
    enabled_lanes: Mapped[list[str]] = mapped_column(
        text_array(), nullable=False, default=list
    )
    status: Mapped[EngagementStatus] = mapped_column(
        Enum(
            EngagementStatus,
            name="engagement_status",
            values_callable=lambda e: [i.value for i in e],
        ),
        nullable=False,
        default=EngagementStatus.ACTIVE,
    )
