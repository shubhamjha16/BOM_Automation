"""Persisted lane results and field verdicts.

These are what let an assessment be re-read years later exactly as it was issued.
`guideline_version_id` on the lane result is the pin: a v3.0 catalogue arriving
next year does not retroactively change what this submission was measured
against.

`engine_version` and `inputs_hash` sit beside it so a re-score can be
distinguished from a drift in the engine — if the same document produces a
different number, one of those three columns says why.
"""

from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import (
    DateTime,
    Enum,
    ForeignKey,
    Index,
    Integer,
    Numeric,
    String,
    Text,
    Uuid,
)
from sqlalchemy.orm import Mapped, mapped_column

from app.models.base import Base, Timestamped, UuidPrimaryKey
from app.models.enums import FieldVerdict, LaneVerdict


class LaneResult(UuidPrimaryKey, Timestamped, Base):
    __tablename__ = "lane_results"
    __table_args__ = (Index("ix_lane_results_submission_id_lane", "submission_id", "lane"),)

    org_id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True), ForeignKey("orgs.id", ondelete="CASCADE"), nullable=False, index=True
    )
    submission_id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True),
        ForeignKey("submissions.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    #: The version this lane was scored under. Never updated in place.
    guideline_version_id: Mapped[uuid.UUID | None] = mapped_column(
        Uuid(as_uuid=True), ForeignKey("guideline_versions.id", ondelete="RESTRICT")
    )
    lane: Mapped[str] = mapped_column(String(10), nullable=False)
    #: Null for lane_absent, lane_timeout and lane_not_applicable. Never zero as a
    #: placeholder — zero is a real score a supplier can earn.
    score: Mapped[float | None] = mapped_column(Numeric(5, 2))
    verdict: Mapped[LaneVerdict] = mapped_column(
        Enum(LaneVerdict, name="lane_verdict", values_callable=lambda e: [i.value for i in e]),
        nullable=False,
    )
    entity_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    detail: Mapped[str | None] = mapped_column(Text)
    engine_version: Mapped[str] = mapped_column(String(20), nullable=False, default="")
    inputs_hash: Mapped[str | None] = mapped_column(String(64))
    computed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


class FieldVerdictRow(UuidPrimaryKey, Timestamped, Base):
    """One element's verdict within one lane result."""

    __tablename__ = "field_verdicts"
    __table_args__ = (
        # The field table is read per lane result, filtered by verdict, on every
        # page load. Hand-added — autogenerate would not produce it (§5).
        Index("ix_field_verdicts_lane_result_id_verdict", "lane_result_id", "verdict"),
    )

    org_id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True), ForeignKey("orgs.id", ondelete="CASCADE"), nullable=False, index=True
    )
    lane_result_id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True),
        ForeignKey("lane_results.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    minimum_element_id: Mapped[uuid.UUID | None] = mapped_column(
        Uuid(as_uuid=True), ForeignKey("minimum_elements.id", ondelete="RESTRICT")
    )
    #: Denormalised so a verdict remains readable if the catalogue row is ever
    #: superseded. The clause gate (S8) still resolves through the FK.
    element_key: Mapped[str] = mapped_column(String(64), nullable=False)
    clause: Mapped[str] = mapped_column(String(32), nullable=False)
    verdict: Mapped[FieldVerdict] = mapped_column(
        Enum(FieldVerdict, name="field_verdict", values_callable=lambda e: [i.value for i in e]),
        nullable=False,
    )
    populated: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    total: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    coverage: Mapped[float | None] = mapped_column(Numeric(5, 4))
    weight: Mapped[float | None] = mapped_column(Numeric(5, 2))
    detail: Mapped[str | None] = mapped_column(Text)
    #: Paired with every not_determinable verdict, never left empty.
    consumer_action: Mapped[str | None] = mapped_column(Text)
