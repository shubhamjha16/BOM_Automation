"""The guideline and its minimum elements, as versioned data.

**Why the catalogue is a table and not a Python constant.** The guideline will
reach v3.0. When it does, every assessment already issued was scored under v2.0
and must keep reporting against v2.0 — a client holding a conformance assessment
must be able to say which document it was measured against. A code constant
cannot do that: it changes for everyone at once, retroactively, and silently.

`checksum` is what makes the pinning real. It is computed over the encoded
elements at seed time, so an edit to `services/catalogue/*.py` that is not
accompanied by a new version row is detectable rather than invisible.
"""

from __future__ import annotations

import uuid
from datetime import date

from sqlalchemy import Date, Enum, ForeignKey, Index, String, Text, UniqueConstraint, Uuid
from sqlalchemy.orm import Mapped, mapped_column

from app.models.base import Base, Timestamped, UuidPrimaryKey
from app.models.enums import Determinability, Tier


class GuidelineVersion(UuidPrimaryKey, Timestamped, Base):
    __tablename__ = "guideline_versions"
    __table_args__ = (UniqueConstraint("version", name="uq_guideline_versions_version"),)

    ref: Mapped[str] = mapped_column(String(255), nullable=False)
    version: Mapped[str] = mapped_column(String(20), nullable=False)
    published_on: Mapped[date | None] = mapped_column(Date)
    #: SHA-256 over the encoded elements. A silent catalogue edit moves this.
    checksum: Mapped[str] = mapped_column(String(64), nullable=False)
    reviewed_by: Mapped[str | None] = mapped_column(String(255))


class MinimumElement(UuidPrimaryKey, Timestamped, Base):
    """One row of a CERT-In minimum-element table, pinned to a guideline version."""

    __tablename__ = "minimum_elements"
    __table_args__ = (
        UniqueConstraint(
            "guideline_version_id", "lane", "key", name="uq_minimum_elements_version_lane_key"
        ),
        Index("ix_minimum_elements_version_lane", "guideline_version_id", "lane"),
    )

    guideline_version_id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True),
        ForeignKey("guideline_versions.id", ondelete="CASCADE"),
        nullable=False,
    )
    lane: Mapped[str] = mapped_column(String(10), nullable=False)
    key: Mapped[str] = mapped_column(String(64), nullable=False)
    label: Mapped[str] = mapped_column(String(255), nullable=False)
    #: The clause every verdict citing this element resolves through (S8).
    clause: Mapped[str] = mapped_column(String(32), nullable=False)
    tier: Mapped[Tier] = mapped_column(
        Enum(Tier, name="element_tier", values_callable=lambda e: [i.value for i in e]),
        nullable=False,
    )
    determinability: Mapped[Determinability] = mapped_column(
        Enum(
            Determinability,
            name="element_determinability",
            values_callable=lambda e: [i.value for i in e],
        ),
        nullable=False,
    )
    #: 'entity' or 'document' — what the element is a property of.
    scope: Mapped[str] = mapped_column(String(10), nullable=False, default="entity")
    rationale: Mapped[str | None] = mapped_column(Text)
    #: Required on every HUMAN element: a not_determinable verdict without an
    #: action reads as a shrug and the reader assumes it passed.
    consumer_action: Mapped[str | None] = mapped_column(Text)
