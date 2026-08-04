"""Tenant root. Every scoped table carries `org_id` back to here."""

from __future__ import annotations

from sqlalchemy import Integer, String
from sqlalchemy.orm import Mapped, mapped_column

from app.models.base import Base, Timestamped, UuidPrimaryKey


class Org(UuidPrimaryKey, Timestamped, Base):
    __tablename__ = "orgs"

    name: Mapped[str] = mapped_column(String(255), nullable=False)
    plan: Mapped[str] = mapped_column(String(50), nullable=False, default="starter")
    seats: Mapped[int] = mapped_column(Integer, nullable=False, default=1)
