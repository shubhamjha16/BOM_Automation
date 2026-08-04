"""A client of the firm using this platform — the organisation whose suppliers
are being assessed. Distinct from `orgs`, which is the assessing firm itself.
"""

from __future__ import annotations

import uuid

from sqlalchemy import Enum, ForeignKey, String, Uuid
from sqlalchemy.orm import Mapped, mapped_column

from app.models.base import Base, Timestamped, UuidPrimaryKey
from app.models.enums import Sector


class Client(UuidPrimaryKey, Timestamped, Base):
    __tablename__ = "clients"

    org_id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True), ForeignKey("orgs.id", ondelete="CASCADE"), nullable=False, index=True
    )
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    sector: Mapped[Sector] = mapped_column(
        Enum(Sector, name="client_sector", values_callable=lambda e: [i.value for i in e]),
        nullable=False,
        default=Sector.PRIVATE,
    )
