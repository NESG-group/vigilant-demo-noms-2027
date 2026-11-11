from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import TIMESTAMP, String
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column

from vigilant.db.base import Base


class Capture(Base):
    """Catalog entry for a staged pcap file.

    Stores only the file location and the time window covered by the
    capture. Packet-level data is never persisted in the database; it is
    read on demand from the file at ``file_path``.
    """

    __tablename__ = "captures"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True)
    file_path: Mapped[str] = mapped_column(String(length=1024), nullable=False)
    event_start: Mapped[datetime] = mapped_column(TIMESTAMP(timezone=True), nullable=False)
    event_end: Mapped[datetime] = mapped_column(TIMESTAMP(timezone=True), nullable=False)
