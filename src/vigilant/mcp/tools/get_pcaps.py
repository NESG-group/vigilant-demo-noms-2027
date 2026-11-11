from __future__ import annotations

import uuid
from datetime import datetime

from pydantic import BaseModel
from sqlalchemy import select

from vigilant.db.models import Capture
from vigilant.db.session import get_session


class CaptureSummary(BaseModel):
    """Minimal identifying info for a stored capture."""

    capture_id: uuid.UUID
    event_start: datetime
    event_end: datetime


class CaptureNotFoundError(ValueError):
    """Raised when `capture_id` has no matching row in the datalake."""


async def get_capture_file_path(capture_id: uuid.UUID) -> str:
    """Resolve the on-disk path of a registered capture.

    Raises:
        CaptureNotFoundError: if `capture_id` has no catalog row.
    """
    async with get_session() as session:
        capture = await session.get(Capture, capture_id)
    if capture is None:
        raise CaptureNotFoundError(f"No capture found with id {capture_id}.")
    return str(capture.file_path)


async def list_captures(
    start: datetime | None = None,
    end: datetime | None = None,
) -> list[CaptureSummary]:
    """Return captures registered in the datalake, optionally filtered to
    those whose time window overlaps [start, end].

    Omitting both returns every capture. Omitting one bound leaves that
    side open (e.g. start=None means "any capture ending before `end`").
    """
    async with get_session() as session:
        stmt = select(Capture).order_by(Capture.event_start.desc())
        if start is not None:
            stmt = stmt.where(Capture.event_end >= start)
        if end is not None:
            stmt = stmt.where(Capture.event_start <= end)

        result = await session.scalars(stmt)
        return [CaptureSummary(capture_id=c.id, event_start=c.event_start, event_end=c.event_end) for c in result.all()]
