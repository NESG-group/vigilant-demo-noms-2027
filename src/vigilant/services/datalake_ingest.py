from __future__ import annotations

import uuid
from datetime import UTC, datetime
from pathlib import Path

from scapy.utils import PcapReader
from sqlalchemy.ext.asyncio import AsyncSession

from vigilant.db.models import Capture


async def ingest_capture_to_datalake(
    session: AsyncSession,
    pcap_path: Path,
    *,
    capture_id: uuid.UUID,
) -> Capture:
    """Compute the time window of the pcap at `pcap_path` and persist a
    `Capture` row referencing it.

    `pcap_path` must already be the file's final, persistent on-disk
    location — this function does not move or copy it.

    Raises:
        ValueError: if the pcap contains no packets, since `event_start`/
            `event_end` would have no value to take.
    """
    event_start: datetime | None = None
    event_end: datetime | None = None

    with PcapReader(str(pcap_path)) as reader:
        for pkt in reader:
            ts = datetime.fromtimestamp(float(pkt.time), tz=UTC)
            if event_start is None or ts < event_start:
                event_start = ts
            if event_end is None or ts > event_end:
                event_end = ts

    if event_start is None or event_end is None:
        raise ValueError("Pcap file contains no packets.")

    capture = Capture(
        id=capture_id,
        file_path=str(pcap_path),
        event_start=event_start,
        event_end=event_end,
    )
    session.add(capture)
    await session.flush()
    return capture
