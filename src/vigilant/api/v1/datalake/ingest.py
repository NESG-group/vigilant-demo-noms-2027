from __future__ import annotations

import uuid
from pathlib import Path

from vigilant.config import settings
from vigilant.db.models import Capture
from vigilant.db.session import get_session
from vigilant.services.datalake_ingest import ingest_capture_to_datalake


async def ingest_pcap_bytes(data: bytes) -> Capture:
    """Stage an uploaded pcap under `PCAP_STAGING_ROOT` and register it in
    the datalake catalog.

    The file is written to its final location before the catalog row is
    created, so `Capture.file_path` always points to a file that exists.
    """
    capture_id = uuid.uuid4()
    capture_dir = Path(settings.pcap_staging_root) / str(capture_id)
    capture_dir.mkdir(parents=True, exist_ok=True)

    pcap_path = capture_dir / "raw.pcap"
    pcap_path.write_bytes(data)

    async with get_session() as session:
        return await ingest_capture_to_datalake(session, pcap_path, capture_id=capture_id)
