import uuid
from datetime import UTC
from pathlib import Path

import pytest
from scapy.utils import wrpcap

from vigilant.db.models import Capture
from vigilant.services.datalake_ingest import ingest_capture_to_datalake

DATA_PCAPS = Path(__file__).parents[2] / "data"


class FakeSession:
    """Records what would have been persisted, without touching Postgres."""

    def __init__(self) -> None:
        self.added: list[Capture] = []

    def add(self, obj: Capture) -> None:
        self.added.append(obj)

    async def flush(self) -> None:
        return None


@pytest.mark.asyncio
async def test_ingest_capture_to_datalake_computes_time_window() -> None:
    """The capture's event_start/event_end should span its first and last packet."""
    session = FakeSession()
    capture_id = uuid.uuid4()
    pcap_path = DATA_PCAPS / "ip-networktrace2.pcapng"

    capture = await ingest_capture_to_datalake(session, pcap_path, capture_id=capture_id)  # type: ignore[arg-type]

    assert capture.id == capture_id
    assert capture.file_path == str(pcap_path)
    assert capture.event_start <= capture.event_end
    assert capture.event_start.tzinfo == UTC
    assert session.added == [capture]


@pytest.mark.asyncio
async def test_ingest_capture_to_datalake_does_not_persist_packet_contents() -> None:
    """Only the Capture row is added to the session — never per-packet rows."""
    session = FakeSession()
    pcap_path = DATA_PCAPS / "arp-icmp.pcapng"

    await ingest_capture_to_datalake(session, pcap_path, capture_id=uuid.uuid4())  # type: ignore[arg-type]

    assert len(session.added) == 1
    assert isinstance(session.added[0], Capture)


@pytest.mark.asyncio
async def test_ingest_capture_to_datalake_rejects_empty_pcap(tmp_path: Path) -> None:
    """A pcap with no packets should raise instead of producing a capture with no time window."""
    empty_pcap = tmp_path / "empty.pcap"
    wrpcap(str(empty_pcap), [])
    session = FakeSession()

    with pytest.raises(ValueError, match="no packets"):
        await ingest_capture_to_datalake(session, empty_pcap, capture_id=uuid.uuid4())  # type: ignore[arg-type]
