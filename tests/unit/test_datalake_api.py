import uuid
from datetime import UTC, datetime
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from vigilant.api.v1.datalake import ingest as ingest_module
from vigilant.api.v1.datalake import router as router_module
from vigilant.db.models import Capture


@pytest.mark.asyncio
async def test_ingest_pcap_bytes_writes_file_before_registering_capture(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """ingest_pcap_bytes must persist the file to its final path before handing
    that path to the datalake service, so file_path always resolves."""
    monkeypatch.setattr(ingest_module.settings, "pcap_staging_root", tmp_path)

    seen_paths: list[Path] = []

    async def fake_ingest_capture_to_datalake(_session: object, pcap_path: Path, *, capture_id: uuid.UUID) -> Capture:
        seen_paths.append(pcap_path)
        assert pcap_path.exists(), "file must be written before the service is called"
        return Capture(
            id=capture_id,
            file_path=str(pcap_path),
            event_start=datetime(2026, 1, 1, tzinfo=UTC),
            event_end=datetime(2026, 1, 1, 0, 1, tzinfo=UTC),
        )

    monkeypatch.setattr(ingest_module, "ingest_capture_to_datalake", fake_ingest_capture_to_datalake)

    capture = await ingest_module.ingest_pcap_bytes(b"pcap-bytes")

    assert seen_paths[0].read_bytes() == b"pcap-bytes"
    assert capture.file_path == str(seen_paths[0])


@pytest.mark.asyncio
async def test_ingest_pcap_bytes_stages_under_a_fresh_uuid_directory(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Each ingestion should get its own capture_id-named directory."""
    monkeypatch.setattr(ingest_module.settings, "pcap_staging_root", tmp_path)

    async def fake_ingest_capture_to_datalake(_session: object, pcap_path: Path, *, capture_id: uuid.UUID) -> Capture:
        assert pcap_path.parent.name == str(capture_id)
        return Capture(
            id=capture_id,
            file_path=str(pcap_path),
            event_start=datetime(2026, 1, 1, tzinfo=UTC),
            event_end=datetime(2026, 1, 1, 0, 1, tzinfo=UTC),
        )

    monkeypatch.setattr(ingest_module, "ingest_capture_to_datalake", fake_ingest_capture_to_datalake)

    await ingest_module.ingest_pcap_bytes(b"pcap-bytes")


def test_ingest_endpoint_rejects_non_pcap_filename(client: TestClient) -> None:
    """POST /v1/datalake/ingest should reject files that don't look like pcaps."""
    response = client.post(
        "/v1/datalake/ingest",
        files={"file": ("notes.txt", b"hello", "text/plain")},
    )

    assert response.status_code == 400


def test_ingest_endpoint_rejects_empty_file(client: TestClient) -> None:
    """POST /v1/datalake/ingest should reject an empty upload."""
    response = client.post(
        "/v1/datalake/ingest",
        files={"file": ("capture.pcap", b"", "application/vnd.tcpdump.pcap")},
    )

    assert response.status_code == 400


def test_ingest_endpoint_returns_capture_summary(client: TestClient, monkeypatch: pytest.MonkeyPatch) -> None:
    """A valid pcap upload should return the registered capture's id and time window."""
    capture_id = uuid.uuid4()

    async def fake_ingest_pcap_bytes(_data: bytes) -> Capture:
        return Capture(
            id=capture_id,
            file_path="/data/pcaps/x.pcap",
            event_start=datetime(2026, 1, 1, tzinfo=UTC),
            event_end=datetime(2026, 1, 1, 0, 1, tzinfo=UTC),
        )

    monkeypatch.setattr(router_module, "ingest_pcap_bytes", fake_ingest_pcap_bytes)

    response = client.post(
        "/v1/datalake/ingest",
        files={"file": ("capture.pcap", b"pcap-bytes", "application/vnd.tcpdump.pcap")},
    )

    assert response.status_code == 200
    body = response.json()
    assert body["capture_id"] == str(capture_id)
    assert body["event_start"] == "2026-01-01T00:00:00+00:00"
    assert body["event_end"] == "2026-01-01T00:01:00+00:00"


def test_ingest_endpoint_returns_422_when_the_pcap_has_no_packets(
    client: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A pcap with no packets has no time window, so it is an unprocessable upload rather than a 500."""

    async def fake_ingest_pcap_bytes(_data: bytes) -> Capture:
        raise ValueError("Pcap file contains no packets.")

    monkeypatch.setattr(router_module, "ingest_pcap_bytes", fake_ingest_pcap_bytes)

    response = client.post(
        "/v1/datalake/ingest",
        files={"file": ("capture.pcap", b"pcap-bytes", "application/vnd.tcpdump.pcap")},
    )

    assert response.status_code == 422
    assert response.json()["detail"] == "Pcap file contains no packets."
