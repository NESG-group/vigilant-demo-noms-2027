from __future__ import annotations

from fastapi import APIRouter, HTTPException, UploadFile
from pydantic import BaseModel

from vigilant.api.v1.datalake.ingest import ingest_pcap_bytes
from vigilant.api.v1.pcap.utils import looks_like_pcap

datalake_router = APIRouter()


class IngestResponseModel(BaseModel):
    capture_id: str
    event_start: str
    event_end: str


@datalake_router.post("/ingest", response_model=IngestResponseModel)
async def ingest_pcap_to_datalake(file: UploadFile) -> IngestResponseModel:
    """Accept a pcap/pcapng upload, stage it on disk, and register it in the
    datalake catalog."""
    if not looks_like_pcap(file.filename, file.content_type):
        raise HTTPException(status_code=400, detail="File does not look like a pcap/pcapng capture.")

    data = await file.read()
    if not data:
        raise HTTPException(status_code=400, detail="Empty file.")

    try:
        capture = await ingest_pcap_bytes(data)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc

    return IngestResponseModel(
        capture_id=str(capture.id),
        event_start=capture.event_start.isoformat(),
        event_end=capture.event_end.isoformat(),
    )
