from __future__ import annotations

from fastapi import APIRouter, HTTPException
from fastapi import Path as FastAPIPath
from fastapi.responses import FileResponse

from vigilant.api.v1.pcap.utils import staged_file_path

pcap_router = APIRouter()


@pcap_router.get("/files/{file_id}")
async def get_file_info(
    file_id: str = FastAPIPath(..., description="The unique ID of the staged file (e.g., the pcap_ref)"),
) -> dict[str, object]:
    """Check if a staged file exists."""
    file_path = staged_file_path(file_id)
    if not file_path.exists():
        raise HTTPException(status_code=404, detail="File not found in staging.")

    return {"file_id": file_id, "exists": True, "path": str(file_path)}


@pcap_router.get("/files/{file_id}/content")
async def get_file_content(
    file_id: str = FastAPIPath(..., description="The unique ID of the staged file"),
) -> FileResponse:
    """Retrieve the raw bytes of a staged file."""
    file_path = staged_file_path(file_id)
    if not file_path.exists():
        raise HTTPException(status_code=404, detail="File not found in staging.")

    return FileResponse(file_path)
