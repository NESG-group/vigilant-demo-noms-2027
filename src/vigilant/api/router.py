from fastapi import APIRouter
from fastapi.responses import RedirectResponse

from vigilant.api.v1 import chat
from vigilant.api.v1.datalake.router import datalake_router
from vigilant.api.v1.pcap.router import pcap_router

api_router = APIRouter()

api_router.include_router(chat.router, prefix="/v1", tags=["OpenAI Compatible Chat"])
api_router.include_router(pcap_router, prefix="/v1/pcap", tags=["PCAP Staging"])
api_router.include_router(datalake_router, prefix="/v1/datalake", tags=["Datalake Ingest"])


@api_router.get("/", include_in_schema=False)
async def redirect_to_docs() -> RedirectResponse:
    """Redirect to Swagger UI documentation."""
    return RedirectResponse(url="/docs")
