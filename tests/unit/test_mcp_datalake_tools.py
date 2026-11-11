import uuid
from datetime import UTC, datetime

import pytest
from mcp.shared.memory import create_connected_server_and_client_session

from vigilant.mcp import server as server_module
from vigilant.mcp.server import mcp
from vigilant.mcp.tools.get_pcaps import (
    CaptureNotFoundError,
    CaptureSummary,
)


@pytest.mark.asyncio
async def test_list_captures_tool_returns_registered_captures(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The list_captures MCP tool should expose CaptureSummary rows from the datalake."""
    capture_id = uuid.uuid4()

    async def fake_list_captures(*, start: datetime | None = None, end: datetime | None = None) -> list[CaptureSummary]:
        return [
            CaptureSummary(
                capture_id=capture_id,
                event_start=datetime(2026, 1, 1, tzinfo=UTC),
                event_end=datetime(2026, 1, 1, 0, 1, tzinfo=UTC),
            )
        ]

    monkeypatch.setattr(server_module, "_list_captures", fake_list_captures)

    async with create_connected_server_and_client_session(mcp._mcp_server) as client:
        result = await client.call_tool("list_captures", {})

    assert result.isError is False
    assert str(capture_id) in result.content[0].text  # type: ignore[union-attr]


@pytest.mark.asyncio
@pytest.mark.parametrize("tool", ["pcap_ip", "pcap_arp", "pcap_tcp", "pcap_udp"])
async def test_view_tools_reject_invalid_uuid(tool: str) -> None:
    """A malformed capture_id should surface as a tool error, not an unhandled exception."""
    async with create_connected_server_and_client_session(mcp._mcp_server) as client:
        result = await client.call_tool(tool, {"capture_id": "not-a-uuid"})

    assert result.isError is True


@pytest.mark.asyncio
@pytest.mark.parametrize("tool", ["pcap_ip", "pcap_arp", "pcap_tcp", "pcap_udp"])
async def test_view_tools_report_unknown_capture(monkeypatch: pytest.MonkeyPatch, tool: str) -> None:
    """An unregistered capture_id should surface as a tool error, not an unhandled exception."""

    async def fake_view(parsed_capture_id: uuid.UUID, offset: int, limit: int) -> object:
        raise CaptureNotFoundError(f"No capture found with id {parsed_capture_id}.")

    monkeypatch.setattr(server_module, f"_{tool}", fake_view)

    async with create_connected_server_and_client_session(mcp._mcp_server) as client:
        result = await client.call_tool(tool, {"capture_id": str(uuid.uuid4())})

    assert result.isError is True
