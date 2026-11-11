from __future__ import annotations

import uuid
from datetime import datetime

from mcp.server.fastmcp import FastMCP

from vigilant.mcp.tools.filter_pcaps import PcapFilterResult
from vigilant.mcp.tools.filter_pcaps import pcap_arp as _pcap_arp
from vigilant.mcp.tools.filter_pcaps import pcap_ip as _pcap_ip
from vigilant.mcp.tools.filter_pcaps import pcap_tcp as _pcap_tcp
from vigilant.mcp.tools.filter_pcaps import pcap_udp as _pcap_udp
from vigilant.mcp.tools.get_pcaps import CaptureNotFoundError, CaptureSummary
from vigilant.mcp.tools.get_pcaps import (
    list_captures as _list_captures,
)
from vigilant.mcp.tools.ingest_pcap import IngestError, IngestResult
from vigilant.mcp.tools.ingest_pcap import ingest_pcap as _ingest_pcap

mcp = FastMCP("vigilant-network")


def _parse_capture_id(capture_id: str) -> uuid.UUID:
    """Parse a capture UUID, raising an error message the LLM can act on."""
    try:
        return uuid.UUID(capture_id)
    except ValueError as exc:
        raise ValueError(f"capture_id must be a valid UUID, got {capture_id!r}") from exc


@mcp.tool()
async def ping() -> str:
    """Health-check tool used to verify MCP connectivity (Hermes <-> VIGILANT, FastAPI <-> VIGILANT)."""
    return "pong"


@mcp.tool()
async def ingest_pcap(pcap_ref: str) -> IngestResult | IngestError:
    """
    Resolve and validate a staged pcap/pcapng attachment and register it in
    the datalake. Returns the `capture_id` to pass to the pcap_* views.

    pcap_ref: the exact reference from the
    `[pcap attachment staged: pcap_ref=...]` marker. Do not pass raw bytes,
    base64 content, or a filesystem path.
    """
    return await _ingest_pcap(pcap_ref)


@mcp.tool()
async def list_captures(start: str | None = None, end: str | None = None) -> list[CaptureSummary]:
    """
    List captures registered in the datalake, optionally filtered to those
    whose time window overlaps a given range. Results are ordered newest first.

    start/end: ISO 8601 timestamps (e.g. "2024-11-11T19:00:00Z"). Omit
    both to list every capture. Use this to find a capture_id when the
    user describes a capture by time rather than giving its UUID.
    """
    parsed_start = datetime.fromisoformat(start) if start else None
    parsed_end = datetime.fromisoformat(end) if end else None
    return await _list_captures(start=parsed_start, end=parsed_end)


@mcp.tool()
async def pcap_ip(capture_id: str, offset: int = 0, limit: int = 100) -> PcapFilterResult:
    """
    IPv4 view of a stored capture: src/dst, protocol name, TTL and IP length
    per packet. Use it for L3 questions (who talks to whom, TTL anomalies,
    protocol distribution). No ports, no flags, no application text.

    capture_id: a UUID from list_captures or ingest_pcap. offset/limit: paging.
    """
    parsed_id = _parse_capture_id(capture_id)
    try:
        return await _pcap_ip(parsed_id, offset, limit)
    except CaptureNotFoundError as exc:
        raise ValueError(str(exc)) from exc


@mcp.tool()
async def pcap_arp(capture_id: str, offset: int = 0, limit: int = 100) -> PcapFilterResult:
    """
    ARP view of a stored capture: opcode (1 request, 2 reply) with sender and
    target MAC and IP for every ARP packet, requests included. Use it to
    confirm or refute ARP spoofing, gratuitous ARP or ARP scanning.

    capture_id: a UUID from list_captures or ingest_pcap. offset/limit: paging.
    """
    parsed_id = _parse_capture_id(capture_id)
    try:
        return await _pcap_arp(parsed_id, offset, limit)
    except CaptureNotFoundError as exc:
        raise ValueError(str(exc)) from exc


@mcp.tool()
async def pcap_tcp(capture_id: str, offset: int = 0, limit: int = 100) -> PcapFilterResult:
    """
    TCP view of a stored capture: addresses, ports, flags (e.g. "SYN,ACK"),
    seq/ack, window, payload length and stream index per packet. Use it for
    handshakes, SYN scans, resets and connection behaviour. ICMP errors that
    merely quote a TCP header are excluded.

    capture_id: a UUID from list_captures or ingest_pcap. offset/limit: paging.
    """
    parsed_id = _parse_capture_id(capture_id)
    try:
        return await _pcap_tcp(parsed_id, offset, limit)
    except CaptureNotFoundError as exc:
        raise ValueError(str(exc)) from exc


@mcp.tool()
async def pcap_udp(capture_id: str, offset: int = 0, limit: int = 100) -> PcapFilterResult:
    """
    UDP view of a stored capture: addresses, ports, UDP length and stream index
    per packet. Use it for DNS/NTP/DHCP-style traffic, beaconing patterns and
    UDP scans. ICMP errors that merely quote a UDP header are excluded.

    capture_id: a UUID from list_captures or ingest_pcap. offset/limit: paging.
    """
    parsed_id = _parse_capture_id(capture_id)
    try:
        return await _pcap_udp(parsed_id, offset, limit)
    except CaptureNotFoundError as exc:
        raise ValueError(str(exc)) from exc


def main() -> None:
    """Entrypoint for running the MCP server over stdio (local Hermes profile)."""
    mcp.run()


if __name__ == "__main__":
    main()
