"""tshark-backed filtered views over a capture stored in the datalake.

Each view is a fixed display filter plus a fixed set of tshark fields. The
capture is read in place from the datalake: nothing is written to disk. The
functions here are pure (no FastMCP dependency) so they can be tested on their
own; ``vigilant.mcp.server`` wraps them as MCP tools.

Design notes:
    * Output is streamed from tshark and bounded: only ``limit`` rows (after
      ``offset``) are kept in memory, the rest are only counted.
    * tshark is always launched with an argument vector (never a shell), and the
      only caller-controlled strings that reach it are validated first.
    * Callers receive rows plus the filter that produced them, never a filesystem path.
"""

from __future__ import annotations

import asyncio
import json
import logging
import sys
import uuid
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from typing import Final, Literal

from pydantic import BaseModel

from vigilant.mcp.tools.get_pcaps import get_capture_file_path

_TSHARK: Final[str] = "tshark"
_TIMEOUT_S: Final[float] = 120.0
_STREAM_LIMIT_BYTES: Final[int] = 1024 * 1024
_DEFAULT_LIMIT: Final[int] = 100
_MAX_LIMIT: Final[int] = 1000
_MAX_WARNING_CHARS: Final[int] = 300

# One line per view call, parseable with `grep pcap_view_applied`. This is the ground truth of which
# filter was applied, independent of what the LLM says in its answer.
_AUDIT_LOG = logging.getLogger("vigilant.pcap_views")

# Same fact as one plain line on stdout (prefix + JSON). The rich console handler wraps long records over
# several lines, which makes `docker logs` hard to parse; scripts/run_questions.py reads this line instead.
AUDIT_PREFIX: Final[str] = "PCAP_VIEW_APPLIED "
_AUDIT_JSON_LOG = logging.getLogger("vigilant.pcap_views.audit")
_AUDIT_JSON_LOG.setLevel(logging.INFO)
_AUDIT_JSON_LOG.propagate = False
if not _AUDIT_JSON_LOG.handlers:
    _audit_handler = logging.StreamHandler(sys.stdout)
    _audit_handler.setFormatter(logging.Formatter("%(message)s"))
    _AUDIT_JSON_LOG.addHandler(_audit_handler)

ViewName = Literal["ip", "arp", "tcp", "udp"]

BASE_FIELDS = ["frame.number", "frame.time_relative"]
IP_FIELDS = [
    "ip.version",
    "ip.hdr_len",
    "ip.dsfield",
    "ip.len",
    "ip.id",
    "ip.flags",
    "ip.frag_offset",
    "ip.ttl",
    "ip.proto",
    "ip.checksum",
    "ip.src",
    "ip.dst",
]
ARP_FIELDS = [
    "arp.hw.type",
    "arp.proto.type",
    "arp.hw.size",
    "arp.proto.size",
    "arp.opcode",
    "arp.src.hw_mac",
    "arp.src.proto_ipv4",
    "arp.dst.hw_mac",
    "arp.dst.proto_ipv4",
]
TCP_FIELDS = [
    "tcp.srcport",
    "tcp.dstport",
    "tcp.seq",
    "tcp.ack",
    "tcp.flags",
    "tcp.len",
    "tcp.checksum",
    "tcp.window_size",
]
UDP_FIELDS = ["udp.srcport", "udp.dstport", "udp.length", "udp.checksum"]

_IP_PROTO_NAMES: Final[dict[str, str]] = {
    "0": "HOPOPT",
    "1": "ICMP",
    "2": "IGMP",
    "3": "GGP",
    "4": "IP-in-IP (encapsulation)",
    "5": "ST",
    "6": "TCP",
    "7": "CBT",
    "8": "EGP",
    "9": "IGP",
    "10": "BBN-RCC-MON",
    "11": "NVP-II",
    "12": "PUP",
    "13": "ARGUS",
    "14": "EMCON",
    "15": "XNET",
    "16": "CHAOS",
    "17": "UDP",
    "18": "MUX",
    "19": "DCN-MEAS",
    "20": "HMP",
    "21": "PRM",
    "22": "XNS-IDP",
    "23": "TRUNK-1",
    "24": "TRUNK-2",
    "25": "LEAF-1",
    "26": "LEAF-2",
    "27": "RDP",
    "28": "IRTP",
    "29": "ISO-TP4",
    "30": "NETBLT",
    "31": "MFE-NSP",
    "32": "MERIT-INP",
    "33": "DCCP",
    "34": "3PC",
    "35": "IDPR",
    "36": "XTP",
    "37": "DDP",
    "38": "IDPR-CMTP",
    "39": "TP++",
    "40": "IL",
    "41": "IPv6",
    "42": "SDRP",
    "43": "IPv6-Route",
    "44": "IPv6-Frag",
    "45": "IDRP",
    "46": "RSVP",
    "47": "GRE",
    "48": "DSR",
    "49": "BNA",
    "50": "ESP",
    "51": "AH",
    "52": "I-NLSP",
    "53": "SWIPE",
    "54": "NARP",
    "55": "MOBILE",
    "56": "TLSP",
    "57": "SKIP",
    "58": "ICMPv6",
    "59": "IPv6-NoNxt",
    "60": "IPv6-Opts",
    "61": "Any host internal protocol",
    "62": "CFTP",
    "63": "Any local network",
    "64": "SAT-EXPAK",
    "65": "KRYPTOLAN",
    "66": "RVD",
    "67": "IPPC",
    "68": "Any distributed file system",
    "69": "SAT-MON",
    "70": "VISA",
    "71": "IPCV",
    "72": "CPNX",
    "73": "CPHB",
    "74": "WSN",
    "75": "PVP",
    "76": "BR-SAT-MON",
    "77": "SUN-ND",
    "78": "WB-MON",
    "79": "WB-EXPAK",
    "80": "ISO-IP",
    "81": "VMTP",
    "82": "SECURE-VMTP",
    "83": "VINES",
    "84": "TTP/IPTM",
    "85": "NSFNET-IGP",
    "86": "DGP",
    "87": "TCF",
    "88": "EIGRP",
    "89": "OSPF",
    "90": "Sprite-RPC",
    "91": "LARP",
    "92": "MTP",
    "93": "AX.25",
    "94": "IPIP",
    "95": "MICP (deprecated)",
    "96": "SCC-SP",
    "97": "ETHERIP",
    "98": "ENCAP",
    "99": "Any private encryption scheme",
    "100": "GMTP",
    "101": "IFMP",
    "102": "PNNI",
    "103": "PIM",
    "104": "ARIS",
    "105": "SCPS",
    "106": "QNX",
    "107": "A/N",
    "108": "IPComp",
    "109": "SNP",
    "110": "Compaq-Peer",
    "111": "IPX-in-IP",
    "112": "VRRP",
    "113": "PGM",
    "114": "Any 0-hop protocol",
    "115": "L2TP",
    "116": "DDX",
    "117": "IATP",
    "118": "STP",
    "119": "SRP",
    "120": "UTI",
    "121": "SMP",
    "122": "SM (deprecated)",
    "123": "PTP",
    "124": "IS-IS over IPv4",
    "125": "FIRE",
    "126": "CRTP",
    "127": "CRUDP",
    "128": "SSCOPMCE",
    "129": "IPLT",
    "130": "SPS",
    "131": "PIPE",
    "132": "SCTP",
    "133": "FC",
    "134": "RSVP-E2E-IGNORE",
    "135": "Mobility Header",
    "136": "UDPLite",
    "137": "MPLS-in-IP",
    "138": "MANET",
    "139": "HIP",
    "140": "Shim6",
    "141": "WESP",
    "142": "ROHC",
    "253": "Experimentation and testing",
    "254": "Experimentation and testing",
    "255": "Reserved",
}
_TCP_FLAG_BITS = [("FIN", 0x01), ("SYN", 0x02), ("RST", 0x04), ("PSH", 0x08), ("ACK", 0x10), ("URG", 0x20)]
RowFix = Callable[[dict[str, str]], None]


class TsharkError(RuntimeError):
    """tshark is missing, failed, or timed out."""


class PcapFilterResult(BaseModel):
    """A bounded, column-oriented slice of one view of a stored capture."""

    capture_id: uuid.UUID
    view: ViewName
    display_filter: str  # the filter applied to the capture
    columns: list[str]
    rows: list[list[str]]
    matched_count: int
    offset: int
    truncated: bool
    warning: str | None = None


# --------------------------------------------------------------------------- #
# Row post-processing
# --------------------------------------------------------------------------- #


def _fix_ip_proto(row: dict[str, str]) -> None:
    """Replace the numeric IP protocol with its name when known."""
    value = row.get("ip.proto", "")
    if value:
        row["ip.proto"] = _IP_PROTO_NAMES.get(value, value)


def _fix_tcp_flags(row: dict[str, str]) -> None:
    """Render the hex ``tcp.flags`` value as a comma-separated flag list."""
    value = row.get("tcp.flags", "")
    if not value:
        return
    try:
        bits = int(value, 16)
    except ValueError:
        return
    row["tcp.flags"] = ",".join(name for name, mask in _TCP_FLAG_BITS if bits & mask) or "none"


@dataclass(frozen=True, slots=True)
class _ViewSpec:
    fields: tuple[str, ...]
    display_filter: str
    fixes: tuple[RowFix, ...] = ()


_FIELD_VIEWS: Final[dict[str, _ViewSpec]] = {
    "ip": _ViewSpec(
        fields=(*BASE_FIELDS, *IP_FIELDS),
        display_filter="ip",
        fixes=(_fix_ip_proto,),
    ),
    "arp": _ViewSpec(
        fields=(*BASE_FIELDS, *ARP_FIELDS),
        display_filter="arp",
    ),
    # "!icmp && !icmpv6": ICMP errors quote the original TCP/UDP header, and a bare
    # "tcp"/"udp" filter would match that quoted copy. A TCP/UDP packet is one whose
    # OUTER transport is TCP/UDP.
    "tcp": _ViewSpec(
        fields=(*BASE_FIELDS, *TCP_FIELDS),
        display_filter="tcp && !icmp && !icmpv6",
        fixes=(_fix_tcp_flags,),
    ),
    "udp": _ViewSpec(
        fields=(*BASE_FIELDS, *UDP_FIELDS),
        display_filter="udp && !icmp && !icmpv6",
    ),
}


# --------------------------------------------------------------------------- #
# tshark execution
# --------------------------------------------------------------------------- #


async def _run_tshark(args: Sequence[str], *, offset: int, limit: int) -> tuple[list[str], int, str | None]:
    """Run tshark and stream stdout.

    Returns ``(kept_lines, total_lines, warning)`` where ``kept_lines`` holds
    lines ``[offset, offset + limit)`` and ``warning`` is tshark's trimmed
    stderr when it exited non-zero but still produced output (e.g. a capture
    whose last packet was cut short).

    Raises:
        TsharkError: tshark is not installed, timed out, or failed with no output.
    """
    try:
        proc = await asyncio.create_subprocess_exec(
            *args,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            limit=_STREAM_LIMIT_BYTES,
        )
    except FileNotFoundError as exc:
        raise TsharkError("tshark is not installed on the VIGILANT backend") from exc

    if proc.stdout is None or proc.stderr is None:
        raise TsharkError("could not attach to tshark output streams")

    stderr_task = asyncio.create_task(proc.stderr.read())
    kept: list[str] = []
    total = 0
    try:
        async with asyncio.timeout(_TIMEOUT_S):
            async for raw in proc.stdout:
                if offset <= total < offset + limit:
                    kept.append(raw.decode("utf-8", errors="replace").rstrip("\r\n"))
                total += 1
            returncode = await proc.wait()
            stderr = (await stderr_task).decode("utf-8", errors="replace").strip()
    except TimeoutError as exc:
        raise TsharkError(f"tshark timed out after {_TIMEOUT_S:.0f}s") from exc
    finally:
        if proc.returncode is None:
            proc.kill()
            await proc.wait()
        if not stderr_task.done():
            stderr_task.cancel()

    if returncode != 0:
        if total == 0:
            raise TsharkError(f"tshark failed (exit {returncode}): {stderr[:_MAX_WARNING_CHARS]}")
        return kept, total, stderr[:_MAX_WARNING_CHARS] or f"tshark exited with code {returncode}"
    return kept, total, None


def _bounds(offset: int, limit: int) -> tuple[int, int]:
    return max(0, offset), max(1, min(limit, _MAX_LIMIT))


def _result(
    capture_id: uuid.UUID,
    view: ViewName,
    display_filter: str,
    columns: list[str],
    rows: list[list[str]],
    total: int,
    offset: int,
    warning: str | None,
) -> PcapFilterResult:
    _AUDIT_LOG.info(
        "pcap_view_applied capture_id=%s tool=pcap_%s display_filter=%r offset=%d returned=%d matched=%d",
        capture_id,
        view,
        display_filter,
        offset,
        len(rows),
        total,
    )
    _AUDIT_JSON_LOG.info(
        "%s%s",
        AUDIT_PREFIX,
        json.dumps(
            {
                "capture_id": str(capture_id),
                "tool": f"pcap_{view}",
                "display_filter": display_filter,
                "offset": offset,
                "returned": len(rows),
                "matched": total,
            }
        ),
    )
    return PcapFilterResult(
        capture_id=capture_id,
        view=view,
        display_filter=display_filter,
        columns=columns,
        rows=rows,
        matched_count=total,
        offset=offset,
        truncated=total > offset + len(rows),
        warning=warning,
    )


async def _field_view(capture_id: uuid.UUID, view: ViewName, offset: int, limit: int) -> PcapFilterResult:
    spec = _FIELD_VIEWS[view]
    offset, limit = _bounds(offset, limit)
    file_path = await get_capture_file_path(capture_id)

    args = [_TSHARK, "-n", "-r", file_path, "-T", "fields", "-E", "separator=\t", "-E", "occurrence=f"]
    args += ["-Y", spec.display_filter]
    for field in spec.fields:
        args += ["-e", field]

    lines, total, warning = await _run_tshark(args, offset=offset, limit=limit)

    columns = list(spec.fields)
    rows: list[list[str]] = []
    for line in lines:
        cells = line.split("\t")
        cells += [""] * (len(spec.fields) - len(cells))
        row = dict(zip(spec.fields, cells, strict=False))
        for fix in spec.fixes:
            fix(row)
        rows.append([row[c] for c in columns])
    return _result(capture_id, view, spec.display_filter, columns, rows, total, offset, warning)


# --------------------------------------------------------------------------- #
# Public views
# --------------------------------------------------------------------------- #


async def pcap_ip(capture_id: uuid.UUID, offset: int = 0, limit: int = _DEFAULT_LIMIT) -> PcapFilterResult:
    """IPv4 packets with address, protocol name, TTL and length."""
    return await _field_view(capture_id, "ip", offset, limit)


async def pcap_arp(capture_id: uuid.UUID, offset: int = 0, limit: int = _DEFAULT_LIMIT) -> PcapFilterResult:
    """ARP requests and replies with opcode and sender/target MAC and IP."""
    return await _field_view(capture_id, "arp", offset, limit)


async def pcap_tcp(capture_id: uuid.UUID, offset: int = 0, limit: int = _DEFAULT_LIMIT) -> PcapFilterResult:
    """Packets whose outer transport is TCP, with ports, flags, seq/ack and stream."""
    return await _field_view(capture_id, "tcp", offset, limit)


async def pcap_udp(capture_id: uuid.UUID, offset: int = 0, limit: int = _DEFAULT_LIMIT) -> PcapFilterResult:
    """Packets whose outer transport is UDP, with ports, length and stream."""
    return await _field_view(capture_id, "udp", offset, limit)
