import shutil
import stat
import uuid
from pathlib import Path

import pytest
from mcp.shared.memory import create_connected_server_and_client_session

from vigilant.mcp.server import mcp
from vigilant.mcp.tools import filter_pcaps
from vigilant.mcp.tools.filter_pcaps import (
    PcapFilterResult,
    TsharkError,
    pcap_arp,
    pcap_ip,
    pcap_tcp,
    pcap_udp,
)
from vigilant.mcp.tools.get_pcaps import CaptureNotFoundError

FIXTURES = Path(__file__).parents[2] / "data"


def _fake_tshark(tmp_path: Path, stdout: str = "", stderr: str = "", exit_code: int = 0, sleep: float = 0) -> Path:
    """Create an executable that records its argv and prints canned output."""
    out = tmp_path / "stdout.txt"
    out.write_text(stdout)
    err = tmp_path / "stderr.txt"
    err.write_text(stderr)
    script = tmp_path / "fake-tshark"
    script.write_text(
        "#!/bin/sh\n"
        f'printf "%s\\n" "$@" > "{tmp_path}/argv.txt"\n'
        f"sleep {sleep}\n"
        f'cat "{out}"\n'
        f'cat "{err}" >&2\n'
        f"exit {exit_code}\n"
    )
    script.chmod(script.stat().st_mode | stat.S_IEXEC)
    return script


@pytest.fixture
def capture_id(monkeypatch: pytest.MonkeyPatch) -> uuid.UUID:
    cid = uuid.uuid4()

    async def fake_path(_capture_id: uuid.UUID) -> str:
        return "/data/raw.pcap"

    monkeypatch.setattr(filter_pcaps, "get_capture_file_path", fake_path)
    return cid


def _argv(tmp_path: Path) -> list[str]:
    return (tmp_path / "argv.txt").read_text().splitlines()


async def test_tcp_view_builds_args_and_postprocesses(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capture_id: uuid.UUID
) -> None:
    """The TCP view uses the outer-transport filter and renders flags by name."""
    fields = filter_pcaps._FIELD_VIEWS["tcp"].fields
    cells = dict.fromkeys(fields, "")
    cells.update({"frame.number": "1", "tcp.flags": "0x0012", "tcp.srcport": "443"})
    monkeypatch.setattr(
        filter_pcaps, "_TSHARK", str(_fake_tshark(tmp_path, "\t".join(cells[f] for f in fields) + "\n"))
    )

    result = await pcap_tcp(capture_id)

    argv = _argv(tmp_path)
    assert argv[argv.index("-Y") + 1] == "tcp && !icmp && !icmpv6"
    assert argv[argv.index("-r") + 1] == "/data/raw.pcap"
    row = dict(zip(result.columns, result.rows[0], strict=True))
    assert row["tcp.flags"] == "SYN,ACK"
    assert result.display_filter == "tcp && !icmp && !icmpv6"
    assert row["tcp.srcport"] == "443"
    assert result.matched_count == 1
    assert result.truncated is False


async def test_ip_view_maps_protocol_numbers(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capture_id: uuid.UUID
) -> None:
    """Known IP protocol numbers become names; unknown ones are left as-is."""
    fields = filter_pcaps._FIELD_VIEWS["ip"].fields
    lines = []
    for proto in ("1", "200"):
        cells = dict.fromkeys(fields, "")
        cells["ip.proto"] = proto
        lines.append("\t".join(cells[f] for f in fields))
    monkeypatch.setattr(filter_pcaps, "_TSHARK", str(_fake_tshark(tmp_path, "\n".join(lines) + "\n")))

    result = await pcap_ip(capture_id)

    protos = [dict(zip(result.columns, r, strict=True))["ip.proto"] for r in result.rows]
    assert protos == ["ICMP", "200"]


async def test_arp_and_udp_views_use_their_filters(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capture_id: uuid.UUID
) -> None:
    """ARP and UDP views send the expected display filter."""
    monkeypatch.setattr(filter_pcaps, "_TSHARK", str(_fake_tshark(tmp_path, "1\t0.1\t60\t1\t\t\t\t\n")))
    await pcap_arp(capture_id)
    argv = _argv(tmp_path)
    assert argv[argv.index("-Y") + 1] == "arp"

    await pcap_udp(capture_id)
    argv = _argv(tmp_path)
    assert argv[argv.index("-Y") + 1] == "udp && !icmp && !icmpv6"


async def test_paging_and_truncation(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capture_id: uuid.UUID) -> None:
    """offset/limit select a window; matched_count still counts every line."""
    lines = "".join(f"{i}\t0\t60\ta\tb\t6\t64\t60\n" for i in range(10))
    monkeypatch.setattr(filter_pcaps, "_TSHARK", str(_fake_tshark(tmp_path, lines)))

    result = await pcap_ip(capture_id, offset=2, limit=3)

    assert [r[0] for r in result.rows] == ["2", "3", "4"]
    assert result.matched_count == 10
    assert result.truncated is True
    assert result.offset == 2


async def test_limit_is_clamped(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capture_id: uuid.UUID) -> None:
    """A negative offset and an absurd limit are clamped, not trusted."""
    monkeypatch.setattr(filter_pcaps, "_TSHARK", str(_fake_tshark(tmp_path, "1\t0\t60\ta\tb\t6\t64\t60\n")))

    result = await pcap_ip(capture_id, offset=-5, limit=10**9)

    assert result.offset == 0
    assert len(result.rows) == 1


async def test_nonzero_exit_without_output_is_an_error(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capture_id: uuid.UUID
) -> None:
    """tshark failing with no rows surfaces its stderr."""
    monkeypatch.setattr(filter_pcaps, "_TSHARK", str(_fake_tshark(tmp_path, stderr="bad file", exit_code=2)))

    with pytest.raises(TsharkError, match="bad file"):
        await pcap_ip(capture_id)


async def test_nonzero_exit_with_output_becomes_a_warning(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capture_id: uuid.UUID
) -> None:
    """A cut-short capture still returns its rows plus a warning."""
    monkeypatch.setattr(
        filter_pcaps,
        "_TSHARK",
        str(_fake_tshark(tmp_path, "1\t0\t60\ta\tb\t6\t64\t60\n", stderr="cut short", exit_code=2)),
    )

    result = await pcap_ip(capture_id)

    assert len(result.rows) == 1
    assert result.warning == "cut short"


async def test_nonzero_exit_with_output_and_empty_stderr_still_warns(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capture_id: uuid.UUID
) -> None:
    """The warning falls back to the exit code when stderr is empty."""
    monkeypatch.setattr(
        filter_pcaps, "_TSHARK", str(_fake_tshark(tmp_path, "1\t0\t60\ta\tb\t6\t64\t60\n", exit_code=2))
    )

    result = await pcap_ip(capture_id)

    assert result.warning == "tshark exited with code 2"


async def test_missing_tshark_binary(monkeypatch: pytest.MonkeyPatch, capture_id: uuid.UUID) -> None:
    """A missing tshark executable gives an actionable error."""
    monkeypatch.setattr(filter_pcaps, "_TSHARK", "/nonexistent/tshark")

    with pytest.raises(TsharkError, match="not installed"):
        await pcap_ip(capture_id)


async def test_timeout_kills_tshark(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capture_id: uuid.UUID) -> None:
    """A hung tshark is killed and reported."""
    monkeypatch.setattr(filter_pcaps, "_TSHARK", str(_fake_tshark(tmp_path, sleep=5)))
    monkeypatch.setattr(filter_pcaps, "_TIMEOUT_S", 0.2)

    with pytest.raises(TsharkError, match="timed out"):
        await pcap_ip(capture_id)


async def test_unknown_capture_propagates(monkeypatch: pytest.MonkeyPatch) -> None:
    """The datalake lookup error is not swallowed."""

    async def missing(_capture_id: uuid.UUID) -> str:
        raise CaptureNotFoundError("nope")

    monkeypatch.setattr(filter_pcaps, "get_capture_file_path", missing)

    with pytest.raises(CaptureNotFoundError):
        await pcap_arp(uuid.uuid4())


def test_tcp_flag_fix_ignores_unparseable_and_empty_values() -> None:
    """Flag rendering leaves empty and non-hex values untouched; zero is 'none'."""
    row = {"tcp.flags": ""}
    filter_pcaps._fix_tcp_flags(row)
    assert row["tcp.flags"] == ""
    row = {"tcp.flags": "weird"}
    filter_pcaps._fix_tcp_flags(row)
    assert row["tcp.flags"] == "weird"
    row = {"tcp.flags": "0x0000"}
    filter_pcaps._fix_tcp_flags(row)
    assert row["tcp.flags"] == "none"


async def test_views_are_registered_as_mcp_tools() -> None:
    """Every view is exposed over MCP with a capture_id argument."""
    async with create_connected_server_and_client_session(mcp._mcp_server) as client:
        tools = {t.name: t for t in (await client.list_tools()).tools}

    for name in ("pcap_ip", "pcap_arp", "pcap_tcp", "pcap_udp"):
        assert name in tools
        assert "capture_id" in tools[name].inputSchema["required"]


async def test_mcp_tool_forwards_arguments(monkeypatch: pytest.MonkeyPatch) -> None:
    """The MCP wrapper parses capture_id and forwards paging arguments."""
    from vigilant.mcp import server

    cid = uuid.uuid4()
    seen: dict[str, object] = {}

    async def fake_tcp(capture_id: uuid.UUID, offset: int, limit: int) -> PcapFilterResult:
        seen.update(capture_id=capture_id, offset=offset, limit=limit)
        return PcapFilterResult(
            capture_id=capture_id,
            view="tcp",
            display_filter="tcp && !icmp && !icmpv6",
            columns=[],
            rows=[],
            matched_count=0,
            offset=offset,
            truncated=False,
        )

    monkeypatch.setattr(server, "_pcap_tcp", fake_tcp)

    async with create_connected_server_and_client_session(mcp._mcp_server) as client:
        result = await client.call_tool("pcap_tcp", {"capture_id": str(cid), "offset": 5, "limit": 7})

    assert not result.isError
    assert seen == {"capture_id": cid, "offset": 5, "limit": 7}


async def test_unfiltered_views_are_not_exposed() -> None:
    """Unfiltered views are not registered."""
    async with create_connected_server_and_client_session(mcp._mcp_server) as client:
        names = {t.name for t in (await client.list_tools()).tools}

    assert "pcap_general" not in names
    assert "pcap_wide" not in names


@pytest.mark.parametrize("tool", ["pcap_ip", "pcap_arp", "pcap_tcp", "pcap_udp"])
async def test_mcp_tools_report_invalid_and_unknown_ids(monkeypatch: pytest.MonkeyPatch, tool: str) -> None:
    """Bad UUIDs and unregistered captures surface as tool errors."""

    async def missing(_capture_id: uuid.UUID) -> str:
        raise CaptureNotFoundError("No capture found")

    monkeypatch.setattr(filter_pcaps, "get_capture_file_path", missing)

    async with create_connected_server_and_client_session(mcp._mcp_server) as client:
        bad = await client.call_tool(tool, {"capture_id": "not-a-uuid"})
        unknown = await client.call_tool(tool, {"capture_id": str(uuid.uuid4())})

    assert bad.isError
    assert unknown.isError


@pytest.mark.skipif(shutil.which("tshark") is None, reason="tshark not installed")
async def test_real_tshark_on_fixture(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capture_id: uuid.UUID) -> None:
    """End to end against the real binary and the ARP/ICMP fixture."""
    # Copied to tmp_path: distro AppArmor profiles for tshark may deny reads under the checkout directory.
    local_copy = tmp_path / "arp-icmp.pcapng"
    shutil.copy(FIXTURES / "arp-icmp.pcapng", local_copy)

    async def fixture_path(_capture_id: uuid.UUID) -> str:
        return str(local_copy)

    monkeypatch.setattr(filter_pcaps, "get_capture_file_path", fixture_path)

    arp = await pcap_arp(capture_id)
    ip = await pcap_ip(capture_id)
    tcp = await pcap_tcp(capture_id)

    assert arp.matched_count > 0
    assert arp.display_filter == "arp"
    assert ip.matched_count > 0
    assert tcp.matched_count == 0


def test_view_call_is_audit_logged(caplog: pytest.LogCaptureFixture) -> None:
    """Every view call leaves one parseable log line with the filter, independent of the LLM answer."""
    import logging

    from vigilant.mcp.tools.filter_pcaps import _result

    with caplog.at_level(logging.INFO, logger="vigilant.pcap_views"):
        _result(uuid.uuid4(), "arp", "arp", [], [], 3, 0, None)

    assert "pcap_view_applied" in caplog.text
    assert "tool=pcap_arp" in caplog.text
    assert "display_filter='arp'" in caplog.text


def test_view_call_emits_one_line_json_audit_record() -> None:
    """The plain stdout record is one parseable line: this is what scripts/run_questions.py checks."""
    import json
    import logging

    from vigilant.mcp.tools.filter_pcaps import AUDIT_PREFIX, _result

    class _Collect(logging.Handler):
        def __init__(self) -> None:
            super().__init__()
            self.messages: list[str] = []

        def emit(self, record: logging.LogRecord) -> None:
            self.messages.append(record.getMessage())

    collector = _Collect()
    audit = logging.getLogger("vigilant.pcap_views.audit")
    audit.addHandler(collector)
    capture_id = uuid.uuid4()
    try:
        _result(capture_id, "tcp", "tcp && !icmp && !icmpv6", [], [["1"], ["2"]], 9, 4, None)
    finally:
        audit.removeHandler(collector)

    assert len(collector.messages) == 1
    assert collector.messages[0].startswith(AUDIT_PREFIX)
    assert "\n" not in collector.messages[0]
    assert json.loads(collector.messages[0].removeprefix(AUDIT_PREFIX)) == {
        "capture_id": str(capture_id),
        "tool": "pcap_tcp",
        "display_filter": "tcp && !icmp && !icmpv6",
        "offset": 4,
        "returned": 2,
        "matched": 9,
    }
