from __future__ import annotations

import base64
import binascii
import os
import re
import uuid
from pathlib import Path
from typing import Final

# --- Detection -------------------------------------------------------------

_PCAP_MIME_HINTS: Final[frozenset[str]] = frozenset(
    {"application/vnd.tcpdump.pcap", "application/x-pcapng", "application/octet-stream"}
)
_PCAP_EXTENSIONS: Final[frozenset[str]] = frozenset({".pcap", ".pcapng", ".cap"})

UUID_PATTERN: Final[re.Pattern[str]] = re.compile(
    r"\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}\b"
)


def looks_like_pcap(filename: str | None, mime_hint: str | None) -> bool:
    """Return True if the filename extension or MIME hint suggests a pcap capture."""
    if filename is not None and Path(filename).suffix.lower() in _PCAP_EXTENSIONS:
        return True
    if mime_hint is not None:
        mime = mime_hint.split(";", 1)[0].strip().lower()
        return mime in _PCAP_MIME_HINTS
    return False


# --- Decoding ----------------------------------------------------------------

OPEN_WEBUI_UPLOADS_ROOT: Final[Path] = Path(
    os.environ.get("OPEN_WEBUI_UPLOADS_DIR", "/var/lib/open-webui/data/uploads")
)


def decode_data_uri(data_uri: str) -> bytes | None:
    """Extract raw bytes from a `data:<mime>;base64,<...>` URI.

    Returns None if the URI is not base64-encoded data we can decode.
    """
    if not data_uri.startswith("data:") or ";base64," not in data_uri:
        return None
    _, encoded = data_uri.split(";base64,", 1)
    try:
        return base64.b64decode(encoded, validate=True)
    except (binascii.Error, ValueError):
        return None


def read_open_webui_file(file_id: str) -> tuple[str, bytes] | None:
    """Resolve an Open WebUI file id from the shared uploads directory,
    bypassing Open WebUI's RAG/text-extraction pipeline entirely."""
    try:
        uuid.UUID(file_id)
    except (ValueError, AttributeError):
        return None

    matches = list(OPEN_WEBUI_UPLOADS_ROOT.glob(f"{file_id}_*"))
    if len(matches) != 1 or not matches[0].is_file():
        return None

    filename = matches[0].name.removeprefix(f"{file_id}_")
    return filename, matches[0].read_bytes()


# --- Staging storage ---------------------------------------------------------

STAGING_ROOT: Final[Path] = Path(os.environ.get("VIGILANT_STAGING_DIR", "/var/lib/vigilant/staging"))


def stage_bytes(data: bytes) -> str:
    """Write raw bytes to a fresh staging entry and return its ref id."""
    ref = uuid.uuid4().hex
    entry_dir = STAGING_ROOT / ref
    entry_dir.mkdir(parents=True, exist_ok=False, mode=0o700)
    (entry_dir / "attachment.bin").write_bytes(data)
    return ref


def staged_file_path(file_id: str) -> Path:
    """Return the expected attachment path for a given staging ref."""
    return STAGING_ROOT / file_id / "attachment.bin"
