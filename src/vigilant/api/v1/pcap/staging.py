from __future__ import annotations

from vigilant.api.v1.chat_schema import ChatMessage, FilePart, ImagePart, TextPart
from vigilant.api.v1.pcap.utils import UUID_PATTERN, decode_data_uri, looks_like_pcap, read_open_webui_file, stage_bytes


def _stage_pcap_ids_in_text(text: str) -> str:
    """Replace PCAP file ids embedded in Open WebUI's extracted-text payload."""
    staged = text
    for file_id in dict.fromkeys(UUID_PATTERN.findall(text)):
        resolved = read_open_webui_file(file_id)
        if resolved is None:
            continue
        filename, data = resolved
        if not looks_like_pcap(filename, None):
            continue
        ref = stage_bytes(data)
        staged += f"\n[pcap attachment staged: pcap_ref={ref}, filename={filename}]"
    return staged


def stage_pcap_attachments(messages: list[ChatMessage]) -> list[dict[str, object]]:
    """
    Scan messages for pcap-like attachments, write their raw bytes to the
    staging directory, and replace those content parts with a short text
    note the LLM can read and act on directly (no transcription needed).

    Returns plain dicts ready to forward to Hermes (mirrors the previous
    `message.model_dump()` shape used by the router).
    """
    result: list[dict[str, object]] = []

    for message in messages:
        if isinstance(message.content, str):
            result.append({"role": message.role, "content": _stage_pcap_ids_in_text(message.content)})
            continue

        new_parts: list[object] = []
        for part in message.content:
            if isinstance(part, FilePart):
                filename = part.file.filename
                data: bytes | None = None
                if part.file.file_data is not None:
                    data = decode_data_uri(part.file.file_data)
                elif part.file.file_id is not None:
                    resolved = read_open_webui_file(part.file.file_id)
                    if resolved is not None:
                        filename, data = resolved
                if data is not None and looks_like_pcap(filename, None):
                    ref = stage_bytes(data)
                    new_parts.append(
                        {
                            "type": "text",
                            "text": f"[pcap attachment staged: pcap_ref={ref}, filename={filename or 'unknown'}]",
                        }
                    )
                    continue
                new_parts.append(part.model_dump())
            elif isinstance(part, ImagePart):
                data = decode_data_uri(part.image_url.url)
                mime_hint = part.image_url.url.split(";", 1)[0].removeprefix("data:") if data else None
                if data is not None and looks_like_pcap(None, mime_hint):
                    ref = stage_bytes(data)
                    new_parts.append({"type": "text", "text": f"[pcap attachment staged: pcap_ref={ref}]"})
                    continue
                new_parts.append(part.model_dump())
            elif isinstance(part, TextPart):
                new_parts.append(part.model_dump())

        result.append({"role": message.role, "content": new_parts})

    return result
