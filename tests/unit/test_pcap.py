import base64
from pathlib import Path

import pytest

from vigilant.api.v1.chat_schema import ChatMessage
from vigilant.api.v1.pcap import staging as pcap_staging
from vigilant.api.v1.pcap import utils as pcap_utils


class TestLooksLikePcap:
    """Detection heuristics for pcap-like attachments."""

    def test_matches_known_extensions(self) -> None:
        assert pcap_utils.looks_like_pcap("capture.pcap", None) is True
        assert pcap_utils.looks_like_pcap("capture.pcapng", None) is True
        assert pcap_utils.looks_like_pcap("capture.cap", None) is True

    def test_rejects_unrelated_extension(self) -> None:
        assert pcap_utils.looks_like_pcap("notes.txt", None) is False

    def test_matches_known_mime_hint(self) -> None:
        assert pcap_utils.looks_like_pcap(None, "application/vnd.tcpdump.pcap") is True
        assert pcap_utils.looks_like_pcap(None, "application/x-pcapng; charset=binary") is True

    def test_rejects_unrelated_mime_hint(self) -> None:
        assert pcap_utils.looks_like_pcap(None, "image/png") is False

    def test_no_filename_or_mime_hint_is_false(self) -> None:
        assert pcap_utils.looks_like_pcap(None, None) is False


class TestDecodeDataUri:
    """Extracting raw bytes from a data: URI."""

    def test_decodes_valid_base64_payload(self) -> None:
        payload = base64.b64encode(b"raw-bytes").decode()
        result = pcap_utils.decode_data_uri(f"data:application/octet-stream;base64,{payload}")

        assert result == b"raw-bytes"

    def test_rejects_non_data_uri(self) -> None:
        assert pcap_utils.decode_data_uri("https://example.com/file.pcap") is None

    def test_rejects_non_base64_data_uri(self) -> None:
        assert pcap_utils.decode_data_uri("data:text/plain,hello") is None

    def test_rejects_malformed_base64(self) -> None:
        assert pcap_utils.decode_data_uri("data:application/octet-stream;base64,not-valid-b64!!!") is None


class TestReadOpenWebuiFile:
    """Resolving an Open WebUI file id against the shared uploads directory."""

    def test_rejects_non_uuid_file_id(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(pcap_utils, "OPEN_WEBUI_UPLOADS_ROOT", tmp_path)

        assert pcap_utils.read_open_webui_file("not-a-uuid") is None

    def test_returns_none_when_file_missing(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(pcap_utils, "OPEN_WEBUI_UPLOADS_ROOT", tmp_path)

        assert pcap_utils.read_open_webui_file("a828a4b2-3023-4603-af46-cfd2e3ec96d5") is None

    def test_resolves_filename_and_bytes(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(pcap_utils, "OPEN_WEBUI_UPLOADS_ROOT", tmp_path)
        file_id = "a828a4b2-3023-4603-af46-cfd2e3ec96d5"
        (tmp_path / f"{file_id}_capture.pcapng").write_bytes(b"pcap-bytes")

        result = pcap_utils.read_open_webui_file(file_id)

        assert result == ("capture.pcapng", b"pcap-bytes")


class TestStageBytes:
    """Persisting raw bytes to the staging store."""

    def test_writes_attachment_and_returns_ref(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(pcap_utils, "STAGING_ROOT", tmp_path)

        ref = pcap_utils.stage_bytes(b"raw-pcap-bytes")

        assert (tmp_path / ref / "attachment.bin").read_bytes() == b"raw-pcap-bytes"


class TestStagePcapAttachments:
    """Orchestration: scanning ChatMessages and staging pcap-like content."""

    def test_plain_text_without_uuid_is_untouched(self) -> None:
        messages = [ChatMessage(role="user", content="hola, ¿qué tal?")]

        result = pcap_staging.stage_pcap_attachments(messages)

        assert result == [{"role": "user", "content": "hola, ¿qué tal?"}]

    def test_uuid_in_text_that_does_not_resolve_is_left_alone(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr(pcap_utils, "OPEN_WEBUI_UPLOADS_ROOT", tmp_path)
        file_id = "a828a4b2-3023-4603-af46-cfd2e3ec96d5"
        text = f"revisa el archivo {file_id}"

        result = pcap_staging.stage_pcap_attachments([ChatMessage(role="user", content=text)])

        assert result == [{"role": "user", "content": text}]

    def test_text_part_passes_through_untouched(self) -> None:
        messages = [
            ChatMessage(role="user", content=[{"type": "text", "text": "analiza esto"}]),
        ]

        result = pcap_staging.stage_pcap_attachments(messages)

        assert result[0]["content"] == [{"type": "text", "text": "analiza esto"}]

    def test_non_pcap_file_part_passes_through_untouched(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(pcap_utils, "STAGING_ROOT", tmp_path)
        payload = base64.b64encode(b"just some text content").decode()
        messages = [
            ChatMessage(
                role="user",
                content=[
                    {
                        "type": "file",
                        "file": {
                            "filename": "notes.txt",
                            "file_data": f"data:text/plain;base64,{payload}",
                        },
                    }
                ],
            ),
        ]

        result = pcap_staging.stage_pcap_attachments(messages)

        content = result[0]["content"]
        assert content[0]["type"] == "file"  # type: ignore[index]

    def test_inline_base64_pcap_file_part_is_staged(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(pcap_utils, "STAGING_ROOT", tmp_path)
        payload = base64.b64encode(b"pcap-bytes").decode()
        messages = [
            ChatMessage(
                role="user",
                content=[
                    {
                        "type": "file",
                        "file": {
                            "filename": "capture.pcapng",
                            "file_data": f"data:application/octet-stream;base64,{payload}",
                        },
                    }
                ],
            ),
        ]

        result = pcap_staging.stage_pcap_attachments(messages)

        text = result[0]["content"][0]["text"]  # type: ignore[index]
        assert "pcap_ref=" in text
        assert "filename=capture.pcapng" in text

    def test_pcap_disguised_as_image_part_is_staged(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(pcap_utils, "STAGING_ROOT", tmp_path)
        payload = base64.b64encode(b"pcap-bytes").decode()
        messages = [
            ChatMessage(
                role="user",
                content=[
                    {
                        "type": "image_url",
                        "image_url": {"url": f"data:application/x-pcapng;base64,{payload}"},
                    }
                ],
            ),
        ]

        result = pcap_staging.stage_pcap_attachments(messages)

        text = result[0]["content"][0]["text"]  # type: ignore[index]
        assert "pcap_ref=" in text

    def test_ordinary_image_part_passes_through_untouched(self) -> None:
        payload = base64.b64encode(b"\x89PNG-fake-bytes").decode()
        messages = [
            ChatMessage(
                role="user",
                content=[
                    {
                        "type": "image_url",
                        "image_url": {"url": f"data:image/png;base64,{payload}"},
                    }
                ],
            ),
        ]

        result = pcap_staging.stage_pcap_attachments(messages)

        content = result[0]["content"]
        assert content[0]["type"] == "image_url"  # type: ignore[index]
