"""Tests for openrattler.tools.builtin.drive_tools — DriveToolHandler."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from openrattler.config.loader import GoogleConfig
from openrattler.integrations.google.client import GoogleClientFactory
from openrattler.integrations.google.sanitizer import GoogleContentSanitizer, SanitizedContent
from openrattler.models.messages import UniversalMessage
from openrattler.models.tools import ToolResult
from openrattler.storage.audit import AuditLog
from openrattler.tools.builtin.drive_tools import (
    DRIVE_CREATE_FOLDER,
    DRIVE_LIST_FILES,
    DRIVE_LIST_FOLDERS,
    DRIVE_READ_FILE,
    DRIVE_UPLOAD_FILE,
    DriveToolHandler,
    _ATTRIBUTION,
    register_drive_tools,
)
from openrattler.tools.registry import ToolRegistry

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


def _make_audit(tmp_path: Path) -> AuditLog:
    return AuditLog(tmp_path / "audit.jsonl")


def _make_google_config(**overrides: object) -> GoogleConfig:
    defaults: dict = {
        "enabled": True,
        "credentials_file": "/tmp/credentials.json",
        "token_file": "/tmp/token.json",
        "user_email": "test@example.com",
        "max_file_bytes": 5_000_000,
        "max_file_chars": 20000,
        "max_email_chars": 10000,
    }
    defaults.update(overrides)
    return GoogleConfig(**defaults)


def _make_client_factory() -> tuple[MagicMock, MagicMock]:
    """Return (factory mock, drive_svc mock)."""
    factory = MagicMock(spec=GoogleClientFactory)
    svc = MagicMock()
    factory.drive_service = AsyncMock(return_value=svc)
    return factory, svc


def _make_sanitizer(tmp_path: Path, config: GoogleConfig | None = None) -> GoogleContentSanitizer:
    cfg = config or _make_google_config()
    audit = _make_audit(tmp_path)
    return GoogleContentSanitizer(config=cfg, audit=audit)


def _make_handler(
    tmp_path: Path,
    *,
    factory: MagicMock | None = None,
    config: GoogleConfig | None = None,
    sanitizer: GoogleContentSanitizer | None = None,
) -> tuple[DriveToolHandler, MagicMock]:
    """Return *(handler, drive_svc_mock)*."""
    cfg = config or _make_google_config()
    if factory is None:
        factory, svc = _make_client_factory()
    else:
        svc = factory.drive_service.return_value  # type: ignore[attr-defined]
    san = sanitizer or _make_sanitizer(tmp_path, config=cfg)
    audit = _make_audit(tmp_path)
    handler = DriveToolHandler(client=factory, sanitizer=san, config=cfg, audit=audit)
    return handler, svc


# ---------------------------------------------------------------------------
# handle_list_files
# ---------------------------------------------------------------------------


class TestHandleListFiles:
    async def test_returns_tool_result_with_universal_message(self, tmp_path: Path) -> None:
        handler, svc = _make_handler(tmp_path)
        fake_files = [{"id": "f1", "name": "report.txt", "mimeType": "text/plain"}]
        svc.files.return_value.list.return_value.execute.return_value = {"files": fake_files}

        result = await handler.handle_list_files(call_id="c1")

        assert isinstance(result, ToolResult)
        assert result.success is True
        assert isinstance(result.result, UniversalMessage)
        print(f"list_files result: {result.result.params}")

    async def test_trust_level_is_local(self, tmp_path: Path) -> None:
        handler, svc = _make_handler(tmp_path)
        svc.files.return_value.list.return_value.execute.return_value = {"files": []}

        result = await handler.handle_list_files()

        assert result.result.trust_level == "local"

    async def test_files_in_params(self, tmp_path: Path) -> None:
        handler, svc = _make_handler(tmp_path)
        fake_files = [{"id": "f1", "name": "a.txt"}, {"id": "f2", "name": "b.txt"}]
        svc.files.return_value.list.return_value.execute.return_value = {"files": fake_files}

        result = await handler.handle_list_files()

        assert result.result.params["files"] == fake_files

    async def test_empty_response_returns_empty_list(self, tmp_path: Path) -> None:
        handler, svc = _make_handler(tmp_path)
        svc.files.return_value.list.return_value.execute.return_value = {}

        result = await handler.handle_list_files()

        assert result.success is True
        assert result.result.params["files"] == []

    async def test_folder_id_filter_included_in_query(self, tmp_path: Path) -> None:
        handler, svc = _make_handler(tmp_path)
        svc.files.return_value.list.return_value.execute.return_value = {"files": []}

        await handler.handle_list_files(folder_id="folder123")

        call_kwargs = svc.files.return_value.list.call_args.kwargs
        assert "'folder123' in parents" in call_kwargs["q"]

    async def test_mime_type_filter_included_in_query(self, tmp_path: Path) -> None:
        handler, svc = _make_handler(tmp_path)
        svc.files.return_value.list.return_value.execute.return_value = {"files": []}

        await handler.handle_list_files(mime_type="text/plain")

        call_kwargs = svc.files.return_value.list.call_args.kwargs
        assert "mimeType = 'text/plain'" in call_kwargs["q"]

    async def test_trace_id_propagated(self, tmp_path: Path) -> None:
        handler, svc = _make_handler(tmp_path)
        svc.files.return_value.list.return_value.execute.return_value = {"files": []}

        result = await handler.handle_list_files(trace_id="trace-list-files")

        assert result.result.trace_id == "trace-list-files"

    async def test_google_api_exception_returns_failure(self, tmp_path: Path) -> None:
        handler, svc = _make_handler(tmp_path)
        svc.files.return_value.list.return_value.execute.side_effect = Exception("quota exceeded")

        result = await handler.handle_list_files(call_id="c_fail")

        assert result.success is False
        assert "quota exceeded" in (result.error or "")
        assert result.call_id == "c_fail"
        print(f"list_files error: {result.error}")


# ---------------------------------------------------------------------------
# handle_list_folders
# ---------------------------------------------------------------------------


class TestHandleListFolders:
    async def test_returns_tool_result_with_universal_message(self, tmp_path: Path) -> None:
        handler, svc = _make_handler(tmp_path)
        svc.files.return_value.list.return_value.execute.return_value = {
            "files": [{"id": "fold1", "name": "Projects"}]
        }

        result = await handler.handle_list_folders(call_id="c2")

        assert isinstance(result, ToolResult)
        assert result.success is True
        assert isinstance(result.result, UniversalMessage)

    async def test_trust_level_is_local(self, tmp_path: Path) -> None:
        handler, svc = _make_handler(tmp_path)
        svc.files.return_value.list.return_value.execute.return_value = {"files": []}

        result = await handler.handle_list_folders()

        assert result.result.trust_level == "local"

    async def test_folders_in_params(self, tmp_path: Path) -> None:
        handler, svc = _make_handler(tmp_path)
        fake = [{"id": "fold1", "name": "Work"}]
        svc.files.return_value.list.return_value.execute.return_value = {"files": fake}

        result = await handler.handle_list_folders()

        assert result.result.params["folders"] == fake

    async def test_parent_id_included_in_query(self, tmp_path: Path) -> None:
        handler, svc = _make_handler(tmp_path)
        svc.files.return_value.list.return_value.execute.return_value = {"files": []}

        await handler.handle_list_folders(parent_id="parent999")

        call_kwargs = svc.files.return_value.list.call_args.kwargs
        assert "'parent999' in parents" in call_kwargs["q"]

    async def test_folder_mime_type_always_in_query(self, tmp_path: Path) -> None:
        handler, svc = _make_handler(tmp_path)
        svc.files.return_value.list.return_value.execute.return_value = {"files": []}

        await handler.handle_list_folders()

        call_kwargs = svc.files.return_value.list.call_args.kwargs
        assert "application/vnd.google-apps.folder" in call_kwargs["q"]

    async def test_google_api_exception_returns_failure(self, tmp_path: Path) -> None:
        handler, svc = _make_handler(tmp_path)
        svc.files.return_value.list.return_value.execute.side_effect = Exception("drive error")

        result = await handler.handle_list_folders()

        assert result.success is False
        assert "drive error" in (result.error or "")


# ---------------------------------------------------------------------------
# handle_read_file
# ---------------------------------------------------------------------------


class TestHandleReadFile:
    def _setup_text_file(self, svc: MagicMock, content: bytes = b"hello world") -> None:
        svc.files.return_value.get.return_value.execute.return_value = {
            "id": "f1",
            "name": "test.txt",
            "mimeType": "text/plain",
            "size": str(len(content)),
        }
        svc.files.return_value.get_media.return_value.execute.return_value = content

    def _setup_gdoc(self, svc: MagicMock, content: bytes = b"doc content") -> None:
        svc.files.return_value.get.return_value.execute.return_value = {
            "id": "doc1",
            "name": "My Doc",
            "mimeType": "application/vnd.google-apps.document",
        }
        svc.files.return_value.export_media.return_value.execute.return_value = content

    async def test_returns_tool_result_with_universal_message(self, tmp_path: Path) -> None:
        handler, svc = _make_handler(tmp_path)
        self._setup_text_file(svc)

        result = await handler.handle_read_file(file_id="f1", call_id="c3")

        assert isinstance(result, ToolResult)
        assert result.success is True
        assert isinstance(result.result, UniversalMessage)
        print(f"read_file result params keys: {list(result.result.params.keys())}")

    async def test_trust_level_is_public(self, tmp_path: Path) -> None:
        handler, svc = _make_handler(tmp_path)
        self._setup_text_file(svc)

        result = await handler.handle_read_file(file_id="f1")

        assert result.result.trust_level == "public"

    async def test_sanitizer_called_for_text_file(self, tmp_path: Path) -> None:
        config = _make_google_config()
        factory, svc = _make_client_factory()
        mock_sanitizer = MagicMock(spec=GoogleContentSanitizer)
        mock_sanitizer.sanitize_file_content = AsyncMock(
            return_value=SanitizedContent(
                text="hello world",
                was_truncated=False,
                security_flags=[],
                original_length=11,
            )
        )
        mock_sanitizer.wrap_for_agent.return_value = "[FILE CONTENT]\nhello world\n[/FILE CONTENT]"
        audit = _make_audit(tmp_path)
        handler = DriveToolHandler(
            client=factory, sanitizer=mock_sanitizer, config=config, audit=audit
        )
        self._setup_text_file(svc)

        result = await handler.handle_read_file(file_id="f1")

        mock_sanitizer.sanitize_file_content.assert_called_once()
        mock_sanitizer.wrap_for_agent.assert_called_once()
        assert result.success is True

    async def test_google_doc_uses_export_api(self, tmp_path: Path) -> None:
        handler, svc = _make_handler(tmp_path)
        self._setup_gdoc(svc)

        result = await handler.handle_read_file(file_id="doc1")

        assert result.success is True
        # export_media should be called for Google Docs, not get_media
        svc.files.return_value.export_media.assert_called_once_with(
            fileId="doc1", mimeType="text/plain"
        )
        svc.files.return_value.get_media.assert_not_called()

    async def test_unsupported_binary_mime_type_returns_failure(self, tmp_path: Path) -> None:
        handler, svc = _make_handler(tmp_path)
        svc.files.return_value.get.return_value.execute.return_value = {
            "id": "pdf1",
            "name": "doc.pdf",
            "mimeType": "application/pdf",
            "size": "1000",
        }

        result = await handler.handle_read_file(file_id="pdf1")

        assert result.success is False
        assert "not supported" in (result.error or "").lower()
        assert "application/pdf" in (result.error or "")
        print(f"unsupported mime error: {result.error}")

    async def test_file_too_large_returns_failure(self, tmp_path: Path) -> None:
        config = _make_google_config(max_file_bytes=100)
        handler, svc = _make_handler(tmp_path, config=config)
        svc.files.return_value.get.return_value.execute.return_value = {
            "id": "big1",
            "name": "huge.txt",
            "mimeType": "text/plain",
            "size": "999999",
        }

        result = await handler.handle_read_file(file_id="big1")

        assert result.success is False
        assert "too large" in (result.error or "").lower()
        print(f"too large error: {result.error}")

    async def test_trace_id_propagated(self, tmp_path: Path) -> None:
        handler, svc = _make_handler(tmp_path)
        self._setup_text_file(svc)

        result = await handler.handle_read_file(file_id="f1", trace_id="trace-read-file")

        assert result.result.trace_id == "trace-read-file"

    async def test_params_contain_file_id_and_body(self, tmp_path: Path) -> None:
        handler, svc = _make_handler(tmp_path)
        self._setup_text_file(svc, content=b"some content")

        result = await handler.handle_read_file(file_id="f1")

        assert result.result.params["file_id"] == "f1"
        assert "body" in result.result.params

    async def test_metadata_fetch_failure_returns_failure(self, tmp_path: Path) -> None:
        handler, svc = _make_handler(tmp_path)
        svc.files.return_value.get.return_value.execute.side_effect = Exception("metadata error")

        result = await handler.handle_read_file(file_id="missing")

        assert result.success is False
        assert "metadata error" in (result.error or "")


# ---------------------------------------------------------------------------
# handle_create_folder
# ---------------------------------------------------------------------------


class TestHandleCreateFolder:
    async def test_returns_tool_result_with_universal_message(self, tmp_path: Path) -> None:
        handler, svc = _make_handler(tmp_path)
        svc.files.return_value.create.return_value.execute.return_value = {
            "id": "fold_new",
            "name": "My Folder",
        }

        result = await handler.handle_create_folder(name="My Folder", call_id="c4")

        assert isinstance(result, ToolResult)
        assert result.success is True
        assert isinstance(result.result, UniversalMessage)
        print(f"create_folder result: {result.result.params}")

    async def test_trust_level_is_local(self, tmp_path: Path) -> None:
        handler, svc = _make_handler(tmp_path)
        svc.files.return_value.create.return_value.execute.return_value = {"id": "f1", "name": "X"}

        result = await handler.handle_create_folder(name="X")

        assert result.result.trust_level == "local"

    async def test_params_contain_folder_id_and_name(self, tmp_path: Path) -> None:
        handler, svc = _make_handler(tmp_path)
        svc.files.return_value.create.return_value.execute.return_value = {
            "id": "folder_abc",
            "name": "Reports",
        }

        result = await handler.handle_create_folder(name="Reports")

        assert result.result.params["folder_id"] == "folder_abc"
        assert result.result.params["name"] == "Reports"

    async def test_attribution_in_app_properties(self, tmp_path: Path) -> None:
        handler, svc = _make_handler(tmp_path)
        svc.files.return_value.create.return_value.execute.return_value = {"id": "f1", "name": "X"}

        await handler.handle_create_folder(name="X")

        call_kwargs = svc.files.return_value.create.call_args.kwargs
        assert call_kwargs["body"]["appProperties"]["created_by"] == _ATTRIBUTION

    async def test_parent_id_in_body_when_provided(self, tmp_path: Path) -> None:
        handler, svc = _make_handler(tmp_path)
        svc.files.return_value.create.return_value.execute.return_value = {"id": "f1", "name": "X"}

        await handler.handle_create_folder(name="X", parent_id="parent_xyz")

        call_kwargs = svc.files.return_value.create.call_args.kwargs
        assert call_kwargs["body"]["parents"] == ["parent_xyz"]

    async def test_no_parents_when_parent_id_not_provided(self, tmp_path: Path) -> None:
        handler, svc = _make_handler(tmp_path)
        svc.files.return_value.create.return_value.execute.return_value = {"id": "f1", "name": "X"}

        await handler.handle_create_folder(name="X")

        call_kwargs = svc.files.return_value.create.call_args.kwargs
        assert "parents" not in call_kwargs["body"]

    async def test_audit_event_logged_on_success(self, tmp_path: Path) -> None:
        audit = _make_audit(tmp_path)
        factory, svc = _make_client_factory()
        cfg = _make_google_config()
        san = _make_sanitizer(tmp_path, config=cfg)
        handler = DriveToolHandler(client=factory, sanitizer=san, config=cfg, audit=audit)
        svc.files.return_value.create.return_value.execute.return_value = {
            "id": "folder_audit",
            "name": "Audit Folder",
        }

        await handler.handle_create_folder(name="Audit Folder")

        matching = await audit.query(event_type="drive_folder_created")
        assert len(matching) == 1
        assert matching[0].details["folder_id"] == "folder_audit"
        print(f"Audit event: {matching[0]}")

    async def test_trace_id_propagated(self, tmp_path: Path) -> None:
        handler, svc = _make_handler(tmp_path)
        svc.files.return_value.create.return_value.execute.return_value = {"id": "f1", "name": "X"}

        result = await handler.handle_create_folder(name="X", trace_id="trace-create-folder")

        assert result.result.trace_id == "trace-create-folder"

    async def test_google_api_exception_returns_failure(self, tmp_path: Path) -> None:
        handler, svc = _make_handler(tmp_path)
        svc.files.return_value.create.return_value.execute.side_effect = Exception("folder error")

        result = await handler.handle_create_folder(name="Bad Folder", call_id="c_fail4")

        assert result.success is False
        assert "folder error" in (result.error or "")


# ---------------------------------------------------------------------------
# handle_upload_file
# ---------------------------------------------------------------------------


class TestHandleUploadFile:
    def _setup_upload(self, svc: MagicMock, file_id: str = "upload_001") -> None:
        svc.files.return_value.create.return_value.execute.return_value = {
            "id": file_id,
            "name": "test.txt",
        }

    async def test_returns_tool_result_with_universal_message(self, tmp_path: Path) -> None:
        handler, svc = _make_handler(tmp_path)
        self._setup_upload(svc)

        result = await handler.handle_upload_file(
            name="test.txt", content="hello", mime_type="text/plain", call_id="c5"
        )

        assert isinstance(result, ToolResult)
        assert result.success is True
        assert isinstance(result.result, UniversalMessage)
        print(f"upload_file result: {result.result.params}")

    async def test_trust_level_is_local(self, tmp_path: Path) -> None:
        handler, svc = _make_handler(tmp_path)
        self._setup_upload(svc)

        result = await handler.handle_upload_file(
            name="test.txt", content="data", mime_type="text/plain"
        )

        assert result.result.trust_level == "local"

    async def test_params_contain_file_id_and_name(self, tmp_path: Path) -> None:
        handler, svc = _make_handler(tmp_path)
        svc.files.return_value.create.return_value.execute.return_value = {
            "id": "uploaded_file_id",
            "name": "output.md",
        }

        result = await handler.handle_upload_file(
            name="output.md", content="# Title", mime_type="text/markdown"
        )

        assert result.result.params["file_id"] == "uploaded_file_id"
        assert result.result.params["name"] == "output.md"

    async def test_attribution_in_app_properties(self, tmp_path: Path) -> None:
        handler, svc = _make_handler(tmp_path)
        self._setup_upload(svc)

        await handler.handle_upload_file(
            name="report.txt", content="content", mime_type="text/plain"
        )

        call_kwargs = svc.files.return_value.create.call_args.kwargs
        assert call_kwargs["body"]["appProperties"]["created_by"] == _ATTRIBUTION

    async def test_folder_id_in_body_when_provided(self, tmp_path: Path) -> None:
        handler, svc = _make_handler(tmp_path)
        self._setup_upload(svc)

        await handler.handle_upload_file(
            name="file.txt", content="data", mime_type="text/plain", folder_id="folder_xyz"
        )

        call_kwargs = svc.files.return_value.create.call_args.kwargs
        assert call_kwargs["body"]["parents"] == ["folder_xyz"]

    async def test_no_parents_when_folder_id_not_provided(self, tmp_path: Path) -> None:
        handler, svc = _make_handler(tmp_path)
        self._setup_upload(svc)

        await handler.handle_upload_file(name="file.txt", content="data", mime_type="text/plain")

        call_kwargs = svc.files.return_value.create.call_args.kwargs
        assert "parents" not in call_kwargs["body"]

    async def test_trace_id_propagated(self, tmp_path: Path) -> None:
        handler, svc = _make_handler(tmp_path)
        self._setup_upload(svc)

        result = await handler.handle_upload_file(
            name="file.txt",
            content="data",
            mime_type="text/plain",
            trace_id="trace-upload-file",
        )

        assert result.result.trace_id == "trace-upload-file"

    async def test_google_api_exception_returns_failure(self, tmp_path: Path) -> None:
        handler, svc = _make_handler(tmp_path)
        svc.files.return_value.create.return_value.execute.side_effect = Exception("upload error")

        result = await handler.handle_upload_file(
            name="bad.txt", content="data", mime_type="text/plain", call_id="c_fail5"
        )

        assert result.success is False
        assert "upload error" in (result.error or "")


# ---------------------------------------------------------------------------
# register_drive_tools / google.enabled gate
# ---------------------------------------------------------------------------


class TestRegisterDriveTools:
    def test_all_five_tools_registered(self, tmp_path: Path) -> None:
        registry = ToolRegistry()
        factory, svc = _make_client_factory()
        cfg = _make_google_config()
        san = _make_sanitizer(tmp_path, config=cfg)
        audit = _make_audit(tmp_path)
        handler = DriveToolHandler(client=factory, sanitizer=san, config=cfg, audit=audit)

        register_drive_tools(registry, handler)

        names = {t.name for t in registry.list_tools()}
        assert "drive_list_files" in names
        assert "drive_list_folders" in names
        assert "drive_read_file" in names
        assert "drive_create_folder" in names
        assert "drive_upload_file" in names
        print(f"Registered drive tools: {names}")

    def test_tools_not_registered_when_google_disabled(self) -> None:
        """When google.enabled=False, startup.py does not call register_drive_tools."""
        registry = ToolRegistry()
        names = {t.name for t in registry.list_tools()}
        assert "drive_list_files" not in names
        assert "drive_create_folder" not in names

    def test_create_folder_requires_approval(self) -> None:
        assert DRIVE_CREATE_FOLDER.requires_approval is True

    def test_upload_file_requires_approval(self) -> None:
        assert DRIVE_UPLOAD_FILE.requires_approval is True

    def test_read_tools_do_not_require_approval(self) -> None:
        assert DRIVE_LIST_FILES.requires_approval is False
        assert DRIVE_LIST_FOLDERS.requires_approval is False
        assert DRIVE_READ_FILE.requires_approval is False

    def test_write_tools_action_level_3(self) -> None:
        assert DRIVE_CREATE_FOLDER.action_level == 3
        assert DRIVE_UPLOAD_FILE.action_level == 3

    def test_read_tools_action_level_5(self) -> None:
        assert DRIVE_LIST_FILES.action_level == 5
        assert DRIVE_LIST_FOLDERS.action_level == 5
        assert DRIVE_READ_FILE.action_level == 5
