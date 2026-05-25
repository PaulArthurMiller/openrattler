"""Google Drive tools for the 41.x integration layer.

Five tool handlers let the main agent list and read files, and create folders
and upload new files, in the user's Google Drive:

  - ``drive_list_files``    — query files by name / type / folder
  - ``drive_list_folders``  — list folders under an optional parent
  - ``drive_read_file``     — read text content of a file (sanitized)
  - ``drive_create_folder`` — create a new folder
  - ``drive_upload_file``   — upload a new file

Read results for listings carry ``trust_level="local"`` (own Drive structure).
File *content* carries ``trust_level="public"`` — a file may contain data from
any external source and is treated as attacker-controlled.

All results are wrapped in a ``ToolResult`` with the structured payload in
``result`` (a ``UniversalMessage``).

SECURITY NOTES
--------------
- ``drive_read_file`` passes all content through ``GoogleContentSanitizer``
  before returning it.  The result carries ``trust_level="public"``.
- Binary / unsupported MIME types are refused with a clear error rather than
  attempting to decode them.
- Large files (exceeding ``config.max_file_bytes``) are refused before any
  download is attempted.
- ``drive_upload_file`` and ``drive_create_folder`` set ``appProperties``
  attribution so assistant-created files are identifiable.
- Google API exceptions are caught and surfaced as ``ToolResult(success=False)``
  — they never propagate raw to the LLM.
- ``trace_id`` from the originating ``ToolCall`` is propagated to every result
  ``UniversalMessage`` for end-to-end audit correlation.
"""

from __future__ import annotations

import io
import logging
from typing import TYPE_CHECKING, Any, Optional

from openrattler.models.agents import TrustLevel
from openrattler.models.audit import AuditEvent
from openrattler.models.messages import create_message
from openrattler.models.tools import ToolDefinition, ToolResult

if TYPE_CHECKING:
    from openrattler.config.loader import GoogleConfig
    from openrattler.integrations.google.client import GoogleClientFactory
    from openrattler.integrations.google.sanitizer import GoogleContentSanitizer
    from openrattler.models.tools import ToolCall
    from openrattler.storage.audit import AuditLog
    from openrattler.tools.registry import ToolRegistry

logger = logging.getLogger(__name__)

_TOOLS_SESSION_KEY = "agent:main:main"
_ATTRIBUTION = "OpenRattler"

# Google Docs MIME type — exported as plain text via the Drive export endpoint.
_GDOC_MIME = "application/vnd.google-apps.document"

# MIME types whose content we can safely decode as text.
_TEXT_MIME_PREFIXES = ("text/",)
_EXPORTABLE_MIMES = frozenset({_GDOC_MIME})


def _is_readable(mime_type: str) -> bool:
    """Return True when *mime_type* is a text type or exportable Google Doc."""
    if mime_type in _EXPORTABLE_MIMES:
        return True
    return any(mime_type.startswith(prefix) for prefix in _TEXT_MIME_PREFIXES)


# ---------------------------------------------------------------------------
# Tool definitions
# ---------------------------------------------------------------------------

DRIVE_LIST_FILES = ToolDefinition(
    name="drive_list_files",
    description=(
        "Query files in Google Drive by name, MIME type, or parent folder. "
        "Returns file names, IDs, MIME types, and sizes. "
        "Note: does not return file content — use drive_read_file for that."
    ),
    parameters={
        "type": "object",
        "properties": {
            "query": {
                "type": "string",
                "description": "Drive query string (e.g. \"name contains 'report'\")",
            },
            "folder_id": {
                "type": "string",
                "description": "Restrict results to a specific folder by Drive folder ID",
            },
            "max_results": {
                "type": "integer",
                "description": "Maximum number of files to return (default: 20)",
                "default": 20,
            },
            "mime_type": {
                "type": "string",
                "description": "Filter by MIME type (e.g. 'application/pdf')",
            },
        },
        "required": [],
    },
    requires_approval=False,
    action_level=5,
    trust_level_required=TrustLevel.main,
    security_notes="Read-only listing. Returns own Drive metadata — trust_level='local'.",
)

DRIVE_LIST_FOLDERS = ToolDefinition(
    name="drive_list_folders",
    description=(
        "List folders in Google Drive, optionally under a specific parent folder. "
        "Returns folder names and IDs."
    ),
    parameters={
        "type": "object",
        "properties": {
            "parent_id": {
                "type": "string",
                "description": "Parent folder Drive ID to list children of (default: Drive root)",
            },
            "max_results": {
                "type": "integer",
                "description": "Maximum number of folders to return (default: 20)",
                "default": 20,
            },
        },
        "required": [],
    },
    requires_approval=False,
    action_level=5,
    trust_level_required=TrustLevel.main,
    security_notes="Read-only listing. Returns own Drive folder structure — trust_level='local'.",
)

DRIVE_READ_FILE = ToolDefinition(
    name="drive_read_file",
    description=(
        "Read the text content of a Google Drive file by file ID. "
        "Supports text files and Google Docs (exported as plain text). "
        "Binary files (PDF, images, etc.) are not supported. "
        "Note: Google Docs exported as plain text lose formatting (headers, bullets, tables)."
    ),
    parameters={
        "type": "object",
        "properties": {
            "file_id": {
                "type": "string",
                "description": "Google Drive file ID",
            },
        },
        "required": ["file_id"],
    },
    requires_approval=False,
    action_level=5,
    trust_level_required=TrustLevel.main,
    security_notes=(
        "Content passes through GoogleContentSanitizer before reaching the agent. "
        "Result carries trust_level='public' — file content may originate from any source."
    ),
)

DRIVE_CREATE_FOLDER = ToolDefinition(
    name="drive_create_folder",
    description=(
        "Create a new folder in Google Drive. "
        "Optionally place it inside an existing parent folder."
    ),
    parameters={
        "type": "object",
        "properties": {
            "name": {
                "type": "string",
                "description": "Name for the new folder",
            },
            "parent_id": {
                "type": "string",
                "description": "Drive folder ID to create this folder inside (default: Drive root)",
            },
        },
        "required": ["name"],
    },
    requires_approval=True,
    action_level=3,
    trust_level_required=TrustLevel.main,
    security_notes=(
        "Write operation — requires human approval. "
        "appProperties attribution set so assistant-created folders are identifiable."
    ),
)

DRIVE_UPLOAD_FILE = ToolDefinition(
    name="drive_upload_file",
    description=(
        "Upload a new file to Google Drive with the given text content. "
        "Optionally place it inside an existing folder."
    ),
    parameters={
        "type": "object",
        "properties": {
            "name": {
                "type": "string",
                "description": "File name for the uploaded file",
            },
            "content": {
                "type": "string",
                "description": "Text content to write to the file",
            },
            "mime_type": {
                "type": "string",
                "description": "MIME type of the file (e.g. 'text/plain', 'text/markdown')",
            },
            "folder_id": {
                "type": "string",
                "description": "Drive folder ID to upload into (default: Drive root)",
            },
        },
        "required": ["name", "content", "mime_type"],
    },
    requires_approval=True,
    action_level=3,
    trust_level_required=TrustLevel.main,
    security_notes=(
        "Write operation — requires human approval. "
        "appProperties attribution set so assistant-created files are identifiable."
    ),
)


# ---------------------------------------------------------------------------
# Handler
# ---------------------------------------------------------------------------


class DriveToolHandler:
    """Handles execution of the five Drive tool definitions.

    Args:
        client:    ``GoogleClientFactory`` providing the Drive API service.
        sanitizer: ``GoogleContentSanitizer`` — applied to all file reads.
        config:    ``GoogleConfig`` carrying limits (max_file_bytes, max_file_chars).
        audit:     Shared audit log.
    """

    def __init__(
        self,
        client: "GoogleClientFactory",
        sanitizer: "GoogleContentSanitizer",
        config: "GoogleConfig",
        audit: "AuditLog",
    ) -> None:
        self._client = client
        self._sanitizer = sanitizer
        self._config = config
        self._audit = audit

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    async def _handle_auth_expired(self, tool_name: str, call_id: str) -> ToolResult:
        """Clear stale credentials and return an actionable error for invalid_grant."""
        logger.warning("%s: Google OAuth invalid_grant detected — clearing credentials.", tool_name)
        self._client.clear_auth()
        await self._audit.log(
            AuditEvent(
                event="google_auth_expired",
                agent_id="drive_tools",
                session_key=_TOOLS_SESSION_KEY,
                details={"tool": tool_name, "error": "invalid_grant"},
            )
        )
        return ToolResult(
            call_id=call_id,
            success=False,
            error=(
                "Google OAuth token has expired (invalid_grant). "
                "Run 'openrattler auth google' to re-authorize. "
                "Drive tools will be unavailable until re-authorized."
            ),
        )

    # ------------------------------------------------------------------
    # Tool handlers
    # ------------------------------------------------------------------

    async def handle_list_files(
        self,
        query: Optional[str] = None,
        folder_id: Optional[str] = None,
        max_results: int = 20,
        mime_type: Optional[str] = None,
        *,
        call_id: str = "",
        trace_id: Optional[str] = None,
    ) -> ToolResult:
        """List Drive files matching optional filters.

        Args:
            query:       Drive query string (e.g. ``"name contains 'report'"``).
            folder_id:   Restrict to a specific folder by ID.
            max_results: Upper bound on returned files.
            mime_type:   Filter by MIME type.
            call_id:     Passed through to ``ToolResult``.
            trace_id:    Propagated to result ``UniversalMessage``.

        Returns:
            ``ToolResult`` with ``params["files"]`` on success, or
            ``ToolResult(success=False)`` on API error.
        """
        q_parts: list[str] = []
        if folder_id:
            q_parts.append(f"'{folder_id}' in parents")
        if mime_type:
            q_parts.append(f"mimeType = '{mime_type}'")
        if query:
            q_parts.append(query)
        q_parts.append("trashed = false")
        q_string = " and ".join(q_parts)

        try:
            svc = await self._client.drive_service()
            response: dict[str, Any] = (
                svc.files()
                .list(
                    q=q_string,
                    pageSize=max_results,
                    fields="files(id,name,mimeType,size,modifiedTime,parents)",
                )
                .execute()
            )
            files = response.get("files", [])
            logger.debug("drive_list_files: returned %d files", len(files))
        except Exception as exc:
            if "invalid_grant" in str(exc):
                return await self._handle_auth_expired("drive_list_files", call_id)
            logger.exception("drive_list_files failed")
            return ToolResult(call_id=call_id, success=False, error=str(exc))

        result_msg = create_message(
            from_agent="drive_tools",
            to_agent="agent:main",
            session_key=_TOOLS_SESSION_KEY,
            type="response",
            operation="drive_list_files",
            trust_level="local",
            params={"files": files},
            trace_id=trace_id,
        )
        return ToolResult(call_id=call_id, success=True, result=result_msg)

    async def handle_list_folders(
        self,
        parent_id: Optional[str] = None,
        max_results: int = 20,
        *,
        call_id: str = "",
        trace_id: Optional[str] = None,
    ) -> ToolResult:
        """List folders in Drive, optionally under *parent_id*.

        Args:
            parent_id:   Restrict to children of this folder ID.
            max_results: Upper bound on returned folders.
            call_id:     Passed through to ``ToolResult``.
            trace_id:    Propagated to result ``UniversalMessage``.

        Returns:
            ``ToolResult`` with ``params["folders"]`` on success, or
            ``ToolResult(success=False)`` on API error.
        """
        q_parts = ["mimeType = 'application/vnd.google-apps.folder'", "trashed = false"]
        if parent_id:
            q_parts.insert(0, f"'{parent_id}' in parents")
        q_string = " and ".join(q_parts)

        try:
            svc = await self._client.drive_service()
            response: dict[str, Any] = (
                svc.files()
                .list(
                    q=q_string,
                    pageSize=max_results,
                    fields="files(id,name,mimeType,modifiedTime,parents)",
                )
                .execute()
            )
            folders = response.get("files", [])
            logger.debug("drive_list_folders: returned %d folders", len(folders))
        except Exception as exc:
            if "invalid_grant" in str(exc):
                return await self._handle_auth_expired("drive_list_folders", call_id)
            logger.exception("drive_list_folders failed")
            return ToolResult(call_id=call_id, success=False, error=str(exc))

        result_msg = create_message(
            from_agent="drive_tools",
            to_agent="agent:main",
            session_key=_TOOLS_SESSION_KEY,
            type="response",
            operation="drive_list_folders",
            trust_level="local",
            params={"folders": folders},
            trace_id=trace_id,
        )
        return ToolResult(call_id=call_id, success=True, result=result_msg)

    async def handle_read_file(
        self,
        file_id: str,
        *,
        call_id: str = "",
        trace_id: Optional[str] = None,
    ) -> ToolResult:
        """Read and sanitize the content of a Drive file.

        Google Docs are exported as ``text/plain``.  Other text/* files are
        downloaded directly.  Binary files are refused with a clear error.
        Files exceeding ``config.max_file_bytes`` are refused before download.

        Args:
            file_id:  Google Drive file ID.
            call_id:  Passed through to ``ToolResult``.
            trace_id: Propagated to result ``UniversalMessage``.

        Returns:
            ``ToolResult`` with ``params["body"]`` (sanitized wrapped text),
            ``params["file_id"]``, ``params["was_truncated"]``, and
            ``params["security_flags"]`` on success;
            ``ToolResult(success=False)`` on error or unsupported type.
        """
        try:
            svc = await self._client.drive_service()

            # Fetch metadata first to check size and MIME type.
            meta: dict[str, Any] = (
                svc.files().get(fileId=file_id, fields="id,name,mimeType,size").execute()
            )
        except Exception as exc:
            if "invalid_grant" in str(exc):
                return await self._handle_auth_expired("drive_read_file", call_id)
            logger.exception("drive_read_file metadata fetch failed: file_id=%s", file_id)
            return ToolResult(call_id=call_id, success=False, error=str(exc))

        mime_type: str = meta.get("mimeType", "")
        file_name: str = meta.get("name", "")

        if not _is_readable(mime_type):
            return ToolResult(
                call_id=call_id,
                success=False,
                error=(
                    "drive_read_file supports text and Google Doc files only — "
                    f"binary file type '{mime_type}' is not supported"
                ),
            )

        # Size check — skip for Google Docs (they have no byte size in metadata).
        if mime_type not in _EXPORTABLE_MIMES:
            size_str = meta.get("size", "0")
            size_bytes = int(size_str) if size_str else 0
            if size_bytes > self._config.max_file_bytes:
                return ToolResult(
                    call_id=call_id,
                    success=False,
                    error=(
                        f"File too large to read: {size_bytes} bytes exceeds "
                        f"max_file_bytes limit of {self._config.max_file_bytes}"
                    ),
                )

        try:
            if mime_type in _EXPORTABLE_MIMES:
                raw_bytes: bytes = (
                    svc.files().export_media(fileId=file_id, mimeType="text/plain").execute()
                )
            else:
                raw_bytes = svc.files().get_media(fileId=file_id).execute()

            raw_text = raw_bytes.decode("utf-8", errors="replace")
            logger.debug(
                "drive_read_file: fetched %d chars from file_id=%s", len(raw_text), file_id
            )
        except Exception as exc:
            if "invalid_grant" in str(exc):
                return await self._handle_auth_expired("drive_read_file", call_id)
            logger.exception("drive_read_file content fetch failed: file_id=%s", file_id)
            return ToolResult(call_id=call_id, success=False, error=str(exc))

        sanitized = await self._sanitizer.sanitize_file_content(raw_text, mime_type)
        wrapped = self._sanitizer.wrap_for_agent(sanitized, "FILE CONTENT")

        result_msg = create_message(
            from_agent="drive_tools",
            to_agent="agent:main",
            session_key=_TOOLS_SESSION_KEY,
            type="response",
            operation="drive_read_file",
            trust_level="public",
            params={
                "file_id": file_id,
                "name": file_name,
                "mime_type": mime_type,
                "body": wrapped,
                "was_truncated": sanitized.was_truncated,
                "security_flags": sanitized.security_flags,
            },
            trace_id=trace_id,
        )
        return ToolResult(call_id=call_id, success=True, result=result_msg)

    async def handle_create_folder(
        self,
        name: str,
        parent_id: Optional[str] = None,
        *,
        call_id: str = "",
        trace_id: Optional[str] = None,
    ) -> ToolResult:
        """Create a new folder in Drive.

        Args:
            name:      Folder name.
            parent_id: Optional parent folder ID; defaults to Drive root.
            call_id:   Passed through to ``ToolResult``.
            trace_id:  Propagated to result ``UniversalMessage``.

        Returns:
            ``ToolResult`` with ``params["folder_id"]`` and ``params["name"]``
            on success, or ``ToolResult(success=False)`` on API error.
        """
        metadata: dict[str, Any] = {
            "name": name,
            "mimeType": "application/vnd.google-apps.folder",
            "appProperties": {"created_by": _ATTRIBUTION},
        }
        if parent_id:
            metadata["parents"] = [parent_id]

        try:
            svc = await self._client.drive_service()
            created: dict[str, Any] = svc.files().create(body=metadata, fields="id,name").execute()
            folder_id: str = created.get("id", "")
            logger.info("drive_create_folder: created folder_id=%s name=%r", folder_id, name)
        except Exception as exc:
            if "invalid_grant" in str(exc):
                return await self._handle_auth_expired("drive_create_folder", call_id)
            logger.exception("drive_create_folder failed: name=%r", name)
            return ToolResult(call_id=call_id, success=False, error=str(exc))

        await self._audit.log(
            AuditEvent(
                event="drive_folder_created",
                agent_id="drive_tools",
                session_key=_TOOLS_SESSION_KEY,
                details={"folder_id": folder_id, "name": name, "parent_id": parent_id},
            )
        )

        result_msg = create_message(
            from_agent="drive_tools",
            to_agent="agent:main",
            session_key=_TOOLS_SESSION_KEY,
            type="response",
            operation="drive_create_folder",
            trust_level="local",
            params={"folder_id": folder_id, "name": name},
            trace_id=trace_id,
        )
        return ToolResult(call_id=call_id, success=True, result=result_msg)

    async def handle_upload_file(
        self,
        name: str,
        content: str,
        mime_type: str,
        folder_id: Optional[str] = None,
        *,
        call_id: str = "",
        trace_id: Optional[str] = None,
    ) -> ToolResult:
        """Upload a new text file to Drive.

        Args:
            name:      File name.
            content:   Text content to write.
            mime_type: MIME type for the uploaded file.
            folder_id: Optional parent folder ID; defaults to Drive root.
            call_id:   Passed through to ``ToolResult``.
            trace_id:  Propagated to result ``UniversalMessage``.

        Returns:
            ``ToolResult`` with ``params["file_id"]`` and ``params["name"]``
            on success, or ``ToolResult(success=False)`` on API error.
        """
        # Import MediaIoBaseUpload lazily so the module is only required when
        # Google integration is enabled.
        from googleapiclient.http import MediaIoBaseUpload

        metadata: dict[str, Any] = {
            "name": name,
            "appProperties": {"created_by": _ATTRIBUTION},
        }
        if folder_id:
            metadata["parents"] = [folder_id]

        media = MediaIoBaseUpload(io.BytesIO(content.encode("utf-8")), mimetype=mime_type)

        try:
            svc = await self._client.drive_service()
            uploaded: dict[str, Any] = (
                svc.files().create(body=metadata, media_body=media, fields="id,name").execute()
            )
            file_id: str = uploaded.get("id", "")
            logger.info(
                "drive_upload_file: uploaded file_id=%s name=%r mime=%s",
                file_id,
                name,
                mime_type,
            )
        except Exception as exc:
            if "invalid_grant" in str(exc):
                return await self._handle_auth_expired("drive_upload_file", call_id)
            logger.exception("drive_upload_file failed: name=%r", name)
            return ToolResult(call_id=call_id, success=False, error=str(exc))

        result_msg = create_message(
            from_agent="drive_tools",
            to_agent="agent:main",
            session_key=_TOOLS_SESSION_KEY,
            type="response",
            operation="drive_upload_file",
            trust_level="local",
            params={"file_id": file_id, "name": name},
            trace_id=trace_id,
        )
        return ToolResult(call_id=call_id, success=True, result=result_msg)


# ---------------------------------------------------------------------------
# Registration
# ---------------------------------------------------------------------------


def register_drive_tools(
    registry: "ToolRegistry",
    handler: DriveToolHandler,
) -> None:
    """Register all five Drive tools with *registry*.

    Called from ``startup.py`` when ``config.google.enabled`` is True.

    Args:
        registry: The ``ToolRegistry`` to register tools into.
        handler:  The ``DriveToolHandler`` whose methods serve as callbacks.
    """
    registry.register(DRIVE_LIST_FILES, handler.handle_list_files)
    registry.register(DRIVE_LIST_FOLDERS, handler.handle_list_folders)
    registry.register(DRIVE_READ_FILE, handler.handle_read_file)
    registry.register(DRIVE_CREATE_FOLDER, handler.handle_create_folder)
    registry.register(DRIVE_UPLOAD_FILE, handler.handle_upload_file)
    logger.info(
        "Drive tools registered: list_files, list_folders, read_file, create_folder, upload_file"
    )
