"""Gmail tools for the 41.x integration layer.

Nine tool handlers let the main agent list, read, and organize Gmail threads
and messages:

  - ``gmail_list_threads``   — search/list threads by query
  - ``gmail_read_thread``    — read a thread's full content (MIME-decoded)
  - ``gmail_star_message``   — star or unstar a message
  - ``gmail_mark_important`` — mark or unmark a message as important
  - ``gmail_apply_label``    — apply a label to a thread
  - ``gmail_remove_label``   — remove a label from a thread
  - ``gmail_create_label``   — create a new Gmail label
  - ``gmail_archive``        — archive a thread (remove from INBOX)
  - ``gmail_list_labels``    — list all labels in the mailbox

Read results (thread listings, label lists) carry ``trust_level="local"``
since they reflect the user's own mailbox structure.  Thread *content*
carries ``trust_level="public"`` — email bodies originate from external
senders and are treated as attacker-controlled.

All results are wrapped in a ``ToolResult`` with the structured payload in
``result`` (a ``UniversalMessage``).

SECURITY NOTES
--------------
- ``gmail_read_thread`` passes body content through ``GoogleContentSanitizer``
  before returning it.  The result carries ``trust_level="public"``.
- Subject, From, and Date headers are placed in separate ``params`` keys, NOT
  embedded in the body, so injected text in the body cannot masquerade as
  headers.
- MIME traversal prefers ``text/plain`` over ``text/html``; base64url bodies
  are decoded before sanitization.
- Write operations (archive, label changes, create label) are logged to the
  audit log on success.
- Google API exceptions are caught and surfaced as ``ToolResult(success=False)``
  — they never propagate raw to the LLM.
- ``trace_id`` from the originating ``ToolCall`` is propagated to every result
  ``UniversalMessage`` for end-to-end audit correlation.
"""

from __future__ import annotations

import base64
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

# ---------------------------------------------------------------------------
# Tool definitions
# ---------------------------------------------------------------------------

GMAIL_LIST_THREADS = ToolDefinition(
    name="gmail_list_threads",
    description=(
        "List Gmail threads matching an optional search query. "
        "Returns thread IDs, snippet, and message count. "
        "Use gmail_read_thread to fetch full content for a thread."
    ),
    parameters={
        "type": "object",
        "properties": {
            "query": {
                "type": "string",
                "description": "Gmail search query (e.g. 'from:alice subject:meeting is:unread'). "
                "Defaults to all inbox threads if omitted.",
            },
            "max_results": {
                "type": "integer",
                "description": "Maximum number of threads to return (default: 20)",
                "default": 20,
            },
        },
        "required": [],
    },
    requires_approval=False,
    action_level=5,
    trust_level_required=TrustLevel.main,
    security_notes="Read-only listing. Returns own mailbox thread metadata — trust_level='local'.",
)

GMAIL_READ_THREAD = ToolDefinition(
    name="gmail_read_thread",
    description=(
        "Read the full content of a Gmail thread by thread ID. "
        "Returns subject, sender, date, and sanitized body text. "
        "Prefers plain-text body parts over HTML. "
        "Body content is sanitized for prompt-injection patterns before being returned."
    ),
    parameters={
        "type": "object",
        "properties": {
            "thread_id": {
                "type": "string",
                "description": "Gmail thread ID",
            },
        },
        "required": ["thread_id"],
    },
    requires_approval=False,
    action_level=5,
    trust_level_required=TrustLevel.main,
    security_notes=(
        "Body content passes through GoogleContentSanitizer before reaching the agent. "
        "Result carries trust_level='public' — email body may originate from any external sender."
    ),
)

GMAIL_STAR_MESSAGE = ToolDefinition(
    name="gmail_star_message",
    description="Star or unstar a Gmail message by message ID.",
    parameters={
        "type": "object",
        "properties": {
            "message_id": {
                "type": "string",
                "description": "Gmail message ID",
            },
            "starred": {
                "type": "boolean",
                "description": "True to star; False to unstar",
            },
        },
        "required": ["message_id", "starred"],
    },
    requires_approval=False,
    action_level=3,
    trust_level_required=TrustLevel.main,
    security_notes="Label modification. Audit logged on success.",
)

GMAIL_MARK_IMPORTANT = ToolDefinition(
    name="gmail_mark_important",
    description="Mark or unmark a Gmail message as important.",
    parameters={
        "type": "object",
        "properties": {
            "message_id": {
                "type": "string",
                "description": "Gmail message ID",
            },
            "important": {
                "type": "boolean",
                "description": "True to mark important; False to remove the important flag",
            },
        },
        "required": ["message_id", "important"],
    },
    requires_approval=False,
    action_level=3,
    trust_level_required=TrustLevel.main,
    security_notes="Label modification. Audit logged on success.",
)

GMAIL_APPLY_LABEL = ToolDefinition(
    name="gmail_apply_label",
    description="Apply a label to an entire Gmail thread.",
    parameters={
        "type": "object",
        "properties": {
            "thread_id": {
                "type": "string",
                "description": "Gmail thread ID",
            },
            "label_id": {
                "type": "string",
                "description": "Gmail label ID to apply",
            },
        },
        "required": ["thread_id", "label_id"],
    },
    requires_approval=False,
    action_level=3,
    trust_level_required=TrustLevel.main,
    security_notes="Label modification. Audit logged on success.",
)

GMAIL_REMOVE_LABEL = ToolDefinition(
    name="gmail_remove_label",
    description="Remove a label from an entire Gmail thread.",
    parameters={
        "type": "object",
        "properties": {
            "thread_id": {
                "type": "string",
                "description": "Gmail thread ID",
            },
            "label_id": {
                "type": "string",
                "description": "Gmail label ID to remove",
            },
        },
        "required": ["thread_id", "label_id"],
    },
    requires_approval=False,
    action_level=3,
    trust_level_required=TrustLevel.main,
    security_notes="Label modification. Audit logged on success.",
)

GMAIL_CREATE_LABEL = ToolDefinition(
    name="gmail_create_label",
    description=(
        "Create a new label in the Gmail mailbox. " "Returns the new label's ID and name."
    ),
    parameters={
        "type": "object",
        "properties": {
            "name": {
                "type": "string",
                "description": "Display name for the new label",
            },
            "label_list_visibility": {
                "type": "string",
                "description": "Label list visibility: 'labelShow' or 'labelHide' (default: 'labelShow')",
                "default": "labelShow",
            },
            "message_list_visibility": {
                "type": "string",
                "description": "Message list visibility: 'show' or 'hide' (default: 'show')",
                "default": "show",
            },
        },
        "required": ["name"],
    },
    requires_approval=True,
    action_level=3,
    trust_level_required=TrustLevel.main,
    security_notes="Creates a new mailbox label. Audit logged on success.",
)

GMAIL_ARCHIVE = ToolDefinition(
    name="gmail_archive",
    description=(
        "Archive a Gmail thread by removing it from the INBOX. "
        "The thread is not deleted — it remains searchable in All Mail."
    ),
    parameters={
        "type": "object",
        "properties": {
            "thread_id": {
                "type": "string",
                "description": "Gmail thread ID to archive",
            },
        },
        "required": ["thread_id"],
    },
    requires_approval=True,
    action_level=2,
    trust_level_required=TrustLevel.main,
    security_notes=(
        "Removes INBOX label from thread. Hard to reverse without a 'move to inbox' action. "
        "Audit logged on success."
    ),
)

GMAIL_LIST_LABELS = ToolDefinition(
    name="gmail_list_labels",
    description=(
        "List all labels in the Gmail mailbox (system and user-created). "
        "Returns label IDs and names. Use label IDs with gmail_apply_label and gmail_remove_label."
    ),
    parameters={
        "type": "object",
        "properties": {},
        "required": [],
    },
    requires_approval=False,
    action_level=5,
    trust_level_required=TrustLevel.main,
    security_notes="Read-only. Returns own mailbox label structure — trust_level='local'.",
)


# ---------------------------------------------------------------------------
# MIME body extraction helpers
# ---------------------------------------------------------------------------


def _decode_base64url(data: str) -> str:
    """Decode a base64url-encoded string to UTF-8 text.

    Gmail API encodes all message bodies as base64url.  Padding is added
    before decoding because the API omits trailing ``=`` characters.
    """
    padded = data + "=" * (-len(data) % 4)
    raw_bytes = base64.urlsafe_b64decode(padded)
    return raw_bytes.decode("utf-8", errors="replace")


def _extract_body(payload: dict[str, Any]) -> tuple[str, str]:
    """Walk a Gmail message payload and return *(body_text, mime_type)*.

    Prefers ``text/plain`` parts.  Falls back to ``text/html`` if no
    plain-text part is found.  Handles both single-part and multipart
    messages recursively.

    Returns ``("", "text/plain")`` when no readable body part is found.
    """
    mime_type: str = payload.get("mimeType", "text/plain")
    body_data: str = (payload.get("body") or {}).get("data", "")

    # Single-part message with a body.
    if body_data and not mime_type.startswith("multipart/"):
        return _decode_base64url(body_data), mime_type

    # Multipart: walk parts looking for text/plain first, then text/html.
    parts: list[dict[str, Any]] = payload.get("parts") or []
    plain_text = ""
    html_text = ""
    plain_mime = "text/plain"
    html_mime = "text/html"

    for part in parts:
        part_mime = part.get("mimeType", "")
        if part_mime.startswith("multipart/"):
            # Recurse into nested multipart.
            nested_text, nested_mime = _extract_body(part)
            if nested_text:
                if "html" in nested_mime and not html_text:
                    html_text = nested_text
                    html_mime = nested_mime
                elif not plain_text:
                    plain_text = nested_text
                    plain_mime = nested_mime
        elif part_mime == "text/plain":
            part_data = (part.get("body") or {}).get("data", "")
            if part_data and not plain_text:
                plain_text = _decode_base64url(part_data)
                plain_mime = part_mime
        elif part_mime == "text/html":
            part_data = (part.get("body") or {}).get("data", "")
            if part_data and not html_text:
                html_text = _decode_base64url(part_data)
                html_mime = part_mime

    if plain_text:
        return plain_text, plain_mime
    if html_text:
        return html_text, html_mime
    return "", "text/plain"


def _get_header(headers: list[dict[str, str]], name: str) -> str:
    """Return the first header value matching *name* (case-insensitive)."""
    name_lower = name.lower()
    for h in headers:
        if h.get("name", "").lower() == name_lower:
            return h.get("value", "")
    return ""


# ---------------------------------------------------------------------------
# Handler
# ---------------------------------------------------------------------------


class GmailToolHandler:
    """Handles execution of the nine Gmail tool definitions.

    Args:
        client:    ``GoogleClientFactory`` providing the Gmail API service.
        sanitizer: ``GoogleContentSanitizer`` — applied to all email bodies.
        config:    ``GoogleConfig`` carrying limits (max_email_chars).
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
    # Tool handlers
    # ------------------------------------------------------------------

    async def handle_list_threads(
        self,
        query: Optional[str] = None,
        max_results: int = 20,
        *,
        call_id: str = "",
        trace_id: Optional[str] = None,
    ) -> ToolResult:
        """List Gmail threads matching *query*.

        Args:
            query:       Gmail search query string (optional).
            max_results: Upper bound on returned threads.
            call_id:     Passed through to ``ToolResult``.
            trace_id:    Propagated to result ``UniversalMessage``.

        Returns:
            ``ToolResult`` with ``params["threads"]`` on success.
        """
        try:
            svc = await self._client.gmail_service()
            kwargs: dict[str, Any] = {
                "userId": "me",
                "maxResults": max_results,
            }
            if query:
                kwargs["q"] = query

            response: dict[str, Any] = svc.users().threads().list(**kwargs).execute()
            threads = response.get("threads", [])
            logger.debug("gmail_list_threads: returned %d threads", len(threads))
        except Exception as exc:
            logger.exception("gmail_list_threads failed")
            return ToolResult(call_id=call_id, success=False, error=str(exc))

        result_msg = create_message(
            from_agent="gmail_tools",
            to_agent="agent:main",
            session_key=_TOOLS_SESSION_KEY,
            type="response",
            operation="gmail_list_threads",
            trust_level="local",
            params={"threads": threads},
            trace_id=trace_id,
        )
        return ToolResult(call_id=call_id, success=True, result=result_msg)

    async def handle_read_thread(
        self,
        thread_id: str,
        *,
        call_id: str = "",
        trace_id: Optional[str] = None,
    ) -> ToolResult:
        """Fetch and sanitize a Gmail thread's content.

        Retrieves the thread with ``format='full'``, walks the MIME tree of
        the first message to extract body text (plain preferred over HTML),
        base64url-decodes it, and passes it through ``GoogleContentSanitizer``.

        Metadata headers (Subject, From, Date) are placed in ``params``
        directly, NOT embedded in the body, to prevent header injection.

        Args:
            thread_id: Gmail thread ID.
            call_id:   Passed through to ``ToolResult``.
            trace_id:  Propagated to result ``UniversalMessage``.

        Returns:
            ``ToolResult`` with sanitized ``params["body"]``, separate
            ``params["subject"]``, ``params["from"]``, ``params["date"]``,
            ``params["thread_id"]``, ``params["message_count"]``,
            ``params["was_truncated"]``, and ``params["security_flags"]``.
        """
        try:
            svc = await self._client.gmail_service()
            thread: dict[str, Any] = (
                svc.users().threads().get(userId="me", id=thread_id, format="full").execute()
            )
        except Exception as exc:
            logger.exception("gmail_read_thread failed: thread_id=%s", thread_id)
            return ToolResult(call_id=call_id, success=False, error=str(exc))

        messages: list[dict[str, Any]] = thread.get("messages", [])
        message_count = len(messages)

        # Extract headers from the first (oldest) message.
        first_msg = messages[0] if messages else {}
        first_payload = first_msg.get("payload", {})
        headers: list[dict[str, str]] = first_payload.get("headers", [])

        subject = _get_header(headers, "Subject")
        from_addr = _get_header(headers, "From")
        date = _get_header(headers, "Date")

        # Extract and sanitize the body from the first message.
        raw_body, body_mime = _extract_body(first_payload)
        logger.debug(
            "gmail_read_thread: extracted %d chars (mime=%s) from thread_id=%s",
            len(raw_body),
            body_mime,
            thread_id,
        )

        sanitized = await self._sanitizer.sanitize_email_body(raw_body, body_mime)
        wrapped = self._sanitizer.wrap_for_agent(sanitized, "EMAIL CONTENT")

        result_msg = create_message(
            from_agent="gmail_tools",
            to_agent="agent:main",
            session_key=_TOOLS_SESSION_KEY,
            type="response",
            operation="gmail_read_thread",
            trust_level="public",
            params={
                "thread_id": thread_id,
                "message_count": message_count,
                "subject": subject,
                "from": from_addr,
                "date": date,
                "body": wrapped,
                "was_truncated": sanitized.was_truncated,
                "security_flags": sanitized.security_flags,
            },
            trace_id=trace_id,
        )
        return ToolResult(call_id=call_id, success=True, result=result_msg)

    async def handle_star_message(
        self,
        message_id: str,
        starred: bool,
        *,
        call_id: str = "",
        trace_id: Optional[str] = None,
    ) -> ToolResult:
        """Star or unstar a Gmail message.

        Args:
            message_id: Gmail message ID.
            starred:    True to add STARRED label; False to remove it.
            call_id:    Passed through to ``ToolResult``.
            trace_id:   Propagated to result ``UniversalMessage``.

        Returns:
            ``ToolResult`` with ``params["message_id"]`` on success.
        """
        try:
            svc = await self._client.gmail_service()
            if starred:
                body: dict[str, Any] = {"addLabelIds": ["STARRED"], "removeLabelIds": []}
            else:
                body = {"addLabelIds": [], "removeLabelIds": ["STARRED"]}

            svc.users().messages().modify(userId="me", id=message_id, body=body).execute()
            logger.info("gmail_star_message: message_id=%s starred=%s", message_id, starred)
        except Exception as exc:
            logger.exception("gmail_star_message failed: message_id=%s", message_id)
            return ToolResult(call_id=call_id, success=False, error=str(exc))

        await self._audit.log(
            AuditEvent(
                event="gmail_message_starred",
                agent_id="gmail_tools",
                session_key=_TOOLS_SESSION_KEY,
                details={"message_id": message_id, "starred": starred},
            )
        )

        result_msg = create_message(
            from_agent="gmail_tools",
            to_agent="agent:main",
            session_key=_TOOLS_SESSION_KEY,
            type="response",
            operation="gmail_star_message",
            trust_level="local",
            params={"message_id": message_id, "starred": starred},
            trace_id=trace_id,
        )
        return ToolResult(call_id=call_id, success=True, result=result_msg)

    async def handle_mark_important(
        self,
        message_id: str,
        important: bool,
        *,
        call_id: str = "",
        trace_id: Optional[str] = None,
    ) -> ToolResult:
        """Mark or unmark a Gmail message as important.

        Args:
            message_id: Gmail message ID.
            important:  True to add IMPORTANT label; False to remove it.
            call_id:    Passed through to ``ToolResult``.
            trace_id:   Propagated to result ``UniversalMessage``.

        Returns:
            ``ToolResult`` with ``params["message_id"]`` on success.
        """
        try:
            svc = await self._client.gmail_service()
            if important:
                body: dict[str, Any] = {"addLabelIds": ["IMPORTANT"], "removeLabelIds": []}
            else:
                body = {"addLabelIds": [], "removeLabelIds": ["IMPORTANT"]}

            svc.users().messages().modify(userId="me", id=message_id, body=body).execute()
            logger.info("gmail_mark_important: message_id=%s important=%s", message_id, important)
        except Exception as exc:
            logger.exception("gmail_mark_important failed: message_id=%s", message_id)
            return ToolResult(call_id=call_id, success=False, error=str(exc))

        await self._audit.log(
            AuditEvent(
                event="gmail_message_marked_important",
                agent_id="gmail_tools",
                session_key=_TOOLS_SESSION_KEY,
                details={"message_id": message_id, "important": important},
            )
        )

        result_msg = create_message(
            from_agent="gmail_tools",
            to_agent="agent:main",
            session_key=_TOOLS_SESSION_KEY,
            type="response",
            operation="gmail_mark_important",
            trust_level="local",
            params={"message_id": message_id, "important": important},
            trace_id=trace_id,
        )
        return ToolResult(call_id=call_id, success=True, result=result_msg)

    async def handle_apply_label(
        self,
        thread_id: str,
        label_id: str,
        *,
        call_id: str = "",
        trace_id: Optional[str] = None,
    ) -> ToolResult:
        """Apply a label to a Gmail thread.

        Args:
            thread_id: Gmail thread ID.
            label_id:  Gmail label ID to add.
            call_id:   Passed through to ``ToolResult``.
            trace_id:  Propagated to result ``UniversalMessage``.

        Returns:
            ``ToolResult`` with ``params["thread_id"]`` on success.
        """
        try:
            svc = await self._client.gmail_service()
            svc.users().threads().modify(
                userId="me",
                id=thread_id,
                body={"addLabelIds": [label_id], "removeLabelIds": []},
            ).execute()
            logger.info("gmail_apply_label: thread_id=%s label_id=%s", thread_id, label_id)
        except Exception as exc:
            logger.exception("gmail_apply_label failed: thread_id=%s", thread_id)
            return ToolResult(call_id=call_id, success=False, error=str(exc))

        await self._audit.log(
            AuditEvent(
                event="gmail_label_applied",
                agent_id="gmail_tools",
                session_key=_TOOLS_SESSION_KEY,
                details={"thread_id": thread_id, "label_id": label_id},
            )
        )

        result_msg = create_message(
            from_agent="gmail_tools",
            to_agent="agent:main",
            session_key=_TOOLS_SESSION_KEY,
            type="response",
            operation="gmail_apply_label",
            trust_level="local",
            params={"thread_id": thread_id, "label_id": label_id},
            trace_id=trace_id,
        )
        return ToolResult(call_id=call_id, success=True, result=result_msg)

    async def handle_remove_label(
        self,
        thread_id: str,
        label_id: str,
        *,
        call_id: str = "",
        trace_id: Optional[str] = None,
    ) -> ToolResult:
        """Remove a label from a Gmail thread.

        Args:
            thread_id: Gmail thread ID.
            label_id:  Gmail label ID to remove.
            call_id:   Passed through to ``ToolResult``.
            trace_id:  Propagated to result ``UniversalMessage``.

        Returns:
            ``ToolResult`` with ``params["thread_id"]`` on success.
        """
        try:
            svc = await self._client.gmail_service()
            svc.users().threads().modify(
                userId="me",
                id=thread_id,
                body={"addLabelIds": [], "removeLabelIds": [label_id]},
            ).execute()
            logger.info("gmail_remove_label: thread_id=%s label_id=%s", thread_id, label_id)
        except Exception as exc:
            logger.exception("gmail_remove_label failed: thread_id=%s", thread_id)
            return ToolResult(call_id=call_id, success=False, error=str(exc))

        await self._audit.log(
            AuditEvent(
                event="gmail_label_removed",
                agent_id="gmail_tools",
                session_key=_TOOLS_SESSION_KEY,
                details={"thread_id": thread_id, "label_id": label_id},
            )
        )

        result_msg = create_message(
            from_agent="gmail_tools",
            to_agent="agent:main",
            session_key=_TOOLS_SESSION_KEY,
            type="response",
            operation="gmail_remove_label",
            trust_level="local",
            params={"thread_id": thread_id, "label_id": label_id},
            trace_id=trace_id,
        )
        return ToolResult(call_id=call_id, success=True, result=result_msg)

    async def handle_create_label(
        self,
        name: str,
        label_list_visibility: str = "labelShow",
        message_list_visibility: str = "show",
        *,
        call_id: str = "",
        trace_id: Optional[str] = None,
    ) -> ToolResult:
        """Create a new Gmail label.

        Args:
            name:                     Display name for the new label.
            label_list_visibility:    ``'labelShow'`` or ``'labelHide'``.
            message_list_visibility:  ``'show'`` or ``'hide'``.
            call_id:                  Passed through to ``ToolResult``.
            trace_id:                 Propagated to result ``UniversalMessage``.

        Returns:
            ``ToolResult`` with ``params["label_id"]`` and ``params["name"]``
            on success.
        """
        try:
            svc = await self._client.gmail_service()
            created: dict[str, Any] = (
                svc.users()
                .labels()
                .create(
                    userId="me",
                    body={
                        "name": name,
                        "labelListVisibility": label_list_visibility,
                        "messageListVisibility": message_list_visibility,
                    },
                )
                .execute()
            )
            label_id: str = created.get("id", "")
            logger.info("gmail_create_label: created label_id=%s name=%r", label_id, name)
        except Exception as exc:
            logger.exception("gmail_create_label failed: name=%r", name)
            return ToolResult(call_id=call_id, success=False, error=str(exc))

        await self._audit.log(
            AuditEvent(
                event="gmail_label_created",
                agent_id="gmail_tools",
                session_key=_TOOLS_SESSION_KEY,
                details={"label_id": label_id, "name": name},
            )
        )

        result_msg = create_message(
            from_agent="gmail_tools",
            to_agent="agent:main",
            session_key=_TOOLS_SESSION_KEY,
            type="response",
            operation="gmail_create_label",
            trust_level="local",
            params={"label_id": label_id, "name": name},
            trace_id=trace_id,
        )
        return ToolResult(call_id=call_id, success=True, result=result_msg)

    async def handle_archive(
        self,
        thread_id: str,
        *,
        call_id: str = "",
        trace_id: Optional[str] = None,
    ) -> ToolResult:
        """Archive a Gmail thread by removing the INBOX label.

        Fetches thread metadata first (subject header) for the audit record.

        Args:
            thread_id: Gmail thread ID.
            call_id:   Passed through to ``ToolResult``.
            trace_id:  Propagated to result ``UniversalMessage``.

        Returns:
            ``ToolResult`` with ``params["thread_id"]`` on success.
        """
        subject = ""
        try:
            svc = await self._client.gmail_service()

            # Fetch metadata to capture subject for audit log.
            meta: dict[str, Any] = (
                svc.users()
                .threads()
                .get(userId="me", id=thread_id, format="metadata", metadataHeaders=["Subject"])
                .execute()
            )
            messages: list[dict[str, Any]] = meta.get("messages", [])
            if messages:
                headers = messages[0].get("payload", {}).get("headers", [])
                subject = _get_header(headers, "Subject")

            svc.users().threads().modify(
                userId="me",
                id=thread_id,
                body={"addLabelIds": [], "removeLabelIds": ["INBOX"]},
            ).execute()
            logger.info("gmail_archive: archived thread_id=%s subject=%r", thread_id, subject)
        except Exception as exc:
            logger.exception("gmail_archive failed: thread_id=%s", thread_id)
            return ToolResult(call_id=call_id, success=False, error=str(exc))

        await self._audit.log(
            AuditEvent(
                event="gmail_thread_archived",
                agent_id="gmail_tools",
                session_key=_TOOLS_SESSION_KEY,
                details={"thread_id": thread_id, "subject": subject},
            )
        )

        result_msg = create_message(
            from_agent="gmail_tools",
            to_agent="agent:main",
            session_key=_TOOLS_SESSION_KEY,
            type="response",
            operation="gmail_archive",
            trust_level="local",
            params={"thread_id": thread_id},
            trace_id=trace_id,
        )
        return ToolResult(call_id=call_id, success=True, result=result_msg)

    async def handle_list_labels(
        self,
        *,
        call_id: str = "",
        trace_id: Optional[str] = None,
    ) -> ToolResult:
        """List all Gmail labels (system and user-created).

        Args:
            call_id:  Passed through to ``ToolResult``.
            trace_id: Propagated to result ``UniversalMessage``.

        Returns:
            ``ToolResult`` with ``params["labels"]`` on success.
        """
        try:
            svc = await self._client.gmail_service()
            response: dict[str, Any] = svc.users().labels().list(userId="me").execute()
            labels = response.get("labels", [])
            logger.debug("gmail_list_labels: returned %d labels", len(labels))
        except Exception as exc:
            logger.exception("gmail_list_labels failed")
            return ToolResult(call_id=call_id, success=False, error=str(exc))

        result_msg = create_message(
            from_agent="gmail_tools",
            to_agent="agent:main",
            session_key=_TOOLS_SESSION_KEY,
            type="response",
            operation="gmail_list_labels",
            trust_level="local",
            params={"labels": labels},
            trace_id=trace_id,
        )
        return ToolResult(call_id=call_id, success=True, result=result_msg)


# ---------------------------------------------------------------------------
# Registration
# ---------------------------------------------------------------------------


def register_gmail_tools(
    registry: "ToolRegistry",
    handler: GmailToolHandler,
) -> None:
    """Register all nine Gmail tools with *registry*.

    Called from ``startup.py`` when ``config.google.enabled`` is True.

    Args:
        registry: The ``ToolRegistry`` to register tools into.
        handler:  The ``GmailToolHandler`` whose methods serve as callbacks.
    """
    registry.register(GMAIL_LIST_THREADS, handler.handle_list_threads)
    registry.register(GMAIL_READ_THREAD, handler.handle_read_thread)
    registry.register(GMAIL_STAR_MESSAGE, handler.handle_star_message)
    registry.register(GMAIL_MARK_IMPORTANT, handler.handle_mark_important)
    registry.register(GMAIL_APPLY_LABEL, handler.handle_apply_label)
    registry.register(GMAIL_REMOVE_LABEL, handler.handle_remove_label)
    registry.register(GMAIL_CREATE_LABEL, handler.handle_create_label)
    registry.register(GMAIL_ARCHIVE, handler.handle_archive)
    registry.register(GMAIL_LIST_LABELS, handler.handle_list_labels)
    logger.info(
        "Gmail tools registered: list_threads, read_thread, star_message, mark_important, "
        "apply_label, remove_label, create_label, archive, list_labels"
    )
