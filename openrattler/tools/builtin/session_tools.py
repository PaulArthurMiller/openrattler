"""Built-in session history tool.

``sessions_history`` lets a main-trust agent retrieve recent transcript
messages from another session.  Because this is cross-session data access, the
tool is flagged ``requires_approval=True`` so the executor will pause for human
sign-off (once Piece 16.1 wires in the ApprovalManager).

SECURITY MODEL
--------------
* Approval required — cross-session reads are high-sensitivity; a human must
  confirm each request before it executes.
* Audit-logged — the ToolExecutor logs every invocation (success and failure)
  regardless of the approval outcome.
* TranscriptStore enforces its own session-key validation; malformed or
  traversal-style keys are rejected there.
* The module-level store reference is ``None`` by default; callers must
  explicitly call ``configure_transcript_store`` before using this tool.
"""

from __future__ import annotations

from typing import Any, Optional

from openrattler.models.agents import TrustLevel
from openrattler.storage.transcripts import TranscriptStore
from openrattler.tools.registry import tool

# ---------------------------------------------------------------------------
# Module-level configuration
# ---------------------------------------------------------------------------

_transcript_store: Optional[TranscriptStore] = None


def configure_transcript_store(store: Optional[TranscriptStore]) -> None:
    """Set the ``TranscriptStore`` instance used by ``sessions_history``.

    Args:
        store: A configured ``TranscriptStore``, or ``None`` to disable access.

    Security note:
        The default is ``None`` (disabled).  Production startup code must call
        this with the application-wide store before the tool can be invoked.
    """
    global _transcript_store
    _transcript_store = store


# ---------------------------------------------------------------------------
# Built-in session tool
# ---------------------------------------------------------------------------


@tool(
    trust_level_required=TrustLevel.main,
    requires_approval=True,
    security_notes=(
        "Cross-session data access. Requires human approval before execution. "
        "Every invocation (approved or denied) is audit-logged by the executor. "
        "Session-key validation is delegated to TranscriptStore."
    ),
)
async def sessions_history(target_session_key: str, n: int = 10) -> list[dict[str, Any]]:
    """Retrieve the *n* most recent messages from another session's transcript.

    Args:
        target_session_key: Session key of the transcript to read
                            (e.g. ``"agent:main:main"``).
        n:                  Maximum number of messages to return (default 10).

    Returns:
        A list of message dicts, oldest first, up to *n* entries.

    SECURITY:
    - Requires human approval before execution (cross-session access).
    - TranscriptStore validates the session key format.
    - Trust level required: main.
    """
    if _transcript_store is None:
        raise RuntimeError(
            "TranscriptStore not configured. "
            "Call configure_transcript_store() before using sessions_history."
        )

    messages = await _transcript_store.load_recent(target_session_key, n)
    return [msg.model_dump() for msg in messages]
