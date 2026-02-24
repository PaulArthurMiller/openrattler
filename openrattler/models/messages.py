"""UniversalMessage — the backbone of all OpenRattler inter-component communication.

Every channel, agent, tool, and MCP server exchanges UniversalMessage objects.
This single format enables consistent validation, auditing, and tracing at
every trust boundary.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Any, Literal, Optional

from pydantic import BaseModel, Field

from openrattler.models.errors import ErrorCode

# ---------------------------------------------------------------------------
# Type aliases
# ---------------------------------------------------------------------------

MessageType = Literal["request", "response", "event", "error"]
TrustLevelType = Literal["public", "main", "local", "security", "mcp"]


# ---------------------------------------------------------------------------
# Core model
# ---------------------------------------------------------------------------


class UniversalMessage(BaseModel):
    """Standard message format for all OpenRattler communication.

    Security notes:
    - ``trust_level`` is asserted by the sender and MUST be validated by the
      PitchCatch validator on the receiving side — never trust it blindly.
    - ``params`` and ``metadata`` are arbitrary dicts; validate their contents
      before acting on them.
    - ``trace_id`` ties every hop of a request together; always propagate it
      for end-to-end audit correlation.
    """

    # === Identity ===
    message_id: str = Field(description="Unique message identifier (UUID)")
    from_agent: str = Field(description="Sending component ID")
    to_agent: str = Field(description="Receiving component ID")

    # === Routing ===
    session_key: str = Field(description="Session context for this message")
    channel: Optional[str] = Field(
        default=None,
        description="Originating channel, if the message came from a user",
    )

    # === Content ===
    type: MessageType = Field(description="Message type")
    operation: str = Field(description="What is being requested or responded to")

    # === Payload ===
    params: dict[str, Any] = Field(
        default_factory=dict,
        description="Operation-specific required/optional parameters",
    )
    metadata: dict[str, Any] = Field(
        default_factory=dict,
        description="Context, hints, optional data not required for the operation",
    )

    # === Security ===
    trust_level: TrustLevelType = Field(description="Sender's trust level for permission checks")
    requires_approval: bool = Field(
        default=False,
        description="Whether this operation needs human approval before execution",
    )

    # === Tracking ===
    timestamp: datetime = Field(description="When this message was created (UTC)")
    parent_message_id: Optional[str] = Field(
        default=None,
        description="The message_id this message responds to or continues",
    )
    trace_id: str = Field(
        description="End-to-end request tracking ID shared by all related messages"
    )

    # === Error Handling ===
    error: Optional[dict[str, Any]] = Field(
        default=None,
        description="Error details when type='error'",
    )


# ---------------------------------------------------------------------------
# Factory helpers
# ---------------------------------------------------------------------------


def create_message(
    from_agent: str,
    to_agent: str,
    session_key: str,
    type: MessageType,  # noqa: A002  (shadows builtin intentionally to mirror field name)
    operation: str,
    trust_level: TrustLevelType,
    *,
    channel: Optional[str] = None,
    params: Optional[dict[str, Any]] = None,
    metadata: Optional[dict[str, Any]] = None,
    requires_approval: bool = False,
    trace_id: Optional[str] = None,
    parent_message_id: Optional[str] = None,
    error: Optional[dict[str, Any]] = None,
) -> UniversalMessage:
    """Create a new UniversalMessage with an auto-generated message_id and timestamp.

    ``trace_id`` is auto-generated as a new UUID if not supplied, which starts
    a fresh trace.  Pass an existing ``trace_id`` to continue an in-flight trace.

    Security notes:
    - The caller is responsible for setting an accurate ``trust_level``; it will
      be re-validated by every PitchCatch validator the message passes through.
    """
    return UniversalMessage(
        message_id=str(uuid.uuid4()),
        from_agent=from_agent,
        to_agent=to_agent,
        session_key=session_key,
        channel=channel,
        type=type,
        operation=operation,
        params=params if params is not None else {},
        metadata=metadata if metadata is not None else {},
        trust_level=trust_level,
        requires_approval=requires_approval,
        timestamp=datetime.now(timezone.utc),
        parent_message_id=parent_message_id,
        trace_id=trace_id if trace_id is not None else str(uuid.uuid4()),
        error=error,
    )


def create_response(
    original: UniversalMessage,
    from_agent: str,
    trust_level: TrustLevelType,
    *,
    operation: Optional[str] = None,
    params: Optional[dict[str, Any]] = None,
    metadata: Optional[dict[str, Any]] = None,
    requires_approval: bool = False,
    channel: Optional[str] = None,
) -> UniversalMessage:
    """Create a response to an existing message.

    Automatically sets:
    - ``to_agent`` to the original's ``from_agent``
    - ``parent_message_id`` to the original's ``message_id``
    - ``trace_id`` inherited verbatim from the original (keeps the trace alive)
    - ``type`` to ``"response"``
    - ``operation`` defaults to the original's operation when not supplied

    Security notes:
    - The inherited ``trace_id`` is used for end-to-end audit correlation;
      never generate a new one for a response.
    """
    return UniversalMessage(
        message_id=str(uuid.uuid4()),
        from_agent=from_agent,
        to_agent=original.from_agent,
        session_key=original.session_key,
        channel=channel if channel is not None else original.channel,
        type="response",
        operation=operation if operation is not None else original.operation,
        params=params if params is not None else {},
        metadata=metadata if metadata is not None else {},
        trust_level=trust_level,
        requires_approval=requires_approval,
        timestamp=datetime.now(timezone.utc),
        parent_message_id=original.message_id,
        trace_id=original.trace_id,
        error=None,
    )


def create_error(
    original: UniversalMessage,
    from_agent: str,
    trust_level: TrustLevelType,
    code: ErrorCode,
    message: str,
    details: Optional[dict[str, Any]] = None,
) -> UniversalMessage:
    """Create an error response to an existing message.

    Automatically sets:
    - ``type`` to ``"error"``
    - ``error`` dict with ``code``, ``message``, and ``details``
    - ``parent_message_id`` and ``trace_id`` inherited from the original

    Security notes:
    - ``details`` must not include sensitive internal data (stack traces,
      secrets, internal paths) that could aid an attacker.
    """
    return UniversalMessage(
        message_id=str(uuid.uuid4()),
        from_agent=from_agent,
        to_agent=original.from_agent,
        session_key=original.session_key,
        channel=original.channel,
        type="error",
        operation=original.operation,
        params={},
        metadata={},
        trust_level=trust_level,
        requires_approval=False,
        timestamp=datetime.now(timezone.utc),
        parent_message_id=original.message_id,
        trace_id=original.trace_id,
        error={
            "code": code.value,
            "message": message,
            "details": details if details is not None else {},
        },
    )
