"""Audit event model for the append-only audit log.

Every security-relevant action — tool calls, permission checks, approvals,
session access — is recorded as an AuditEvent and written to the audit log.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Optional

from pydantic import BaseModel, Field


class AuditEvent(BaseModel):
    """A single security-relevant event in the audit log.

    Security notes:
    - ``details`` must not include raw secrets, API keys, or full file
      contents — include only enough context to reconstruct what happened.
    - ``trace_id`` ties an event back to the originating UniversalMessage
      trace for end-to-end correlation.
    """

    event: str = Field(description="Machine-readable event name, e.g. 'tool_call'")
    timestamp: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc),
        description="When this event occurred (UTC)",
    )
    session_key: Optional[str] = Field(
        default=None,
        description="Session context where the event occurred",
    )
    agent_id: Optional[str] = Field(
        default=None,
        description="Agent that triggered the event",
    )
    details: dict[str, Any] = Field(
        default_factory=dict,
        description="Event-specific context (tool name, args, result status, etc.)",
    )
    trace_id: Optional[str] = Field(
        default=None,
        description="Trace ID linking back to the originating message chain",
    )
