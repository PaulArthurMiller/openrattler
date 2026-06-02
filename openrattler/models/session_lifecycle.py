"""Session lifecycle event model for tracking open/close transitions.

Each session emits an open event when it starts and a close event when it
ends.  The close event includes token totals and duration so the report
can produce accurate per-session summaries without relying on idle-timeout
heuristics.
"""

from __future__ import annotations

from datetime import datetime
from typing import Literal, Optional

from pydantic import BaseModel


class SessionLifecycleEvent(BaseModel):
    """One open or close event for a session.

    Open events are emitted at session start.  Close events are emitted in
    finally blocks so they fire even when the session ends due to an error.

    Fields:
        event_type:               "open" or "close".
        session_key:              Identifies the session (same key used in TurnRecord).
        session_type:             Semantic type — heartbeat, interactive, or subagent.
        parent_session_key:       Set on subagent sessions to link them to the parent.
        timestamp:                UTC timestamp at which the event was recorded.
        total_prompt_tokens:      Close events only — accumulated prompt tokens.
        total_completion_tokens:  Close events only — accumulated completion tokens.
        duration_seconds:         Close events only — elapsed time since open event.
        close_reason:             Close events only — "completed", "error", or "disconnect".
    """

    event_type: Literal["open", "close"]
    session_key: str
    session_type: str
    parent_session_key: Optional[str] = None
    timestamp: datetime
    total_prompt_tokens: Optional[int] = None
    total_completion_tokens: Optional[int] = None
    duration_seconds: Optional[float] = None
    close_reason: Optional[str] = None


def infer_session_type(session_key: str) -> str:
    """Infer session_type from the session_key format.

    Patterns:
      agent:main:heartbeat:* → "heartbeat"
      agent:main:main         → "interactive"
      agent:research:*        → "subagent_research"
      agent:summarizer:*      → "subagent_research"
      everything else         → "subagent_other"
    """
    parts = session_key.split(":")
    if len(parts) < 3:
        return "subagent_other"

    if parts[1] == "main" and len(parts) >= 4 and parts[2] == "heartbeat":
        return "heartbeat"

    if parts[1] == "main" and len(parts) == 3 and parts[2] == "main":
        return "interactive"

    if parts[1] in ("research", "summarizer"):
        return "subagent_research"

    return "subagent_other"
