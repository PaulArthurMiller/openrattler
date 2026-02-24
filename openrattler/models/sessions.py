"""Session models — session keys, conversation history, and peer context.

Session keys deterministically route messages to isolated storage buckets.
The format encodes the channel, agent, and conversation context so that two
different groups, channels, or DMs can never share state.
"""

from __future__ import annotations

import re
from datetime import datetime, timezone
from typing import Annotated, Literal, Optional

from pydantic import BaseModel, BeforeValidator, Field

from openrattler.models.messages import UniversalMessage

# ---------------------------------------------------------------------------
# SessionKey — validated string type
# ---------------------------------------------------------------------------

_SESSION_KEY_PATTERN = re.compile(r"^[a-zA-Z0-9_-]+(:[a-zA-Z0-9_-]+){2,}$")


def _validate_session_key(v: object) -> str:
    """Validate session key format.

    Valid examples:
    - ``agent:main:main``
    - ``agent:main:telegram:group:123``
    - ``agent:main:subagent:abc-123``

    Security notes:
    - Rejects ``..`` and absolute-path components to prevent path traversal
      when keys are used to derive filesystem paths.
    - Only allows alphanumeric, hyphens, underscores, and colons.
    - Must start with ``agent:`` and have at least three colon-delimited parts.
    """
    if not isinstance(v, str):
        raise ValueError("Session key must be a string")
    if ".." in v:
        raise ValueError("Session key must not contain '..'")
    if v.startswith("/") or v.startswith("\\"):
        raise ValueError("Session key must not be an absolute path")
    if not v.startswith("agent:"):
        raise ValueError("Session key must start with 'agent:'")
    if not _SESSION_KEY_PATTERN.match(v):
        raise ValueError(
            "Session key must match pattern 'agent:<id>:<context>[:<more>]' "
            "using only alphanumeric characters, hyphens, underscores, and colons"
        )
    return v


SessionKey = Annotated[str, BeforeValidator(_validate_session_key)]


# ---------------------------------------------------------------------------
# Peer — channel-specific conversation endpoint
# ---------------------------------------------------------------------------


class Peer(BaseModel):
    """Represents the conversation endpoint within a channel.

    Used by the session router to compute the correct session key.

    - ``dm``:     Direct message — routes to ``agent:<id>:main``
    - ``group``:  Channel/group — routes to ``agent:<id>:<channel>:group:<peer.id>``
    - ``thread``: Thread reply  — extends the parent session key
    """

    kind: Literal["dm", "group", "thread"]
    id: str
    parent: Optional["Peer"] = None


# Pydantic v2 requires an explicit model_rebuild call for self-referential models.
Peer.model_rebuild()


# ---------------------------------------------------------------------------
# Session — in-memory session state
# ---------------------------------------------------------------------------


class Session(BaseModel):
    """Live session state for an active agent conversation.

    Loaded from transcript storage at the start of each turn and written
    back after the turn completes.
    """

    key: SessionKey
    agent_id: str
    history: list[UniversalMessage] = Field(default_factory=list)
    created_at: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc),
        description="When this session was first created",
    )
    updated_at: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc),
        description="When this session was last modified",
    )
