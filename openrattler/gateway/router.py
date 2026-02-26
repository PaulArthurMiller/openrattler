"""Session router — deterministic mapping from channel/peer context to session key.

The router converts an inbound message's channel, agent, and peer context into
a stable session key.  The same inputs always produce the same key, ensuring
conversation continuity across reconnections and that two different groups or
DMs can never share state.

Session key format:
- DM:     ``agent:{agent_id}:main``
- Group:  ``agent:{agent_id}:{channel}:group:{peer.id}``
- Thread: ``{parent_session_key}:thread:{peer.id}``
"""

from __future__ import annotations

import re
from typing import Any, Optional

from pydantic import BaseModel, Field

from openrattler.models.sessions import Peer

# ---------------------------------------------------------------------------
# Allowlist and validation
# ---------------------------------------------------------------------------

#: Channels recognised by this deployment.  Add new channels here as they are
#: integrated.  Using an explicit allowlist (not a denylist) is intentional —
#: unknown channels are rejected rather than silently accepted.
ALLOWED_CHANNELS: frozenset[str] = frozenset(
    {"cli", "telegram", "slack", "discord", "whatsapp", "mcp"}
)

_SAFE_COMPONENT: re.Pattern[str] = re.compile(r"^[a-zA-Z0-9_-]+$")


def _validate_channel(channel: str) -> None:
    """Reject empty or unknown channel names.

    Security notes:
    - Uses an allowlist — unknown channels raise ``ValueError`` rather than
      being passed through, preventing a forged channel name from polluting
      session key space.
    """
    if not channel:
        raise ValueError("channel must not be empty")
    if channel not in ALLOWED_CHANNELS:
        raise ValueError(
            f"Unknown channel {channel!r}. " f"Allowed channels: {sorted(ALLOWED_CHANNELS)}"
        )


def _validate_agent_id(agent_id: str) -> None:
    """Reject empty or unsafe agent IDs."""
    if not agent_id:
        raise ValueError("agent_id must not be empty")
    if not _SAFE_COMPONENT.match(agent_id):
        raise ValueError(
            f"agent_id contains invalid characters (only alphanumeric, "
            f"hyphens, and underscores allowed): {agent_id!r}"
        )


def _validate_peer_id(peer_id: str) -> None:
    """Reject empty or unsafe peer IDs.

    Security notes:
    - Peer IDs come from external systems (Telegram, Slack, Discord) and are
      embedded in session keys that map to filesystem paths.  Only safe
      characters are permitted.
    """
    if not peer_id:
        raise ValueError("peer.id must not be empty")
    if not _SAFE_COMPONENT.match(peer_id):
        raise ValueError(
            f"peer.id contains invalid characters (only alphanumeric, "
            f"hyphens, and underscores allowed): {peer_id!r}"
        )


# ---------------------------------------------------------------------------
# route_to_session
# ---------------------------------------------------------------------------


def route_to_session(channel: str, agent_id: str, peer: Peer) -> str:
    """Deterministically map a channel/agent/peer context to a session key.

    The same inputs always produce the same session key.  Session keys are
    used to locate transcript files, so this function is the single source
    of truth for session isolation.

    Rules:

    - ``dm``     → ``agent:{agent_id}:main``
    - ``group``  → ``agent:{agent_id}:{channel}:group:{peer.id}``
    - ``thread`` → ``{parent_key}:thread:{peer.id}``
      (resolved recursively from ``peer.parent``)

    Args:
        channel:  The inbound channel name (must be in ``ALLOWED_CHANNELS``).
        agent_id: The agent that owns this session.
        peer:     The conversation context (kind + id, optionally a parent).

    Returns:
        A validated session key string.

    Raises:
        ValueError: If any input fails validation or a thread peer has no
                    parent.

    Security notes:
    - ``channel`` is validated against an explicit allowlist.
    - ``agent_id`` and ``peer.id`` are validated against a safe-character
      pattern before being embedded in the key.
    - Thread recursion inherits all validation from the recursive call so
      every component in a nested key is safe.
    """
    _validate_channel(channel)
    _validate_agent_id(agent_id)
    _validate_peer_id(peer.id)

    if peer.kind == "dm":
        return f"agent:{agent_id}:main"

    if peer.kind == "group":
        return f"agent:{agent_id}:{channel}:group:{peer.id}"

    # peer.kind == "thread"
    if peer.parent is None:
        raise ValueError(
            "Thread peer must have a parent Peer to extend; "
            f"got peer.id={peer.id!r} with no parent"
        )
    parent_key = route_to_session(channel, agent_id, peer.parent)
    return f"{parent_key}:thread:{peer.id}"


# ---------------------------------------------------------------------------
# Binding model
# ---------------------------------------------------------------------------


class Binding(BaseModel):
    """Maps a channel (and optional filters) to a specific agent.

    Bindings are evaluated in order by ``resolve_agent()``; the first
    matching binding wins.  A binding matches when:

    - Its ``channel`` equals the incoming channel.
    - Every non-``None`` filter field (``team_id``, ``guild_id``,
      ``peer_kind``) matches the corresponding value in the caller's
      ``**filters``.

    Examples::

        Binding(channel="slack", team_id="T123", agent_id="work")
        Binding(channel="telegram", peer_kind="dm", agent_id="main")
        Binding(channel="discord", guild_id="456", agent_id="public")
        Binding(channel="cli", agent_id="main")
    """

    channel: str = Field(description="Channel name, e.g. 'slack', 'telegram'")
    agent_id: str = Field(description="Agent to route matching messages to")
    team_id: Optional[str] = Field(
        default=None,
        description="Slack workspace / team ID filter",
    )
    guild_id: Optional[str] = Field(
        default=None,
        description="Discord guild ID filter",
    )
    peer_kind: Optional[str] = Field(
        default=None,
        description="Peer kind filter: 'dm', 'group', or 'thread'",
    )


# ---------------------------------------------------------------------------
# resolve_agent
# ---------------------------------------------------------------------------


def resolve_agent(
    channel: str,
    bindings: list[Binding],
    **filters: Any,
) -> str:
    """Return the agent_id for the first binding matching *channel* and *filters*.

    The function evaluates bindings in order.  A binding matches when its
    ``channel`` field equals the incoming channel and every non-``None``
    filter field on the binding equals the corresponding value in
    ``**filters``.

    Args:
        channel:  The inbound channel name.
        bindings: Ordered list of ``Binding`` objects to search.
        **filters: Optional key/value pairs (e.g. ``team_id="T123"``,
                   ``guild_id="456"``, ``peer_kind="dm"``).

    Returns:
        The ``agent_id`` from the first matching binding.

    Raises:
        ValueError: If ``channel`` is not in ``ALLOWED_CHANNELS`` or no
                    binding matches — fails closed rather than silently
                    routing to a default.

    Security notes:
    - ``channel`` is validated against ``ALLOWED_CHANNELS`` before matching
      so a forged channel name cannot match a binding.
    - Raises on no-match (fail-closed) — never routes to an implicit
      fallback that could bypass the intended permission model.
    """
    _validate_channel(channel)
    for binding in bindings:
        if binding.channel != channel:
            continue
        if binding.team_id is not None and filters.get("team_id") != binding.team_id:
            continue
        if binding.guild_id is not None and filters.get("guild_id") != binding.guild_id:
            continue
        if binding.peer_kind is not None and filters.get("peer_kind") != binding.peer_kind:
            continue
        return binding.agent_id
    raise ValueError(f"No binding found for channel={channel!r} with filters={filters!r}")
