"""Tool permission checking — enforces the agent allowlist/denylist and trust levels.

Every tool invocation passes through ``check_permission`` before execution.
The check is intentionally simple and fast: it never makes network calls or
reads from disk — all data it needs comes from the in-memory
``AgentConfig`` and ``ToolDefinition``.
"""

from __future__ import annotations

from typing import Optional

from openrattler.models.agents import AgentConfig, TrustLevel
from openrattler.models.tools import ToolDefinition

# ---------------------------------------------------------------------------
# Trust level ordering
# ---------------------------------------------------------------------------

#: Numeric order for trust levels.  A tool requiring level N can only be
#: invoked by an agent whose level is >= N.
#:
#: - ``public``   (0) — sandboxed; read-only tools only
#: - ``mcp``      (1) — per-server MCP tools; equivalent to main for ordering
#: - ``main``     (2) — standard personal assistant level
#: - ``security`` (2) — review-only agent; same ordering as main so it can
#:                       use the same memory-review tools
#: - ``local``    (3) — elevated; exec, unrestricted file ops
_TRUST_ORDER: dict[TrustLevel, int] = {
    TrustLevel.public: 0,
    TrustLevel.mcp: 1,
    TrustLevel.main: 2,
    TrustLevel.security: 2,
    TrustLevel.local: 3,
}


# ---------------------------------------------------------------------------
# Permission check
# ---------------------------------------------------------------------------


def check_permission(
    agent_config: AgentConfig,
    tool_name: str,
    tool_def: ToolDefinition,
) -> tuple[bool, Optional[str]]:
    """Return ``(allowed, rejection_reason)`` for an agent/tool pair.

    Rules evaluated in order:

    1. **Denied list**: if ``tool_name`` is in ``agent_config.denied_tools``,
       reject immediately (deny overrides allow).
    2. **Allowed list**: ``tool_name`` must appear in
       ``agent_config.allowed_tools``.  An empty ``allowed_tools`` list means
       *no tools are permitted* (default-deny principle).
    3. **Trust level**: the agent's trust level must be >= the tool's
       ``trust_level_required``.

    Args:
        agent_config: Runtime configuration of the calling agent.
        tool_name:    Name of the tool being requested.
        tool_def:     Registered definition of that tool.

    Returns:
        ``(True, None)`` if permitted; ``(False, reason_string)`` if denied.

    Security notes:
    - Deny list takes absolute precedence — a name in both lists is denied.
    - Empty ``allowed_tools`` denies everything; there is no implicit wildcard.
    - Trust level comparison uses a fixed numeric ordering defined in this
      module — never skip this check.
    """
    # 1. Deny list takes priority over everything.
    if tool_name in agent_config.denied_tools:
        return False, (
            f"Tool '{tool_name}' is explicitly denied for agent " f"'{agent_config.agent_id}'"
        )

    # 2. Must appear in the agent's explicit allowlist.
    if tool_name not in agent_config.allowed_tools:
        return False, (
            f"Tool '{tool_name}' is not in the allowed_tools list for agent "
            f"'{agent_config.agent_id}'"
        )

    # 3. Trust level must be sufficient.
    agent_level = _TRUST_ORDER.get(agent_config.trust_level, 0)
    required_level = _TRUST_ORDER.get(tool_def.trust_level_required, 0)
    if agent_level < required_level:
        return False, (
            f"Tool '{tool_name}' requires trust level "
            f"'{tool_def.trust_level_required.value}' but agent "
            f"'{agent_config.agent_id}' has '{agent_config.trust_level.value}'"
        )

    return True, None


def needs_approval(tool_def: ToolDefinition) -> bool:
    """Return ``True`` if this tool must pause for human approval before execution.

    Security notes:
    - This check is based solely on the tool's registered metadata; it cannot
      be overridden by the calling agent.
    - The actual approval flow is implemented in Piece 16.1 (ApprovalManager).
      Components that call ``execute()`` should check this flag and route
      through the approval manager before invoking the tool handler.
    """
    return tool_def.requires_approval
