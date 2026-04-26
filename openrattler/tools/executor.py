"""Tool executor — permission-gated, audit-logged tool invocation.

``ToolExecutor.execute()`` is the single entry point for running any tool.
It enforces permissions, routes approval-required tools through
``ApprovalManager``, catches all handler exceptions (so the LLM always
receives a ``ToolResult`` rather than a traceback), and logs every
invocation to the audit log.
"""

from __future__ import annotations

import asyncio
import inspect
import uuid
from datetime import datetime, timezone
from typing import TYPE_CHECKING, Any, Optional

from openrattler.models.agents import AgentConfig
from openrattler.models.audit import AuditEvent
from openrattler.models.tools import ToolCall, ToolResult
from openrattler.security.action_levels import DEAD_STOP_ACTIONS, DeadStopError
from openrattler.storage.audit import AuditLog
from openrattler.tools.permissions import check_permission, needs_approval
from openrattler.tools.registry import ToolRegistry

if TYPE_CHECKING:
    from openrattler.mcp.bridge import MCPToolBridge
    from openrattler.security.action_levels import ApprovalThresholdPolicy
    from openrattler.security.approval import ApprovalManager, ApprovalRequest


class ToolExecutor:
    """Executes tool calls on behalf of an agent.

    Full execution flow:

    1. Dead-stop check — if the tool name is in ``DEAD_STOP_ACTIONS``, log
       ``dead_stop_blocked`` and return an error ``ToolResult`` immediately.
       This check runs before permission checks and the approval gate.
    2. Look up the tool definition in the registry.
    3. Run ``check_permission`` — return error result if denied.
    4. If MCP tool, delegate to ``MCPToolBridge`` and return.
    5. Check ``needs_approval(tool_def, policy)`` — if approval required and
       an ``ApprovalManager`` is configured, request human approval and block
       until resolved or timed out.  Denial (including timeout) returns an
       error ``ToolResult`` immediately.
    6. If approved, call ``consume_token`` to validate the single-use token.
       An expired or replayed token blocks execution.
    7. Invoke the handler in a try/except — return error result on any
       exception so the LLM can recover gracefully.
    8. Log the outcome to the audit log.
    9. Return a ``ToolResult``.

    Security notes:
    - This class **never** raises — every code path returns a ``ToolResult``.
    - The dead-stop check runs unconditionally before any other gate.
    - Permission checks are performed on every call; they are never cached.
    - Approval is fail-secure: timeout auto-denies; absence of an
      ``ApprovalManager`` does *not* skip approval (execution proceeds to
      maintain backward compatibility, but production deployments should
      always supply a manager for approval-required tools).
    - Token consumption is a second line of defence against replay: even a
      valid approval result is rejected if the token has already been used
      or has expired since the approval was granted.
    - All executions (success, denial, approval denial, dead-stop, and
      failure) are audit-logged.
    """

    def __init__(
        self,
        registry: ToolRegistry,
        audit_log: AuditLog,
        approval_manager: Optional["ApprovalManager"] = None,
        mcp_bridge: Optional["MCPToolBridge"] = None,
        policy: Optional["ApprovalThresholdPolicy"] = None,
        heartbeat_bypass_ops: Optional[frozenset[str]] = None,
    ) -> None:
        """Initialise the executor.

        Args:
            registry:             Registry containing all registered tools and handlers.
            audit_log:            Audit log that receives one entry per execution.
            approval_manager:     Optional human-in-the-loop approval broker.
                                  When set, tools requiring approval will pause here
                                  until approved, denied, or timed out.
            mcp_bridge:           Optional MCP security bridge.  When set, tool calls
                                  whose name starts with ``mcp:`` are routed to the
                                  bridge instead of a local Python handler.
            policy:               Optional ``ApprovalThresholdPolicy`` that maps action
                                  levels to approval requirements.  When provided, it
                                  replaces the legacy ``tool_def.requires_approval``
                                  boolean.  When ``None``, the legacy flag is used
                                  (backward-compat until all callers pass a policy).
            heartbeat_bypass_ops: Frozenset of tool names that are auto-approved
                                  when the requesting session is a heartbeat session
                                  (session_key starts with ``agent:main:heartbeat:``).
                                  Populated from ``HeartbeatConfig.bypass_approval`` at
                                  startup.  ``None`` or empty frozenset disables bypass.
        """
        self._registry = registry
        self._audit = audit_log
        self._approval_manager = approval_manager
        self._mcp_bridge = mcp_bridge
        self._policy = policy
        self._heartbeat_bypass_ops: frozenset[str] = heartbeat_bypass_ops or frozenset()

    async def execute(
        self,
        agent_config: AgentConfig,
        tool_call: ToolCall,
    ) -> ToolResult:
        """Execute *tool_call* on behalf of *agent_config*.

        Args:
            agent_config: Runtime configuration of the requesting agent.
            tool_call:    Tool invocation produced by the LLM.

        Returns:
            A ``ToolResult`` — always, even on permission denial, approval
            denial, dead-stop block, or handler exception.
        """
        tool_name = tool_call.tool_name

        # --- Step 1: dead-stop check -----------------------------------------
        # Runs unconditionally before tool lookup or permission check.
        # DEAD_STOP_ACTIONS is a compile-time frozenset that cannot be overridden
        # by any config key or approval.
        if tool_name in DEAD_STOP_ACTIONS:
            error = str(DeadStopError(tool_name))
            await self._audit.log(
                AuditEvent(
                    event="dead_stop_blocked",
                    agent_id=agent_config.agent_id,
                    session_key=agent_config.session_key,
                    details={
                        "tool": tool_name,
                        "call_id": tool_call.call_id,
                        "trace_id": tool_call.trace_id,
                    },
                )
            )
            return ToolResult(call_id=tool_call.call_id, success=False, error=error)

        # --- Step 2: look up tool definition ---------------------------------
        tool_def = self._registry.get(tool_name)
        if tool_def is None:
            error = f"Unknown tool: '{tool_name}'"
            await self._log(agent_config, tool_call, success=False, error=error)
            return ToolResult(call_id=tool_call.call_id, success=False, error=error)

        # --- Step 3: permission check ----------------------------------------
        allowed, reason = check_permission(agent_config, tool_name, tool_def)
        if not allowed:
            await self._log(agent_config, tool_call, success=False, error=reason)
            return ToolResult(call_id=tool_call.call_id, success=False, error=reason)

        # --- Step 4: MCP routing ---------------------------------------------
        # MCP tools (name starts with "mcp:") are delegated to MCPToolBridge,
        # which runs its own approval gate and audit logging internally.
        if tool_name.startswith("mcp:") and self._mcp_bridge is not None:
            _, remainder = tool_name.split(":", 1)
            server_id, mcp_tool_name = remainder.split(".", 1)
            # Use propagated trace_id when available; otherwise generate a fresh one.
            trace_id = tool_call.trace_id or uuid.uuid4().hex
            try:
                bridge_result = await self._mcp_bridge.execute(
                    server_id=server_id,
                    tool_name=mcp_tool_name,
                    params=tool_call.arguments,
                    agent_config=agent_config,
                    session_key=agent_config.session_key or "",
                    trace_id=trace_id,
                )
            except Exception as exc:
                error = str(exc) or type(exc).__name__
                await self._log(agent_config, tool_call, success=False, error=error)
                return ToolResult(call_id=tool_call.call_id, success=False, error=error)
            await self._log(
                agent_config,
                tool_call,
                success=bridge_result.success,
                error=bridge_result.error,
            )
            return bridge_result

        # --- Step 5: approval gate -------------------------------------------
        # Heartbeat sessions get a pre-authorized bypass for outbound messages
        # and memory writes — the core operations a heartbeat turn needs in order
        # to report results.  Without the bypass the approval gate blocks every
        # write and send, making heartbeat non-functional.
        # The bypass only fires when: (a) the session key identifies a heartbeat
        # run, (b) the specific tool is in the configured bypass set, and
        # (c) bypass is enabled (heartbeat_bypass_ops is non-empty).
        session_key = agent_config.session_key or ""
        is_heartbeat_session = session_key.startswith("agent:main:heartbeat:")
        heartbeat_bypassed = is_heartbeat_session and tool_name in self._heartbeat_bypass_ops

        if (
            needs_approval(tool_def, self._policy)
            and self._approval_manager is not None
            and not heartbeat_bypassed
        ):
            request = self._build_approval_request(
                agent_config, tool_call, self._approval_manager, tool_def.action_level
            )
            approval_result = await self._approval_manager.request_approval(request)
            if not approval_result.approved:
                error = f"Tool '{tool_name}' execution denied by {approval_result.decided_by}"
                await self._log(
                    agent_config,
                    tool_call,
                    success=False,
                    error=error,
                    approval_id=approval_result.approval_id,
                )
                return ToolResult(call_id=tool_call.call_id, success=False, error=error)

            # --- Step 6: token consumption -----------------------------------
            # Single-use token validated immediately before execution.
            # consume_token returns False if the token is expired or replayed.
            if approval_result.approval_token is not None:
                token_valid = self._approval_manager.consume_token(
                    approval_result.approval_token,
                    approval_result.token_expiry,  # type: ignore[arg-type]
                )
                if not token_valid:
                    error = f"Approval token for '{tool_name}' has expired or been replayed"
                    await self._audit.log(
                        AuditEvent(
                            event="approval_token_rejected",
                            agent_id=agent_config.agent_id,
                            session_key=agent_config.session_key,
                            details={
                                "tool": tool_name,
                                "call_id": tool_call.call_id,
                                "approval_id": approval_result.approval_id,
                            },
                        )
                    )
                    return ToolResult(call_id=tool_call.call_id, success=False, error=error)

        # --- Step 7: invoke handler ------------------------------------------
        handler = self._registry.get_handler(tool_name)
        if handler is None:
            error = f"No handler registered for tool '{tool_name}'"
            await self._log(agent_config, tool_call, success=False, error=error)
            return ToolResult(call_id=tool_call.call_id, success=False, error=error)

        try:
            if inspect.iscoroutinefunction(handler):
                result = await handler(**tool_call.arguments)
            else:
                result = await asyncio.to_thread(handler, **tool_call.arguments)
        except Exception as exc:
            error = str(exc) or type(exc).__name__
            await self._log(agent_config, tool_call, success=False, error=error)
            return ToolResult(call_id=tool_call.call_id, success=False, error=error)

        # --- Step 8: audit log -----------------------------------------------
        await self._log(agent_config, tool_call, success=True)

        # --- Step 9: return result -------------------------------------------
        return ToolResult(call_id=tool_call.call_id, success=True, result=result)

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _build_approval_request(
        self,
        agent_config: AgentConfig,
        tool_call: ToolCall,
        manager: "ApprovalManager",
        action_level: int = 5,
    ) -> "ApprovalRequest":
        """Build an ``ApprovalRequest`` from verified agent and call data.

        Provenance is populated from ``agent_config`` (not from any
        user-controlled field of ``tool_call``) so it is independently
        verifiable.  ``action_level`` comes from the tool definition, not the
        agent.  ``rationale`` and ``trace_id`` are taken from ``tool_call``
        when present.
        """
        from openrattler.security.approval import ApprovalRequest

        return ApprovalRequest(
            approval_id=uuid.uuid4().hex,
            operation=tool_call.tool_name,
            context=tool_call.arguments,
            requesting_agent=agent_config.agent_id,
            session_key=agent_config.session_key or "",
            provenance={
                "trust_level": agent_config.trust_level.value,
                "agent_id": agent_config.agent_id,
                "session_key": agent_config.session_key,
                "timestamp": datetime.now(timezone.utc).isoformat(),
            },
            timestamp=datetime.now(timezone.utc),
            timeout_seconds=manager.default_timeout_seconds,
            action_level=action_level,
            rationale=tool_call.rationale,
            trace_id=tool_call.trace_id,
        )

    async def _log(
        self,
        agent_config: AgentConfig,
        tool_call: ToolCall,
        *,
        success: bool,
        error: Optional[str] = None,
        approval_id: Optional[str] = None,
    ) -> None:
        """Append one audit entry for this tool execution."""
        details: dict[str, Any] = {
            "tool": tool_call.tool_name,
            "call_id": tool_call.call_id,
            "success": success,
        }
        if error is not None:
            details["error"] = error
        if approval_id is not None:
            details["approval_id"] = approval_id
        await self._audit.log(
            AuditEvent(
                event="tool_execution",
                agent_id=agent_config.agent_id,
                session_key=agent_config.session_key,
                details=details,
            )
        )
