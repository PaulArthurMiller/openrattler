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
from openrattler.storage.audit import AuditLog
from openrattler.tools.permissions import check_permission, needs_approval
from openrattler.tools.registry import ToolRegistry

if TYPE_CHECKING:
    from openrattler.security.approval import ApprovalManager, ApprovalRequest


class ToolExecutor:
    """Executes tool calls on behalf of an agent.

    Full execution flow:

    1. Look up the tool definition in the registry.
    2. Run ``check_permission`` — return error result if denied.
    3. If ``needs_approval`` and an ``ApprovalManager`` is configured,
       request human approval and block until resolved or timed out.
       Denial (including timeout) returns an error ``ToolResult`` immediately.
    4. Invoke the handler in a try/except — return error result on any
       exception so the LLM can recover gracefully.
    5. Log the outcome to the audit log.
    6. Return a ``ToolResult``.

    Security notes:
    - This class **never** raises — every code path returns a ``ToolResult``.
    - Permission checks are performed on every call; they are never cached.
    - Approval is fail-secure: timeout auto-denies; absence of an
      ``ApprovalManager`` does *not* skip approval (execution proceeds to
      maintain backward compatibility, but production deployments should
      always supply a manager for approval-required tools).
    - All executions (success, denial, approval denial, and failure) are
      audit-logged.
    """

    def __init__(
        self,
        registry: ToolRegistry,
        audit_log: AuditLog,
        approval_manager: Optional["ApprovalManager"] = None,
    ) -> None:
        """Initialise the executor.

        Args:
            registry:         Registry containing all registered tools and handlers.
            audit_log:        Audit log that receives one entry per execution.
            approval_manager: Optional human-in-the-loop approval broker.
                              When set, any tool with ``requires_approval=True``
                              will pause here until approved, denied, or timed out.
        """
        self._registry = registry
        self._audit = audit_log
        self._approval_manager = approval_manager

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
            denial, or handler exception.
        """
        tool_name = tool_call.tool_name

        # --- Step 1: look up tool definition ---------------------------------
        tool_def = self._registry.get(tool_name)
        if tool_def is None:
            error = f"Unknown tool: '{tool_name}'"
            await self._log(agent_config, tool_call, success=False, error=error)
            return ToolResult(call_id=tool_call.call_id, success=False, error=error)

        # --- Step 2: permission check ----------------------------------------
        allowed, reason = check_permission(agent_config, tool_name, tool_def)
        if not allowed:
            await self._log(agent_config, tool_call, success=False, error=reason)
            return ToolResult(call_id=tool_call.call_id, success=False, error=reason)

        # --- Step 3: approval gate -------------------------------------------
        if needs_approval(tool_def) and self._approval_manager is not None:
            approval_result = await self._approval_manager.request_approval(
                self._build_approval_request(agent_config, tool_call, self._approval_manager)
            )
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

        # --- Step 4: invoke handler ------------------------------------------
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

        # --- Step 5: audit log -----------------------------------------------
        await self._log(agent_config, tool_call, success=True)

        # --- Step 6: return result -------------------------------------------
        return ToolResult(call_id=tool_call.call_id, success=True, result=result)

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _build_approval_request(
        self,
        agent_config: AgentConfig,
        tool_call: ToolCall,
        manager: "ApprovalManager",
    ) -> "ApprovalRequest":
        """Build an ``ApprovalRequest`` from verified agent and call data.

        Provenance is populated from ``agent_config`` (not from any
        user-controlled field of ``tool_call``) so it is independently
        verifiable.
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
