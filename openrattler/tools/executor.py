"""Tool executor — permission-gated, audit-logged tool invocation.

``ToolExecutor.execute()`` is the single entry point for running any tool.
It enforces permissions, catches all handler exceptions (so the LLM always
receives a ``ToolResult`` rather than a traceback), and logs every invocation
to the audit log.

The human-in-the-loop approval flow (Piece 16.1) will be wired in by
adding an ``ApprovalManager`` to the executor; the hook is already
documented in the code as a TODO.
"""

from __future__ import annotations

import asyncio
import inspect
from typing import Optional

from openrattler.models.agents import AgentConfig
from openrattler.models.audit import AuditEvent
from openrattler.models.tools import ToolCall, ToolResult
from openrattler.storage.audit import AuditLog
from openrattler.tools.permissions import check_permission, needs_approval
from openrattler.tools.registry import ToolRegistry


class ToolExecutor:
    """Executes tool calls on behalf of an agent.

    Full execution flow:

    1. Look up the tool definition in the registry.
    2. Run ``check_permission`` — return error result if denied.
    3. Check ``needs_approval`` — (TODO Piece 16.1: route through
       ``ApprovalManager`` here; for now, execution proceeds).
    4. Invoke the handler in a try/except — return error result on any
       exception so the LLM can recover gracefully.
    5. Log the outcome to the audit log.
    6. Return a ``ToolResult``.

    Security notes:
    - This class **never** raises — every code path returns a ``ToolResult``.
    - Permission checks are performed on every call; they are never cached.
    - All executions (success and failure) are audit-logged.
    """

    def __init__(self, registry: ToolRegistry, audit_log: AuditLog) -> None:
        """Initialise the executor.

        Args:
            registry:  Registry containing all registered tools and handlers.
            audit_log: Audit log that receives one entry per execution.
        """
        self._registry = registry
        self._audit = audit_log

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
            A ``ToolResult`` — always, even on permission denial or exception.
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

        # --- Step 3: approval check (stub — wired up in Piece 16.1) ----------
        # TODO(Piece 16.1): if needs_approval(tool_def), route through
        #   ApprovalManager.request_approval() before proceeding.
        #   For now, execution continues so the framework can be tested
        #   end-to-end without a running approval manager.
        _ = needs_approval(tool_def)  # evaluated but not yet acted upon

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

    async def _log(
        self,
        agent_config: AgentConfig,
        tool_call: ToolCall,
        *,
        success: bool,
        error: Optional[str] = None,
    ) -> None:
        """Append one audit entry for this tool execution."""
        await self._audit.log(
            AuditEvent(
                event="tool_execution",
                agent_id=agent_config.agent_id,
                session_key=agent_config.session_key,
                details={
                    "tool": tool_call.tool_name,
                    "call_id": tool_call.call_id,
                    "success": success,
                    **({"error": error} if error is not None else {}),
                },
            )
        )
