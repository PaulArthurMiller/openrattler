"""Tests for ToolExecutor — permission-gated, audit-logged tool invocation."""

from __future__ import annotations

from pathlib import Path

import pytest

from openrattler.models.agents import AgentConfig, TrustLevel
from openrattler.models.tools import ToolCall, ToolDefinition
from openrattler.storage.audit import AuditLog
from openrattler.tools.executor import ToolExecutor
from openrattler.tools.registry import ToolRegistry

# ---------------------------------------------------------------------------
# Fixtures / helpers
# ---------------------------------------------------------------------------


def _make_stack(
    tmp_path: Path,
    *,
    allowed: list[str] | None = None,
    denied: list[str] | None = None,
    trust: TrustLevel = TrustLevel.main,
    tool_trust: TrustLevel = TrustLevel.main,
    tool_name: str = "test_tool",
    requires_approval: bool = False,
    handler_result: object = "success",
    handler_raises: Exception | None = None,
) -> tuple[ToolExecutor, AuditLog]:
    """Build a complete (registry, audit_log, executor) stack for a single tool."""
    reg = ToolRegistry()
    log = AuditLog(tmp_path / "audit.jsonl")
    executor = ToolExecutor(reg, log)

    if handler_raises is not None:

        async def bad_handler(**kwargs: object) -> str:
            raise handler_raises  # type: ignore[misc]

        handler = bad_handler
    else:

        async def good_handler(**kwargs: object) -> object:
            return handler_result

        handler = good_handler  # type: ignore[assignment]

    tool_def = ToolDefinition(
        name=tool_name,
        description="Test",
        parameters={},
        trust_level_required=tool_trust,
        requires_approval=requires_approval,
    )
    reg.register(tool_def, handler)

    return executor, log


def _agent(
    trust: TrustLevel = TrustLevel.main,
    allowed: list[str] | None = None,
    denied: list[str] | None = None,
    tool_name: str = "test_tool",
) -> AgentConfig:
    return AgentConfig(
        agent_id="agent:main:main",
        name="Test",
        description="Test",
        model="test-model",
        trust_level=trust,
        allowed_tools=allowed if allowed is not None else [tool_name],
        denied_tools=denied if denied is not None else [],
        session_key="agent:main:main",
    )


def _call(tool_name: str = "test_tool", **arguments: object) -> ToolCall:
    return ToolCall(tool_name=tool_name, arguments=dict(arguments), call_id="call-001")


# ---------------------------------------------------------------------------
# Successful execution
# ---------------------------------------------------------------------------


class TestSuccessfulExecution:
    async def test_returns_tool_result_with_success_true(self, tmp_path: Path) -> None:
        executor, _ = _make_stack(tmp_path, handler_result="hello")
        result = await executor.execute(_agent(), _call())
        assert result.success is True
        assert result.result == "hello"
        assert result.error is None

    async def test_call_id_preserved(self, tmp_path: Path) -> None:
        executor, _ = _make_stack(tmp_path)
        call = ToolCall(tool_name="test_tool", arguments={}, call_id="my-call-id")
        result = await executor.execute(_agent(), call)
        assert result.call_id == "my-call-id"

    async def test_arguments_passed_to_handler(self, tmp_path: Path) -> None:
        received: dict = {}

        async def capturing_handler(**kwargs: object) -> str:
            received.update(kwargs)
            return "ok"

        reg = ToolRegistry()
        log = AuditLog(tmp_path / "audit.jsonl")
        executor = ToolExecutor(reg, log)
        tool_def = ToolDefinition(
            name="capturing",
            description="",
            parameters={},
            trust_level_required=TrustLevel.main,
        )
        reg.register(tool_def, capturing_handler)

        agent = _agent(tool_name="capturing")
        call = ToolCall(tool_name="capturing", arguments={"x": 1, "y": "hi"}, call_id="c")
        await executor.execute(agent, call)
        assert received == {"x": 1, "y": "hi"}

    async def test_sync_handler_runs_in_thread(self, tmp_path: Path) -> None:
        """A sync (non-async) handler should still work via asyncio.to_thread."""

        def sync_handler(**kwargs: object) -> str:
            return "sync-result"

        reg = ToolRegistry()
        log = AuditLog(tmp_path / "audit.jsonl")
        executor = ToolExecutor(reg, log)
        tool_def = ToolDefinition(
            name="sync_tool",
            description="",
            parameters={},
            trust_level_required=TrustLevel.main,
        )
        reg.register(tool_def, sync_handler)
        result = await executor.execute(_agent(tool_name="sync_tool"), _call("sync_tool"))
        assert result.success is True
        assert result.result == "sync-result"


# ---------------------------------------------------------------------------
# Permission denied
# ---------------------------------------------------------------------------


class TestPermissionDenied:
    async def test_unknown_tool_returns_error(self, tmp_path: Path) -> None:
        executor, _ = _make_stack(tmp_path)
        result = await executor.execute(_agent(), _call("nonexistent"))
        assert result.success is False
        assert result.error is not None

    async def test_tool_not_in_allowlist_returns_error(self, tmp_path: Path) -> None:
        executor, _ = _make_stack(tmp_path)
        agent = _agent(allowed=[])  # empty allowlist
        result = await executor.execute(agent, _call())
        assert result.success is False
        assert "allowed" in (result.error or "").lower()

    async def test_denied_tool_returns_error(self, tmp_path: Path) -> None:
        executor, _ = _make_stack(tmp_path)
        agent = _agent(allowed=["test_tool"], denied=["test_tool"])
        result = await executor.execute(agent, _call())
        assert result.success is False
        assert "denied" in (result.error or "").lower()

    async def test_insufficient_trust_level_returns_error(self, tmp_path: Path) -> None:
        executor, _ = _make_stack(tmp_path, tool_trust=TrustLevel.local)
        agent = _agent(trust=TrustLevel.public, allowed=["test_tool"])
        result = await executor.execute(agent, _call())
        assert result.success is False
        assert "trust" in (result.error or "").lower()


# ---------------------------------------------------------------------------
# Handler exceptions
# ---------------------------------------------------------------------------


class TestHandlerExceptions:
    async def test_exception_returns_error_result(self, tmp_path: Path) -> None:
        executor, _ = _make_stack(tmp_path, handler_raises=RuntimeError("something went wrong"))
        result = await executor.execute(_agent(), _call())
        assert result.success is False
        assert "something went wrong" in (result.error or "")

    async def test_executor_never_raises(self, tmp_path: Path) -> None:
        """Even with a crashing handler, execute() must return a ToolResult."""
        executor, _ = _make_stack(tmp_path, handler_raises=Exception("boom"))
        # This must not raise
        result = await executor.execute(_agent(), _call())
        assert isinstance(result.success, bool)

    async def test_exception_result_has_no_result_value(self, tmp_path: Path) -> None:
        executor, _ = _make_stack(tmp_path, handler_raises=ValueError("bad input"))
        result = await executor.execute(_agent(), _call())
        assert result.result is None


# ---------------------------------------------------------------------------
# Audit logging
# ---------------------------------------------------------------------------


class TestAuditLogging:
    async def test_successful_execution_is_logged(self, tmp_path: Path) -> None:
        executor, audit = _make_stack(tmp_path)
        await executor.execute(_agent(), _call())
        events = await audit.query(event_type="tool_execution")
        assert len(events) == 1
        assert events[0].details["success"] is True

    async def test_permission_denied_is_logged(self, tmp_path: Path) -> None:
        executor, audit = _make_stack(tmp_path)
        await executor.execute(_agent(allowed=[]), _call())
        events = await audit.query(event_type="tool_execution")
        assert len(events) == 1
        assert events[0].details["success"] is False

    async def test_handler_exception_is_logged(self, tmp_path: Path) -> None:
        executor, audit = _make_stack(tmp_path, handler_raises=RuntimeError("oops"))
        await executor.execute(_agent(), _call())
        events = await audit.query(event_type="tool_execution")
        assert len(events) == 1
        assert events[0].details["success"] is False
        assert "oops" in events[0].details.get("error", "")

    async def test_unknown_tool_is_logged(self, tmp_path: Path) -> None:
        executor, audit = _make_stack(tmp_path)
        await executor.execute(_agent(), _call("no_such_tool"))
        events = await audit.query(event_type="tool_execution")
        assert len(events) == 1
        assert events[0].details["success"] is False

    async def test_audit_log_includes_tool_name(self, tmp_path: Path) -> None:
        executor, audit = _make_stack(tmp_path, tool_name="file_read")
        await executor.execute(_agent(tool_name="file_read"), _call("file_read"))
        events = await audit.query(event_type="tool_execution")
        assert events[0].details["tool"] == "file_read"

    async def test_audit_log_includes_call_id(self, tmp_path: Path) -> None:
        executor, audit = _make_stack(tmp_path)
        call = ToolCall(tool_name="test_tool", arguments={}, call_id="unique-id-42")
        await executor.execute(_agent(), call)
        events = await audit.query(event_type="tool_execution")
        assert events[0].details["call_id"] == "unique-id-42"

    async def test_multiple_executions_each_logged(self, tmp_path: Path) -> None:
        executor, audit = _make_stack(tmp_path)
        for i in range(3):
            await executor.execute(_agent(), _call())
        events = await audit.query(event_type="tool_execution")
        assert len(events) == 3
