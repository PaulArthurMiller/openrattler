"""Tests for ToolExecutor — permission-gated, audit-logged tool invocation."""

from __future__ import annotations

from datetime import datetime, timezone
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


# ---------------------------------------------------------------------------
# Piece 39.5 — ToolExecutor + startup integration
# ---------------------------------------------------------------------------


def _make_executor_with_policy(
    tmp_path: Path,
    threshold: int = 3,
) -> tuple["ToolExecutor", "AuditLog", "ToolRegistry"]:
    """Build executor with a real ApprovalThresholdPolicy and ApprovalManager."""
    from openrattler.security.action_levels import ApprovalThresholdPolicy
    from openrattler.security.approval import ApprovalManager

    reg = ToolRegistry()
    log = AuditLog(tmp_path / "audit.jsonl")
    policy = ApprovalThresholdPolicy(threshold=threshold)
    manager = ApprovalManager(log)
    executor = ToolExecutor(reg, log, approval_manager=manager, policy=policy)
    return executor, log, reg


def _make_tool(
    name: str,
    action_level: int = 5,
    result: object = "ok",
) -> tuple["ToolDefinition", object]:
    """Build a ToolDefinition and a simple async handler."""
    from openrattler.models.agents import TrustLevel

    tool_def = ToolDefinition(
        name=name,
        description="Test tool",
        parameters={},
        trust_level_required=TrustLevel.main,
        action_level=action_level,
    )

    async def handler(**kwargs: object) -> object:
        return result

    return tool_def, handler


class TestPiece395Integration:
    """End-to-end executor tests wiring policy, approval manager, and token consumption."""

    async def test_level5_tool_executes_without_approval(self, tmp_path: Path) -> None:
        """A tool at level 5 (read-only) skips the approval gate when threshold=3."""
        executor, _, reg = _make_executor_with_policy(tmp_path, threshold=3)
        tool_def, handler = _make_tool("read_tool", action_level=5)
        reg.register(tool_def, handler)

        result = await executor.execute(
            _agent(tool_name="read_tool"),
            ToolCall(tool_name="read_tool", call_id="c1"),
        )
        assert result.success is True
        assert result.result == "ok"
        print(f"[OK] Level-5 tool executed without approval. result={result.result}")

    async def test_level2_tool_triggers_approval_gate(self, tmp_path: Path) -> None:
        """A tool at level 2 (significant external action) requires approval when threshold=3."""
        from openrattler.security.approval import ApprovalManager, ApprovalRequest

        reg = ToolRegistry()
        log = AuditLog(tmp_path / "audit.jsonl")
        from openrattler.security.action_levels import ApprovalThresholdPolicy

        policy = ApprovalThresholdPolicy(threshold=3)
        manager = ApprovalManager(log)
        executor = ToolExecutor(reg, log, approval_manager=manager, policy=policy)

        tool_def, handler = _make_tool("send_message", action_level=2)
        reg.register(tool_def, handler)

        captured: list[ApprovalRequest] = []

        async def auto_approve(req: ApprovalRequest, mgr: ApprovalManager) -> None:
            captured.append(req)
            await mgr.resolve(req.approval_id, approved=True, decided_by="cli:user")

        manager.set_handler(auto_approve)

        result = await executor.execute(
            _agent(tool_name="send_message"),
            ToolCall(tool_name="send_message", call_id="c2"),
        )
        assert result.success is True
        assert len(captured) == 1
        assert captured[0].action_level == 2
        print(f"[OK] Level-2 tool triggered approval gate. action_level={captured[0].action_level}")

    async def test_dead_stop_tool_returns_error_without_prompting(self, tmp_path: Path) -> None:
        """A dead-stop tool name returns an error ToolResult without any approval prompt."""
        from openrattler.security.action_levels import DEAD_STOP_ACTIONS
        from openrattler.security.approval import ApprovalManager, ApprovalRequest

        reg = ToolRegistry()
        log = AuditLog(tmp_path / "audit.jsonl")
        manager = ApprovalManager(log)
        handler_called: list[bool] = []

        async def handler_never_called(**kwargs: object) -> str:
            handler_called.append(True)
            return "should not run"

        async def should_not_prompt(req: ApprovalRequest, mgr: ApprovalManager) -> None:
            handler_called.append(True)  # Fail if approval handler is invoked

        manager.set_handler(should_not_prompt)
        executor = ToolExecutor(reg, log, approval_manager=manager)

        dead_stop_name = next(iter(DEAD_STOP_ACTIONS))  # e.g. "force_push_main"

        result = await executor.execute(
            _agent(tool_name=dead_stop_name),
            ToolCall(tool_name=dead_stop_name, call_id="c3"),
        )
        assert result.success is False
        assert "dead-stop" in (result.error or "").lower()
        assert handler_called == []  # Neither handler nor approval was invoked

        # Verify audit event was written
        events = await log.query(event_type="dead_stop_blocked")
        assert len(events) == 1
        assert events[0].details["tool"] == dead_stop_name
        print(f"[OK] Dead-stop '{dead_stop_name}' blocked without approval prompt.")

    async def test_expired_token_blocks_execution(self, tmp_path: Path) -> None:
        """An approval token that has already expired is rejected at consume_token time."""
        from datetime import timedelta

        from openrattler.security.action_levels import ApprovalThresholdPolicy
        from openrattler.security.approval import ApprovalManager, ApprovalRequest, ApprovalResult

        reg = ToolRegistry()
        log = AuditLog(tmp_path / "audit.jsonl")
        policy = ApprovalThresholdPolicy(threshold=3)
        manager = ApprovalManager(log)
        executor = ToolExecutor(reg, log, approval_manager=manager, policy=policy)

        tool_def, handler = _make_tool("external_action", action_level=2)
        reg.register(tool_def, handler)

        # Handler that approves with a token that is already expired
        async def approve_with_expired_token(req: ApprovalRequest, mgr: ApprovalManager) -> None:
            # Directly store an approval result with a token expiry in the past
            # so that consume_token() rejects it
            expired_time = datetime.now(timezone.utc) - timedelta(seconds=60)
            result = ApprovalResult(
                approval_id=req.approval_id,
                approved=True,
                decided_by="cli:user",
                timestamp=datetime.now(timezone.utc),
                approval_token=req.approval_token,
                token_expiry=expired_time,  # already expired
            )
            mgr._results[req.approval_id] = result
            mgr._decided.add(req.approval_id)
            mgr._events[req.approval_id].set()

        manager.set_handler(approve_with_expired_token)

        result = await executor.execute(
            _agent(tool_name="external_action"),
            ToolCall(tool_name="external_action", call_id="c4"),
        )
        assert result.success is False
        assert (
            "expired" in (result.error or "").lower() or "replayed" in (result.error or "").lower()
        )

        # Verify token rejection was audit-logged
        events = await log.query(event_type="approval_token_rejected")
        assert len(events) == 1
        print("[OK] Expired token blocked execution and audit-logged.")

    async def test_denied_approval_blocks_execution(self, tmp_path: Path) -> None:
        """An explicit denial returns error and does not invoke the tool handler."""
        from openrattler.security.action_levels import ApprovalThresholdPolicy
        from openrattler.security.approval import ApprovalManager, ApprovalRequest

        reg = ToolRegistry()
        log = AuditLog(tmp_path / "audit.jsonl")
        policy = ApprovalThresholdPolicy(threshold=3)
        manager = ApprovalManager(log)
        executor = ToolExecutor(reg, log, approval_manager=manager, policy=policy)

        executed: list[bool] = []
        tool_def, _ = _make_tool("write_file", action_level=2)

        async def tracking_handler(**kwargs: object) -> str:
            executed.append(True)
            return "ran"

        reg.register(tool_def, tracking_handler)

        async def auto_deny(req: ApprovalRequest, mgr: ApprovalManager) -> None:
            await mgr.resolve(req.approval_id, approved=False, decided_by="cli:user")

        manager.set_handler(auto_deny)

        result = await executor.execute(
            _agent(tool_name="write_file"),
            ToolCall(tool_name="write_file", call_id="c5"),
        )
        assert result.success is False
        assert "denied" in (result.error or "")
        assert executed == []
        print("[OK] Denied approval blocked tool handler execution.")

    async def test_trace_id_propagates_to_approval_request(self, tmp_path: Path) -> None:
        """trace_id on ToolCall is forwarded into the ApprovalRequest."""
        from openrattler.security.action_levels import ApprovalThresholdPolicy
        from openrattler.security.approval import ApprovalManager, ApprovalRequest

        reg = ToolRegistry()
        log = AuditLog(tmp_path / "audit.jsonl")
        policy = ApprovalThresholdPolicy(threshold=3)
        manager = ApprovalManager(log)
        executor = ToolExecutor(reg, log, approval_manager=manager, policy=policy)

        tool_def, handler = _make_tool("write_memory", action_level=3)
        reg.register(tool_def, handler)

        captured: list[ApprovalRequest] = []

        async def capture_and_approve(req: ApprovalRequest, mgr: ApprovalManager) -> None:
            captured.append(req)
            await mgr.resolve(req.approval_id, approved=True, decided_by="cli:user")

        manager.set_handler(capture_and_approve)

        await executor.execute(
            _agent(tool_name="write_memory"),
            ToolCall(tool_name="write_memory", call_id="c6", trace_id="trace-abc-999"),
        )
        assert len(captured) == 1
        assert captured[0].trace_id == "trace-abc-999"
        print(f"[OK] trace_id propagated to approval request: {captured[0].trace_id}")

    async def test_rationale_propagates_to_approval_request(self, tmp_path: Path) -> None:
        """rationale on ToolCall is forwarded into the ApprovalRequest."""
        from openrattler.security.action_levels import ApprovalThresholdPolicy
        from openrattler.security.approval import ApprovalManager, ApprovalRequest

        reg = ToolRegistry()
        log = AuditLog(tmp_path / "audit.jsonl")
        policy = ApprovalThresholdPolicy(threshold=3)
        manager = ApprovalManager(log)
        executor = ToolExecutor(reg, log, approval_manager=manager, policy=policy)

        tool_def, handler = _make_tool("write_memory", action_level=3)
        reg.register(tool_def, handler)

        captured: list[ApprovalRequest] = []

        async def capture_and_approve(req: ApprovalRequest, mgr: ApprovalManager) -> None:
            captured.append(req)
            await mgr.resolve(req.approval_id, approved=True, decided_by="cli:user")

        manager.set_handler(capture_and_approve)

        await executor.execute(
            _agent(tool_name="write_memory"),
            ToolCall(
                tool_name="write_memory",
                call_id="c7",
                rationale="User asked me to save the document.",
            ),
        )
        assert len(captured) == 1
        assert captured[0].rationale == "User asked me to save the document."
        print(f"[OK] rationale propagated to approval request: {captured[0].rationale}")
