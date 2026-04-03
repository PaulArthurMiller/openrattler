"""Tests for the human-in-the-loop approval system.

Covers ApprovalManager (approve / deny / timeout / audit) and
ToolExecutor integration (approval gates block or allow execution).
"""

from __future__ import annotations

import asyncio
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import AsyncMock, patch

import pytest

from openrattler.models.agents import AgentConfig, TrustLevel
from openrattler.models.audit import AuditEvent
from openrattler.models.tools import ToolCall, ToolDefinition
from openrattler.security.action_levels import DEAD_STOP_ACTIONS, DeadStopError
from openrattler.security.approval import (
    ApprovalManager,
    ApprovalRequest,
    ApprovalResult,
    CLIApprovalHandler,
)
from openrattler.storage.audit import AuditLog
from openrattler.tools.executor import ToolExecutor
from openrattler.tools.registry import ToolRegistry

# ---------------------------------------------------------------------------
# Fixtures and helpers
# ---------------------------------------------------------------------------


def _make_audit(tmp_path: Path) -> AuditLog:
    return AuditLog(tmp_path / "audit.jsonl")


def _make_request(timeout_seconds: int = 30) -> ApprovalRequest:
    return ApprovalRequest(
        approval_id="test-approval-001",
        operation="dangerous_file_delete",
        context={"path": "/tmp/test.txt"},
        requesting_agent="agent:main:main",
        session_key="agent:main:main",
        provenance={
            "trust_level": "main",
            "agent_id": "agent:main:main",
            "session_key": "agent:main:main",
            "timestamp": datetime.now(timezone.utc).isoformat(),
        },
        timestamp=datetime.now(timezone.utc),
        timeout_seconds=timeout_seconds,
    )


def _make_agent_config(
    trust_level: TrustLevel = TrustLevel.main,
    allowed_tools: list[str] | None = None,
    requires_approval_tool: bool = False,
) -> AgentConfig:
    return AgentConfig(
        agent_id="agent:main:main",
        name="TestAgent",
        description="test",
        model="mock-model",
        trust_level=trust_level,
        allowed_tools=allowed_tools or [],
        session_key="agent:main:main",
    )


# ---------------------------------------------------------------------------
# ApprovalRequest model
# ---------------------------------------------------------------------------


class TestApprovalRequestModel:
    def test_default_timeout(self):
        req = _make_request()
        assert req.timeout_seconds == 30

    def test_custom_timeout(self):
        req = _make_request(timeout_seconds=5)
        assert req.timeout_seconds == 5

    def test_provenance_field_present(self):
        req = _make_request()
        assert "trust_level" in req.provenance
        assert "agent_id" in req.provenance
        assert "timestamp" in req.provenance


# ---------------------------------------------------------------------------
# ApprovalResult model
# ---------------------------------------------------------------------------


class TestApprovalResultModel:
    def test_approved_true(self):
        result = ApprovalResult(
            approval_id="x",
            approved=True,
            decided_by="cli:user",
            timestamp=datetime.now(timezone.utc),
        )
        assert result.approved is True

    def test_approved_false(self):
        result = ApprovalResult(
            approval_id="x",
            approved=False,
            decided_by="system:timeout",
            timestamp=datetime.now(timezone.utc),
        )
        assert result.approved is False


# ---------------------------------------------------------------------------
# ApprovalManager — approve flow
# ---------------------------------------------------------------------------


class TestApprovalFlow:
    async def test_approve_returns_approved_true(self, tmp_path):
        manager = ApprovalManager(_make_audit(tmp_path))
        request = _make_request()

        async def approve_handler(req: ApprovalRequest, mgr: ApprovalManager) -> None:
            await mgr.resolve(req.approval_id, approved=True, decided_by="cli:user")

        manager.set_handler(approve_handler)
        result = await manager.request_approval(request)

        assert result.approved is True
        assert result.decided_by == "cli:user"
        assert result.approval_id == request.approval_id

    async def test_deny_returns_approved_false(self, tmp_path):
        manager = ApprovalManager(_make_audit(tmp_path))
        request = _make_request()

        async def deny_handler(req: ApprovalRequest, mgr: ApprovalManager) -> None:
            await mgr.resolve(req.approval_id, approved=False, decided_by="cli:user")

        manager.set_handler(deny_handler)
        result = await manager.request_approval(request)

        assert result.approved is False
        assert result.decided_by == "cli:user"

    async def test_no_handler_waits_then_times_out(self, tmp_path):
        manager = ApprovalManager(_make_audit(tmp_path))
        request = _make_request(timeout_seconds=1)
        # No handler registered — must time out and auto-deny.
        result = await manager.request_approval(request)

        assert result.approved is False
        assert result.decided_by == "system:timeout"

    async def test_request_removed_from_pending_after_approval(self, tmp_path):
        manager = ApprovalManager(_make_audit(tmp_path))
        request = _make_request()

        async def approve_handler(req: ApprovalRequest, mgr: ApprovalManager) -> None:
            await mgr.resolve(req.approval_id, approved=True, decided_by="cli:user")

        manager.set_handler(approve_handler)
        await manager.request_approval(request)

        pending = await manager.list_pending()
        assert pending == []


# ---------------------------------------------------------------------------
# ApprovalManager — timeout
# ---------------------------------------------------------------------------


class TestTimeoutAutoDeny:
    async def test_timeout_returns_approved_false(self, tmp_path):
        manager = ApprovalManager(_make_audit(tmp_path))
        request = _make_request(timeout_seconds=1)
        result = await manager.request_approval(request)

        assert result.approved is False
        assert result.decided_by == "system:timeout"

    async def test_timeout_removes_from_pending(self, tmp_path):
        manager = ApprovalManager(_make_audit(tmp_path))
        request = _make_request(timeout_seconds=1)
        await manager.request_approval(request)

        assert await manager.list_pending() == []

    async def test_resolve_after_timeout_is_silently_ignored(self, tmp_path):
        """resolve() called after a timeout must not raise."""
        manager = ApprovalManager(_make_audit(tmp_path))
        request = _make_request(timeout_seconds=1)
        await manager.request_approval(request)

        # Should not raise even though the request is already decided.
        await manager.resolve(request.approval_id, approved=True, decided_by="late:handler")


# ---------------------------------------------------------------------------
# ApprovalManager — list_pending and provenance
# ---------------------------------------------------------------------------


class TestListPendingAndProvenance:
    async def test_list_pending_shows_active_request(self, tmp_path):
        manager = ApprovalManager(_make_audit(tmp_path))
        request = _make_request()
        # Start the request but don't await it — use a task so list_pending
        # is callable while the request is still open.
        task = asyncio.create_task(manager.request_approval(request))
        # Yield to let request_approval register the pending entry.
        await asyncio.sleep(0)

        pending = await manager.list_pending()
        assert len(pending) == 1
        assert pending[0].approval_id == request.approval_id

        # Clean up — approve so the task completes.
        await manager.resolve(request.approval_id, approved=True, decided_by="test")
        await task

    async def test_provenance_keys_in_request(self, tmp_path):
        request = _make_request()
        assert "trust_level" in request.provenance
        assert "agent_id" in request.provenance
        assert "timestamp" in request.provenance
        # Provenance must not rely on user-supplied data — verify it's a dict.
        assert isinstance(request.provenance, dict)

    async def test_resolve_unknown_id_raises(self, tmp_path):
        manager = ApprovalManager(_make_audit(tmp_path))
        with pytest.raises(ValueError, match="No pending approval"):
            await manager.resolve("nonexistent-id", approved=True, decided_by="test")


# ---------------------------------------------------------------------------
# ApprovalManager — audit logging
# ---------------------------------------------------------------------------


class TestAuditLogging:
    async def test_audit_logs_request_event(self, tmp_path):
        audit = _make_audit(tmp_path)
        manager = ApprovalManager(audit)
        request = _make_request()

        async def approve(req: ApprovalRequest, mgr: ApprovalManager) -> None:
            await mgr.resolve(req.approval_id, approved=True, decided_by="cli:user")

        manager.set_handler(approve)
        await manager.request_approval(request)

        events = await audit.query(event_type="approval_requested")
        assert len(events) == 1
        assert events[0].details["approval_id"] == request.approval_id
        assert events[0].details["operation"] == request.operation
        assert "provenance" in events[0].details

    async def test_audit_logs_resolution_event(self, tmp_path):
        audit = _make_audit(tmp_path)
        manager = ApprovalManager(audit)
        request = _make_request()

        async def approve(req: ApprovalRequest, mgr: ApprovalManager) -> None:
            await mgr.resolve(req.approval_id, approved=True, decided_by="cli:user")

        manager.set_handler(approve)
        await manager.request_approval(request)

        events = await audit.query(event_type="approval_resolved")
        assert len(events) == 1
        assert events[0].details["approved"] is True
        assert events[0].details["decided_by"] == "cli:user"

    async def test_audit_logs_both_request_and_resolution(self, tmp_path):
        audit = _make_audit(tmp_path)
        manager = ApprovalManager(audit)
        request = _make_request()

        async def deny(req: ApprovalRequest, mgr: ApprovalManager) -> None:
            await mgr.resolve(req.approval_id, approved=False, decided_by="cli:user")

        manager.set_handler(deny)
        await manager.request_approval(request)

        requested = await audit.query(event_type="approval_requested")
        resolved = await audit.query(event_type="approval_resolved")
        assert len(requested) == 1
        assert len(resolved) == 1

    async def test_timeout_audit_logs_system_timeout(self, tmp_path):
        audit = _make_audit(tmp_path)
        manager = ApprovalManager(audit)
        request = _make_request(timeout_seconds=1)
        await manager.request_approval(request)

        events = await audit.query(event_type="approval_resolved")
        assert len(events) == 1
        assert events[0].details["decided_by"] == "system:timeout"
        assert events[0].details["approved"] is False


# ---------------------------------------------------------------------------
# CLIApprovalHandler
# ---------------------------------------------------------------------------


class TestCLIApprovalHandler:
    async def test_yes_answer_approves(self, tmp_path):
        audit = _make_audit(tmp_path)
        manager = ApprovalManager(audit)
        request = _make_request()
        handler = CLIApprovalHandler()

        with patch.object(CLIApprovalHandler, "_read_input", return_value="y"):
            task = asyncio.create_task(manager.request_approval(request))
            await asyncio.sleep(0)
            await asyncio.create_task(handler(request, manager))
            result = await task

        assert result.approved is True
        assert result.decided_by == "cli:user"

    async def test_no_answer_denies(self, tmp_path):
        audit = _make_audit(tmp_path)
        manager = ApprovalManager(audit)
        request = _make_request()
        handler = CLIApprovalHandler()

        with patch.object(CLIApprovalHandler, "_read_input", return_value="n"):
            task = asyncio.create_task(manager.request_approval(request))
            await asyncio.sleep(0)
            await asyncio.create_task(handler(request, manager))
            result = await task

        assert result.approved is False

    async def test_empty_answer_denies(self, tmp_path):
        audit = _make_audit(tmp_path)
        manager = ApprovalManager(audit)
        request = _make_request()
        handler = CLIApprovalHandler()

        with patch.object(CLIApprovalHandler, "_read_input", return_value=""):
            task = asyncio.create_task(manager.request_approval(request))
            await asyncio.sleep(0)
            await asyncio.create_task(handler(request, manager))
            result = await task

        assert result.approved is False


# ---------------------------------------------------------------------------
# ToolExecutor — approval integration
# ---------------------------------------------------------------------------


def _make_executor(
    tmp_path: Path,
    approval_manager: ApprovalManager | None = None,
) -> tuple[ToolExecutor, ToolRegistry]:
    registry = ToolRegistry()
    audit = _make_audit(tmp_path)
    executor = ToolExecutor(registry, audit, approval_manager=approval_manager)
    return executor, registry


def _approval_tool_def(name: str = "sensitive_op") -> ToolDefinition:
    return ToolDefinition(
        name=name,
        description="Sensitive operation requiring approval",
        parameters={"type": "object", "properties": {}, "required": []},
        trust_level_required=TrustLevel.main,
        requires_approval=True,
    )


class TestToolExecutorApprovalIntegration:
    async def test_approve_allows_tool_execution(self, tmp_path):
        manager = ApprovalManager(_make_audit(tmp_path))
        executor, registry = _make_executor(tmp_path, approval_manager=manager)
        agent = _make_agent_config(allowed_tools=["sensitive_op"])

        executed = []
        registry.register(_approval_tool_def(), lambda: executed.append(True) or "done")

        async def auto_approve(req: ApprovalRequest, mgr: ApprovalManager) -> None:
            await mgr.resolve(req.approval_id, approved=True, decided_by="cli:user")

        manager.set_handler(auto_approve)

        result = await executor.execute(agent, ToolCall(tool_name="sensitive_op", call_id="c1"))

        assert result.success is True
        assert result.result == "done"
        assert executed == [True]

    async def test_deny_blocks_tool_execution(self, tmp_path):
        manager = ApprovalManager(_make_audit(tmp_path))
        executor, registry = _make_executor(tmp_path, approval_manager=manager)
        agent = _make_agent_config(allowed_tools=["sensitive_op"])

        executed = []
        registry.register(_approval_tool_def(), lambda: executed.append(True) or "done")

        async def auto_deny(req: ApprovalRequest, mgr: ApprovalManager) -> None:
            await mgr.resolve(req.approval_id, approved=False, decided_by="cli:user")

        manager.set_handler(auto_deny)

        result = await executor.execute(agent, ToolCall(tool_name="sensitive_op", call_id="c2"))

        assert result.success is False
        assert "denied" in result.error  # type: ignore[operator]
        assert executed == []  # handler was never called

    async def test_timeout_blocks_tool_execution(self, tmp_path):
        audit = _make_audit(tmp_path)
        manager = ApprovalManager(audit, default_timeout_seconds=1)
        executor, registry = _make_executor(tmp_path, approval_manager=manager)
        agent = _make_agent_config(allowed_tools=["sensitive_op"])

        executed = []
        registry.register(_approval_tool_def(), lambda: executed.append(True) or "done")
        # No handler — will time out.

        result = await executor.execute(agent, ToolCall(tool_name="sensitive_op", call_id="c3"))

        assert result.success is False
        assert "system:timeout" in (result.error or "")
        assert executed == []

    async def test_no_approval_manager_executes_without_approval(self, tmp_path):
        """Backward-compat: no manager → tool with requires_approval still runs."""
        executor, registry = _make_executor(tmp_path, approval_manager=None)
        agent = _make_agent_config(allowed_tools=["sensitive_op"])

        registry.register(_approval_tool_def(), lambda: "ran")

        result = await executor.execute(agent, ToolCall(tool_name="sensitive_op", call_id="c4"))

        assert result.success is True

    async def test_non_approval_tool_skips_approval_gate(self, tmp_path):
        manager = ApprovalManager(_make_audit(tmp_path))
        executor, registry = _make_executor(tmp_path, approval_manager=manager)
        agent = _make_agent_config(allowed_tools=["plain_tool"])

        plain_def = ToolDefinition(
            name="plain_tool",
            description="No approval required",
            parameters={"type": "object", "properties": {}, "required": []},
            trust_level_required=TrustLevel.main,
            requires_approval=False,
        )
        registry.register(plain_def, lambda: "plain_result")

        result = await executor.execute(agent, ToolCall(tool_name="plain_tool", call_id="c5"))

        assert result.success is True
        assert result.result == "plain_result"

    async def test_approval_denial_audit_logged(self, tmp_path):
        audit = _make_audit(tmp_path)
        manager = ApprovalManager(audit)
        executor, registry = _make_executor(tmp_path, approval_manager=manager)
        agent = _make_agent_config(allowed_tools=["sensitive_op"])

        registry.register(_approval_tool_def(), lambda: "done")

        async def auto_deny(req: ApprovalRequest, mgr: ApprovalManager) -> None:
            await mgr.resolve(req.approval_id, approved=False, decided_by="cli:user")

        manager.set_handler(auto_deny)
        await executor.execute(agent, ToolCall(tool_name="sensitive_op", call_id="c6"))

        exec_events = await audit.query(event_type="tool_execution")
        assert len(exec_events) == 1
        assert exec_events[0].details["success"] is False
        assert "approval_id" in exec_events[0].details

    async def test_provenance_contains_agent_trust_level(self, tmp_path):
        """Provenance in the request must carry trust_level from AgentConfig."""
        manager = ApprovalManager(_make_audit(tmp_path))
        captured: list[ApprovalRequest] = []
        executor, registry = _make_executor(tmp_path, approval_manager=manager)
        agent = _make_agent_config(trust_level=TrustLevel.main, allowed_tools=["sensitive_op"])

        registry.register(_approval_tool_def(), lambda: "done")

        async def capture_and_approve(req: ApprovalRequest, mgr: ApprovalManager) -> None:
            captured.append(req)
            await mgr.resolve(req.approval_id, approved=True, decided_by="test")

        manager.set_handler(capture_and_approve)
        await executor.execute(agent, ToolCall(tool_name="sensitive_op", call_id="c7"))

        assert len(captured) == 1
        assert captured[0].provenance["trust_level"] == "main"
        assert captured[0].provenance["agent_id"] == "agent:main:main"


# ---------------------------------------------------------------------------
# Piece 39.2 — Enhanced ApprovalRequest fields
# ---------------------------------------------------------------------------


class TestApprovalRequestNewFields:
    def test_action_level_defaults_to_5(self):
        req = _make_request()
        assert req.action_level == 5

    def test_rationale_defaults_to_none(self):
        req = _make_request()
        assert req.rationale is None

    def test_trace_id_defaults_to_none(self):
        req = _make_request()
        assert req.trace_id is None

    def test_approval_token_is_auto_generated(self):
        req = _make_request()
        assert isinstance(req.approval_token, str)
        assert len(req.approval_token) > 0

    def test_two_requests_get_different_tokens(self):
        req1 = _make_request()
        req2 = _make_request()
        assert req1.approval_token != req2.approval_token

    def test_token_expiry_is_in_the_future(self):
        req = _make_request()
        assert req.token_expiry > datetime.now(timezone.utc)

    def test_custom_fields_roundtrip(self):
        req = ApprovalRequest(
            approval_id="req-custom",
            operation="write_file",
            requesting_agent="agent:main:main",
            session_key="agent:main:main",
            provenance={"trust_level": "main", "agent_id": "agent:main:main", "timestamp": "ts"},
            timestamp=datetime.now(timezone.utc),
            action_level=3,
            rationale="The user asked me to save the document.",
            trace_id="trace-abc-123",
        )
        assert req.action_level == 3
        assert req.rationale == "The user asked me to save the document."
        assert req.trace_id == "trace-abc-123"


# ---------------------------------------------------------------------------
# Piece 39.2 — ApprovalResult new fields
# ---------------------------------------------------------------------------


class TestApprovalResultNewFields:
    def test_approval_token_and_expiry_present_on_approval(self, tmp_path):
        """resolve(approved=True) must pass the token and expiry through."""

        async def run() -> ApprovalResult:
            manager = ApprovalManager(_make_audit(tmp_path))
            request = _make_request()

            async def approve(req: ApprovalRequest, mgr: ApprovalManager) -> None:
                await mgr.resolve(req.approval_id, approved=True, decided_by="cli:user")

            manager.set_handler(approve)
            return await manager.request_approval(request)

        result = asyncio.get_event_loop().run_until_complete(run())
        assert result.approved is True
        assert result.approval_token is not None
        assert result.token_expiry is not None

    def test_approval_token_none_on_denial(self, tmp_path):
        """resolve(approved=False) must not pass the token through."""

        async def run() -> ApprovalResult:
            manager = ApprovalManager(_make_audit(tmp_path))
            request = _make_request()

            async def deny(req: ApprovalRequest, mgr: ApprovalManager) -> None:
                await mgr.resolve(req.approval_id, approved=False, decided_by="cli:user")

            manager.set_handler(deny)
            return await manager.request_approval(request)

        result = asyncio.get_event_loop().run_until_complete(run())
        assert result.approved is False
        assert result.approval_token is None
        assert result.token_expiry is None

    def test_approval_token_none_on_timeout(self, tmp_path):
        """Timeout path must not pass a token through."""

        async def run() -> ApprovalResult:
            manager = ApprovalManager(_make_audit(tmp_path))
            request = _make_request(timeout_seconds=1)
            return await manager.request_approval(request)

        result = asyncio.get_event_loop().run_until_complete(run())
        assert result.approved is False
        assert result.approval_token is None


# ---------------------------------------------------------------------------
# Piece 39.2 — consume_token: single-use, time-bounded
# ---------------------------------------------------------------------------


class TestConsumeToken:
    def _manager(self, tmp_path: Path) -> ApprovalManager:
        return ApprovalManager(_make_audit(tmp_path))

    def test_valid_token_is_consumed_returns_true(self, tmp_path):
        manager = self._manager(tmp_path)
        token = str(__import__("uuid").uuid4())
        expiry = datetime.now(timezone.utc) + timedelta(minutes=5)
        assert manager.consume_token(token, expiry) is True

    def test_replayed_token_returns_false(self, tmp_path):
        manager = self._manager(tmp_path)
        token = str(__import__("uuid").uuid4())
        expiry = datetime.now(timezone.utc) + timedelta(minutes=5)
        manager.consume_token(token, expiry)  # first use — True
        assert manager.consume_token(token, expiry) is False  # replay — False

    def test_expired_token_returns_false(self, tmp_path):
        manager = self._manager(tmp_path)
        token = str(__import__("uuid").uuid4())
        # Expiry is in the past.
        expiry = datetime.now(timezone.utc) - timedelta(seconds=1)
        assert manager.consume_token(token, expiry) is False

    def test_different_tokens_are_independent(self, tmp_path):
        manager = self._manager(tmp_path)
        expiry = datetime.now(timezone.utc) + timedelta(minutes=5)
        token1 = str(__import__("uuid").uuid4())
        token2 = str(__import__("uuid").uuid4())
        manager.consume_token(token1, expiry)
        # token2 has not been consumed — must still return True.
        assert manager.consume_token(token2, expiry) is True


# ---------------------------------------------------------------------------
# Piece 39.2 — Dead stop check in request_approval
# ---------------------------------------------------------------------------


def _make_dead_stop_request() -> ApprovalRequest:
    """Build a request for an operation that is in DEAD_STOP_ACTIONS."""
    dead_op = next(iter(DEAD_STOP_ACTIONS))
    return ApprovalRequest(
        approval_id="ds-001",
        operation=dead_op,
        requesting_agent="agent:main:main",
        session_key="agent:main:main",
        provenance={"trust_level": "main", "agent_id": "agent:main:main", "timestamp": "ts"},
        timestamp=datetime.now(timezone.utc),
    )


class TestDeadStopCheck:
    async def test_dead_stop_raises_dead_stop_error(self, tmp_path):
        manager = ApprovalManager(_make_audit(tmp_path))
        request = _make_dead_stop_request()
        with pytest.raises(DeadStopError) as exc_info:
            await manager.request_approval(request)
        assert exc_info.value.action == request.operation

    async def test_dead_stop_writes_audit_event(self, tmp_path):
        audit = _make_audit(tmp_path)
        manager = ApprovalManager(audit)
        request = _make_dead_stop_request()
        try:
            await manager.request_approval(request)
        except DeadStopError:
            pass

        events = await audit.query(event_type="dead_stop_blocked")
        assert len(events) == 1
        assert events[0].details["operation"] == request.operation

    async def test_dead_stop_audit_includes_action_level(self, tmp_path):
        audit = _make_audit(tmp_path)
        manager = ApprovalManager(audit)
        request = _make_dead_stop_request()
        request2 = ApprovalRequest(
            **{**request.model_dump(), "action_level": 1, "approval_id": "ds-002"}
        )
        try:
            await manager.request_approval(request2)
        except DeadStopError:
            pass

        events = await audit.query(event_type="dead_stop_blocked")
        assert events[0].details["action_level"] == 1

    async def test_dead_stop_handler_is_never_called(self, tmp_path):
        manager = ApprovalManager(_make_audit(tmp_path))
        request = _make_dead_stop_request()
        handler_called = []

        async def handler(req: ApprovalRequest, mgr: ApprovalManager) -> None:
            handler_called.append(True)

        manager.set_handler(handler)
        try:
            await manager.request_approval(request)
        except DeadStopError:
            pass

        # Give the event loop a tick to ensure no background task ran.
        await asyncio.sleep(0)
        assert handler_called == []

    async def test_dead_stop_request_not_in_pending(self, tmp_path):
        manager = ApprovalManager(_make_audit(tmp_path))
        request = _make_dead_stop_request()
        try:
            await manager.request_approval(request)
        except DeadStopError:
            pass

        assert await manager.list_pending() == []


# ---------------------------------------------------------------------------
# Piece 39.2 — action_level and trace_id flow through to audit events
# ---------------------------------------------------------------------------


class TestAuditFieldsNewIn392:
    async def test_action_level_in_approval_requested_event(self, tmp_path):
        audit = _make_audit(tmp_path)
        manager = ApprovalManager(audit)
        request = ApprovalRequest(
            approval_id="audit-level-001",
            operation="write_file",
            requesting_agent="agent:main:main",
            session_key="agent:main:main",
            provenance={"trust_level": "main", "agent_id": "a", "timestamp": "ts"},
            timestamp=datetime.now(timezone.utc),
            action_level=3,
        )

        async def approve(req: ApprovalRequest, mgr: ApprovalManager) -> None:
            await mgr.resolve(req.approval_id, approved=True, decided_by="cli:user")

        manager.set_handler(approve)
        await manager.request_approval(request)

        events = await audit.query(event_type="approval_requested")
        assert events[0].details["action_level"] == 3

    async def test_trace_id_in_approval_requested_event(self, tmp_path):
        audit = _make_audit(tmp_path)
        manager = ApprovalManager(audit)
        request = ApprovalRequest(
            approval_id="audit-trace-001",
            operation="write_file",
            requesting_agent="agent:main:main",
            session_key="agent:main:main",
            provenance={"trust_level": "main", "agent_id": "a", "timestamp": "ts"},
            timestamp=datetime.now(timezone.utc),
            trace_id="trace-xyz-999",
        )

        async def approve(req: ApprovalRequest, mgr: ApprovalManager) -> None:
            await mgr.resolve(req.approval_id, approved=True, decided_by="cli:user")

        manager.set_handler(approve)
        await manager.request_approval(request)

        events = await audit.query(event_type="approval_requested")
        assert events[0].details["trace_id"] == "trace-xyz-999"

    async def test_action_level_in_approval_resolved_event(self, tmp_path):
        audit = _make_audit(tmp_path)
        manager = ApprovalManager(audit)
        request = ApprovalRequest(
            approval_id="audit-resolved-001",
            operation="write_file",
            requesting_agent="agent:main:main",
            session_key="agent:main:main",
            provenance={"trust_level": "main", "agent_id": "a", "timestamp": "ts"},
            timestamp=datetime.now(timezone.utc),
            action_level=2,
        )

        async def deny(req: ApprovalRequest, mgr: ApprovalManager) -> None:
            await mgr.resolve(req.approval_id, approved=False, decided_by="cli:user")

        manager.set_handler(deny)
        await manager.request_approval(request)

        events = await audit.query(event_type="approval_resolved")
        assert events[0].details["action_level"] == 2

    async def test_action_level_in_timeout_resolved_event(self, tmp_path):
        audit = _make_audit(tmp_path)
        manager = ApprovalManager(audit)
        request = ApprovalRequest(
            approval_id="audit-timeout-001",
            operation="write_file",
            requesting_agent="agent:main:main",
            session_key="agent:main:main",
            provenance={"trust_level": "main", "agent_id": "a", "timestamp": "ts"},
            timestamp=datetime.now(timezone.utc),
            action_level=4,
            timeout_seconds=1,
        )
        await manager.request_approval(request)

        events = await audit.query(event_type="approval_resolved")
        assert events[0].details["action_level"] == 4
