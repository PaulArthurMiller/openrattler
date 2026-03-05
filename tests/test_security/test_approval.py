"""Tests for the human-in-the-loop approval system.

Covers ApprovalManager (approve / deny / timeout / audit) and
ToolExecutor integration (approval gates block or allow execution).
"""

from __future__ import annotations

import asyncio
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import AsyncMock, patch

import pytest

from openrattler.models.agents import AgentConfig, TrustLevel
from openrattler.models.audit import AuditEvent
from openrattler.models.tools import ToolCall, ToolDefinition
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
