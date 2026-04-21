"""Integration tests for ClaudeCodeTool (piece 40.5).

Tests cover:
- Full write-task flow: workspace created → plan approved → CC spawned → result returned.
- Plan denied → RuntimeError raised (executor surfaces as ToolResult error).
- Dead stop cc_bypass_permissions → ToolResult error, no CC spawn, audit logged.
- cc_promote_request → level-1 approval gate triggered; handler returns intent dict.
- cc_read_analyze → no plan review, read-only tool list, result returned.
- CC timeout → RuntimeError raised (subprocess returns CCResult.error).
- cc_git_push_branch → branch name validation enforced.
- CCConfig.enabled = False → cc_* tools not registered, unknown-tool error.

All subprocess spawns are mocked at CCSubprocessManager.spawn so no real CC
binary is needed.  Approval flows use MagicMock/AsyncMock.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from openrattler.config.loader import CCConfig
from openrattler.models.agents import AgentConfig, TrustLevel
from openrattler.models.tools import ToolCall, ToolResult
from openrattler.security.action_levels import ApprovalThresholdPolicy
from openrattler.security.approval import ApprovalResult
from openrattler.storage.audit import AuditLog
from openrattler.tools.claude_code.output_parser import CCOutputParser
from openrattler.tools.claude_code.plan_reviewer import CCPlanReviewer, PlanReviewResult
from openrattler.tools.claude_code.subprocess_mgr import CCResult, CCSubprocessManager
from openrattler.tools.claude_code.tool import (
    ALL_CC_TOOLS,
    ClaudeCodeTool,
    register_cc_tools,
)
from openrattler.tools.claude_code.workspace import WorkspaceManager
from openrattler.tools.executor import ToolExecutor
from openrattler.tools.registry import ToolRegistry

# ---------------------------------------------------------------------------
# Shared test fixtures
# ---------------------------------------------------------------------------

_PROJECT_PATH = Path("C:/fake/ws/projects/or-test-proj")
_ENV: dict[str, str] = {
    "CLAUDE_CONFIG_DIR": "C:/fake/ws/.claude",
    "GIT_AUTHOR_NAME": "Test Bot",
    "GIT_AUTHOR_EMAIL": "bot@local",
}
_TASK = "Add a hello-world endpoint to the Flask app"
_PROJECT_NAME = "test-proj"

_CC_OUTPUT = json.dumps(
    {
        "type": "result",
        "subtype": "success",
        "result": "Done. Created hello_world endpoint in app.py.",
        "session_id": "sess-abc123",
        "cost_usd": 0.005,
        "num_turns": 3,
        "is_error": False,
    }
)

_PLAN_TEXT = (
    "I will add a /hello endpoint to app.py.\n"
    "Files to modify: app.py\n"
    "Files to create: none\n"
    "Shell commands: none\n"
    "Reasoning: Simple Flask route addition."
)

_PLAN_OUTPUT = json.dumps(
    {
        "type": "result",
        "subtype": "success",
        "result": _PLAN_TEXT,
        "session_id": "plan-sess-001",
        "cost_usd": 0.001,
        "num_turns": 1,
        "is_error": False,
    }
)


def _make_config(**overrides: Any) -> CCConfig:
    defaults: dict[str, Any] = {
        "enabled": True,
        "workspace_root": "C:/fake/ws",
        "assistant_name": "TestBot",
        "project_prefix": "or",
        "git_author_name": "Test Bot",
        "git_author_email": "bot@local",
        "plan_review_enabled": True,
        "plan_review_approval_level": 3,
        "plan_review_timeout_seconds": 120,
        "exec_allowed_tools": ["Read", "Write", "Glob", "Grep", "LS", "Bash"],
    }
    defaults.update(overrides)
    return CCConfig(**defaults)


def _approved_result(approval_id: str = "appr-001") -> ApprovalResult:
    return ApprovalResult(
        approval_id=approval_id,
        approved=True,
        decided_by="cli:user",
        timestamp=datetime.now(timezone.utc),
    )


def _denied_result(approval_id: str = "appr-002") -> ApprovalResult:
    return ApprovalResult(
        approval_id=approval_id,
        approved=False,
        decided_by="cli:user",
        timestamp=datetime.now(timezone.utc),
    )


def _make_tool(
    config: CCConfig | None = None,
    plan_approved: bool = True,
    plan_enabled: bool = True,
    cc_stdout: str = _CC_OUTPUT,
    cc_error: str | None = None,
) -> tuple[ClaudeCodeTool, MagicMock, MagicMock, MagicMock]:
    """Build a ClaudeCodeTool with all collaborators mocked.

    Returns (tool, workspace_mock, subprocess_mgr_mock, plan_reviewer_mock).
    """
    cfg = config or _make_config()

    workspace = MagicMock(spec=WorkspaceManager)
    workspace.create_project.return_value = _PROJECT_PATH
    workspace.get_env.return_value = _ENV

    subprocess_mgr = MagicMock(spec=CCSubprocessManager)
    subprocess_mgr.spawn = AsyncMock(
        return_value=CCResult(stdout=cc_stdout, returncode=0, error=cc_error)
    )

    plan_reviewer = MagicMock(spec=CCPlanReviewer)
    plan_reviewer.review = AsyncMock(
        return_value=PlanReviewResult(
            approved=plan_approved, plan=_PLAN_TEXT if plan_enabled else None
        )
    )

    tool = ClaudeCodeTool(
        workspace=workspace,
        subprocess_mgr=subprocess_mgr,
        plan_reviewer=plan_reviewer,
        config=cfg,
    )
    return tool, workspace, subprocess_mgr, plan_reviewer


# ---------------------------------------------------------------------------
# ClaudeCodeTool handler unit tests
# ---------------------------------------------------------------------------


class TestExecuteWriteTask:
    """cc_write_task handler: plan review + CC write session."""

    async def test_full_flow_returns_cc_result_dict(self) -> None:
        print("\n[test_full_flow_returns_cc_result_dict] happy path")
        tool, workspace, subprocess_mgr, plan_reviewer = _make_tool()

        result = await tool.execute_write_task(task=_TASK, project_name=_PROJECT_NAME)

        print(f"  result={result}")
        assert result["type"] == "cc_result"
        assert "Done. Created hello_world endpoint" in result["content"]
        assert result["session_id"] == "sess-abc123"
        assert result["cost_usd"] == pytest.approx(0.005)
        assert result["num_turns"] == 3
        assert str(_PROJECT_PATH) in result["project_path"]

    async def test_workspace_create_project_called(self) -> None:
        print("\n[test_workspace_create_project_called]")
        tool, workspace, subprocess_mgr, _ = _make_tool()

        await tool.execute_write_task(task=_TASK, project_name=_PROJECT_NAME)

        workspace.create_project.assert_called_once_with(_PROJECT_NAME)

    async def test_plan_review_called_before_spawn(self) -> None:
        print("\n[test_plan_review_called_before_spawn]")
        tool, workspace, subprocess_mgr, plan_reviewer = _make_tool()

        await tool.execute_write_task(task=_TASK, project_name=_PROJECT_NAME)

        plan_reviewer.review.assert_called_once()
        # spawn should only be called when plan approved
        subprocess_mgr.spawn.assert_called_once()

    async def test_plan_denied_raises_runtime_error(self) -> None:
        print("\n[test_plan_denied_raises_runtime_error] plan denied → RuntimeError")
        tool, workspace, subprocess_mgr, plan_reviewer = _make_tool(plan_approved=False)

        with pytest.raises(RuntimeError, match="Plan not approved"):
            await tool.execute_write_task(task=_TASK, project_name=_PROJECT_NAME)

        # CC should never be spawned when plan is denied
        subprocess_mgr.spawn.assert_not_called()
        print("  CC spawn correctly not called after plan denial")

    async def test_uses_exec_allowed_tools(self) -> None:
        print("\n[test_uses_exec_allowed_tools]")
        cfg = _make_config(exec_allowed_tools=["Read", "Write", "Glob"])
        tool, workspace, subprocess_mgr, _ = _make_tool(config=cfg)

        await tool.execute_write_task(task=_TASK, project_name=_PROJECT_NAME)

        call_kwargs = subprocess_mgr.spawn.call_args.kwargs
        assert call_kwargs["allowed_tools"] == ["Read", "Write", "Glob"]

    async def test_cc_error_raises_runtime_error(self) -> None:
        print("\n[test_cc_error_raises_runtime_error]")
        tool, _, subprocess_mgr, _ = _make_tool(
            cc_stdout="", cc_error="CC session timed out after 300s."
        )

        with pytest.raises(RuntimeError, match="timed out"):
            await tool.execute_write_task(task=_TASK, project_name=_PROJECT_NAME)


class TestExecuteReadAnalyze:
    """cc_read_analyze handler: no plan review, read-only tools."""

    async def test_no_plan_review_called(self) -> None:
        print("\n[test_no_plan_review_called] read-only → skip plan phase")
        tool, workspace, subprocess_mgr, plan_reviewer = _make_tool()

        result = await tool.execute_read_analyze(task=_TASK, project_name=_PROJECT_NAME)

        plan_reviewer.review.assert_not_called()
        print("  plan reviewer correctly not called for cc_read_analyze")
        assert result["type"] == "cc_result"

    async def test_read_only_tools_passed_to_spawn(self) -> None:
        print("\n[test_read_only_tools_passed_to_spawn]")
        tool, workspace, subprocess_mgr, _ = _make_tool()

        await tool.execute_read_analyze(task=_TASK, project_name=_PROJECT_NAME)

        call_kwargs = subprocess_mgr.spawn.call_args.kwargs
        assert call_kwargs["allowed_tools"] == ["Read", "Glob", "Grep", "LS"]
        print(f"  allowed_tools={call_kwargs['allowed_tools']}")

    async def test_returns_parsed_content(self) -> None:
        print("\n[test_returns_parsed_content]")
        tool, _, _, _ = _make_tool()

        result = await tool.execute_read_analyze(task=_TASK, project_name=_PROJECT_NAME)

        assert "Done. Created hello_world endpoint" in result["content"]


class TestExecuteRunWithShell:
    """cc_run_with_shell handler: plan review + exec_allowed_tools."""

    async def test_plan_review_called(self) -> None:
        print("\n[test_plan_review_called] run_with_shell includes plan review")
        tool, _, subprocess_mgr, plan_reviewer = _make_tool()

        await tool.execute_run_with_shell(task=_TASK, project_name=_PROJECT_NAME)

        plan_reviewer.review.assert_called_once()
        subprocess_mgr.spawn.assert_called_once()

    async def test_plan_denied_blocks_shell(self) -> None:
        print("\n[test_plan_denied_blocks_shell]")
        tool, _, subprocess_mgr, _ = _make_tool(plan_approved=False)

        with pytest.raises(RuntimeError, match="Plan not approved"):
            await tool.execute_run_with_shell(task=_TASK, project_name=_PROJECT_NAME)

        subprocess_mgr.spawn.assert_not_called()

    async def test_uses_exec_allowed_tools(self) -> None:
        print("\n[test_uses_exec_allowed_tools]")
        tool, _, subprocess_mgr, _ = _make_tool()

        await tool.execute_run_with_shell(task=_TASK, project_name=_PROJECT_NAME)

        call_kwargs = subprocess_mgr.spawn.call_args.kwargs
        # exec_allowed_tools defaults include Bash
        assert "Bash" in call_kwargs["allowed_tools"]


class TestExecuteGitCommit:
    """cc_git_commit handler: system-constructed git commit task."""

    async def test_spawns_with_commit_task(self) -> None:
        print("\n[test_spawns_with_commit_task]")
        tool, _, subprocess_mgr, plan_reviewer = _make_tool()

        await tool.execute_git_commit(
            project_name=_PROJECT_NAME, message="feat: add hello endpoint"
        )

        plan_reviewer.review.assert_not_called()
        call_kwargs = subprocess_mgr.spawn.call_args.kwargs
        assert "feat: add hello endpoint" in call_kwargs["task"]
        print(f"  task snippet: {call_kwargs['task'][:80]}")

    async def test_returns_cc_result(self) -> None:
        print("\n[test_returns_cc_result]")
        tool, _, _, _ = _make_tool()

        result = await tool.execute_git_commit(
            project_name=_PROJECT_NAME, message="chore: initial commit"
        )

        assert result["type"] == "cc_result"


class TestExecuteGitPushBranch:
    """cc_git_push_branch handler: branch validation + push."""

    async def test_valid_branch_prefix_succeeds(self) -> None:
        print("\n[test_valid_branch_prefix_succeeds]")
        cfg = _make_config(project_prefix="or")
        tool, _, subprocess_mgr, _ = _make_tool(config=cfg)

        result = await tool.execute_git_push_branch(
            project_name=_PROJECT_NAME, branch="or/add-hello"
        )

        subprocess_mgr.spawn.assert_called_once()
        assert result["type"] == "cc_result"

    async def test_invalid_branch_prefix_raises(self) -> None:
        print("\n[test_invalid_branch_prefix_raises] wrong prefix → ValueError")
        cfg = _make_config(project_prefix="or")
        tool, _, subprocess_mgr, _ = _make_tool(config=cfg)

        with pytest.raises(ValueError, match="project prefix"):
            await tool.execute_git_push_branch(project_name=_PROJECT_NAME, branch="main")

        subprocess_mgr.spawn.assert_not_called()

    async def test_main_branch_rejected(self) -> None:
        print("\n[test_main_branch_rejected] pushing to main → ValueError")
        tool, _, subprocess_mgr, _ = _make_tool()

        with pytest.raises(ValueError):
            await tool.execute_git_push_branch(project_name=_PROJECT_NAME, branch="main")

    async def test_push_task_contains_branch_name(self) -> None:
        print("\n[test_push_task_contains_branch_name]")
        cfg = _make_config(project_prefix="or")
        tool, _, subprocess_mgr, _ = _make_tool(config=cfg)

        await tool.execute_git_push_branch(project_name=_PROJECT_NAME, branch="or/my-feature")

        task_arg = subprocess_mgr.spawn.call_args.kwargs["task"]
        assert "or/my-feature" in task_arg


class TestExecutePromoteRequest:
    """cc_promote_request handler: returns intent dict without spawning CC."""

    async def test_returns_intent_dict(self) -> None:
        print("\n[test_returns_intent_dict]")
        tool, _, subprocess_mgr, plan_reviewer = _make_tool()

        result = await tool.execute_promote_request(
            project_name=_PROJECT_NAME, branch="or/add-hello", target="main"
        )

        print(f"  result={result}")
        assert result["type"] == "cc_promote_request"
        assert result["status"] == "approved"
        assert result["branch"] == "or/add-hello"
        assert result["target"] == "main"
        assert result["project_name"] == _PROJECT_NAME

    async def test_no_spawn_for_promote(self) -> None:
        print("\n[test_no_spawn_for_promote] promote intent → no CC subprocess")
        tool, _, subprocess_mgr, _ = _make_tool()

        await tool.execute_promote_request(
            project_name=_PROJECT_NAME, branch="or/feature", target="main"
        )

        subprocess_mgr.spawn.assert_not_called()

    async def test_default_target_is_main(self) -> None:
        print("\n[test_default_target_is_main]")
        tool, _, _, _ = _make_tool()

        result = await tool.execute_promote_request(project_name=_PROJECT_NAME, branch="or/feature")

        assert result["target"] == "main"


# ---------------------------------------------------------------------------
# RegisterHandlers
# ---------------------------------------------------------------------------


class TestRegisterHandlers:
    """register_handlers() wires handler callables into the registry."""

    def test_all_handlers_registered(self) -> None:
        print("\n[test_all_handlers_registered]")
        registry = ToolRegistry()
        register_cc_tools(registry)

        tool, _, _, _ = _make_tool()
        tool.register_handlers(registry)

        expected = [
            "cc_write_task",
            "cc_read_analyze",
            "cc_run_with_shell",
            "cc_git_commit",
            "cc_git_push_branch",
            "cc_promote_request",
        ]
        for name in expected:
            handler = registry.get_handler(name)
            assert handler is not None, f"handler for {name!r} not registered"
            print(f"  {name}: handler={handler.__name__}")

    def test_bypass_permissions_has_no_handler(self) -> None:
        print("\n[test_bypass_permissions_has_no_handler]")
        registry = ToolRegistry()
        register_cc_tools(registry)

        tool, _, _, _ = _make_tool()
        tool.register_handlers(registry)

        # The dead-stop sentinel should have no handler (dead stop fires first)
        handler = registry.get_handler("cc_bypass_permissions")
        assert handler is None
        print("  cc_bypass_permissions correctly has no handler")

    def test_warn_when_definition_missing(self, caplog: Any) -> None:
        print("\n[test_warn_when_definition_missing]")
        registry = ToolRegistry()
        # Intentionally do NOT call register_cc_tools — definitions are absent.
        tool, _, _, _ = _make_tool()

        import logging

        with caplog.at_level(logging.WARNING):
            tool.register_handlers(registry)

        assert any("not found" in record.message for record in caplog.records)
        print("  warning logged for missing definitions")


# ---------------------------------------------------------------------------
# ToolExecutor integration tests
# ---------------------------------------------------------------------------

_AUDIT_PATH = Path("C:/dev/null/test-audit.jsonl")


def _make_agent(session_key: str = "sess:main:001") -> AgentConfig:
    return AgentConfig(
        agent_id="agent:test:main",
        name="TestAgent",
        description="Test agent",
        model="anthropic/claude-test",
        trust_level=TrustLevel.main,
        session_key=session_key,
        allowed_tools=list(t.name for t in ALL_CC_TOOLS),
    )


def _make_tool_call(
    tool_name: str,
    arguments: dict[str, Any],
    call_id: str = "call-001",
) -> ToolCall:
    return ToolCall(tool_name=tool_name, arguments=arguments, call_id=call_id)


class TestDeadStopViaExecutor:
    """cc_bypass_permissions dead stop fires before any handler."""

    async def test_dead_stop_returns_error_result(self, tmp_path: Path) -> None:
        print("\n[test_dead_stop_returns_error_result]")
        audit = AuditLog(tmp_path / "audit.jsonl")
        registry = ToolRegistry()
        register_cc_tools(registry)

        tool, _, subprocess_mgr, _ = _make_tool()
        tool.register_handlers(registry)

        executor = ToolExecutor(registry=registry, audit_log=audit)
        agent = _make_agent()
        call = _make_tool_call("cc_bypass_permissions", {})

        result: ToolResult = await executor.execute(agent, call)

        print(f"  result.success={result.success}, error={result.error}")
        assert result.success is False
        assert "cc_bypass_permissions" in (result.error or "").lower()
        subprocess_mgr.spawn.assert_not_called()

    async def test_dead_stop_logged_to_audit(self, tmp_path: Path) -> None:
        print("\n[test_dead_stop_logged_to_audit]")
        audit = AuditLog(tmp_path / "audit.jsonl")
        registry = ToolRegistry()
        register_cc_tools(registry)

        tool, _, _, _ = _make_tool()
        tool.register_handlers(registry)

        executor = ToolExecutor(registry=registry, audit_log=audit)
        agent = _make_agent()
        call = _make_tool_call("cc_bypass_permissions", {})

        await executor.execute(agent, call)

        lines = (tmp_path / "audit.jsonl").read_text().strip().splitlines()
        assert any("dead_stop_blocked" in line for line in lines)
        print(f"  audit contains dead_stop_blocked: True")


class TestCCReadAnalyzeViaExecutor:
    """cc_read_analyze flows through executor without plan review."""

    async def test_executor_returns_success_result(self, tmp_path: Path) -> None:
        print("\n[test_executor_returns_success_result]")
        audit = AuditLog(tmp_path / "audit.jsonl")
        registry = ToolRegistry()
        register_cc_tools(registry)

        tool, _, subprocess_mgr, plan_reviewer = _make_tool()
        tool.register_handlers(registry)

        executor = ToolExecutor(registry=registry, audit_log=audit)
        agent = _make_agent()
        call = _make_tool_call(
            "cc_read_analyze",
            {"task": "Review the codebase", "project_name": "my-proj"},
        )

        result: ToolResult = await executor.execute(agent, call)

        print(f"  result.success={result.success}")
        assert result.success is True
        assert isinstance(result.result, dict)
        assert result.result["type"] == "cc_result"
        plan_reviewer.review.assert_not_called()
        print("  plan reviewer not called (read-only)")


class TestCCTimeoutViaHandler:
    """CC timeout surfaces as a ToolResult error via executor."""

    async def test_timeout_returns_error_via_executor(self, tmp_path: Path) -> None:
        print("\n[test_timeout_returns_error_via_executor]")
        audit = AuditLog(tmp_path / "audit.jsonl")
        registry = ToolRegistry()
        register_cc_tools(registry)

        tool, _, _, _ = _make_tool(
            cc_stdout="",
            cc_error="CC session timed out after 300s. The process was killed.",
        )
        tool.register_handlers(registry)

        executor = ToolExecutor(registry=registry, audit_log=audit)
        agent = _make_agent()
        call = _make_tool_call(
            "cc_read_analyze",
            {"task": "Analyze app.py", "project_name": "my-proj"},
        )

        result: ToolResult = await executor.execute(agent, call)

        print(f"  result.success={result.success}, error={result.error!r}")
        assert result.success is False
        assert "timed out" in (result.error or "")


class TestCCEnabledFalseViaExecutor:
    """When cc.enabled=False, cc_* tools are not registered → unknown-tool error."""

    async def test_unknown_tool_error_when_disabled(self, tmp_path: Path) -> None:
        print("\n[test_unknown_tool_error_when_disabled] cc disabled → unknown-tool error")
        audit = AuditLog(tmp_path / "audit.jsonl")
        registry = ToolRegistry()
        # Simulate the disabled path: register_cc_tools() NOT called

        executor = ToolExecutor(registry=registry, audit_log=audit)
        agent = _make_agent()
        call = _make_tool_call("cc_write_task", {"task": "Do something", "project_name": "proj"})

        result: ToolResult = await executor.execute(agent, call)

        print(f"  result.success={result.success}, error={result.error!r}")
        assert result.success is False
        assert "Unknown tool" in (result.error or "")
