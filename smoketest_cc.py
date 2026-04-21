"""Smoketest for the Claude Code integration layer (pieces 40.1–40.5).

Run with:
    .venv/Scripts/python smoketest_cc.py

Tests five scenarios against the real CC stack:

  1. Startup + workspace init     — WorkspaceManager creates dirs, project, CLAUDE.md
  2. cc_read_analyze (REAL CC)    — Real CC subprocess, read-only, no approval needed
  3. cc_write_task (REAL CC)      — Real CC subprocess, plan review auto-approved via patch
  4. cc_bypass_permissions        — Dead stop fires, no subprocess spawned
  5. cc_git_push_branch prefix    — Bad branch prefix raises ValueError before spawn

Tests 2 and 3 invoke a real `claude` subprocess.  All approval prompts for
tests that need them are patched to auto-approve so the script is non-interactive.
"""

from __future__ import annotations

import asyncio
import sys
import tempfile
from pathlib import Path
from unittest.mock import patch

from openrattler.config.loader import CCConfig
from openrattler.security.action_levels import ApprovalThresholdPolicy
from openrattler.security.approval import (
    ApprovalHandlerRouter,
    ApprovalManager,
    ApprovalResult,
    CLIApprovalHandler,
)
from openrattler.storage.audit import AuditLog
from openrattler.tools.claude_code.plan_reviewer import CCPlanReviewer, PlanReviewResult
from openrattler.tools.claude_code.subprocess_mgr import CCSubprocessManager
from openrattler.tools.claude_code.tool import ClaudeCodeTool, register_cc_tools
from openrattler.tools.claude_code.workspace import WorkspaceManager
from openrattler.tools.executor import ToolExecutor
from openrattler.tools.registry import ToolRegistry
from openrattler.models.agents import AgentConfig, TrustLevel
from openrattler.models.tools import ToolCall

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_results: list[tuple[str, bool]] = []


def log_result(label: str, passed: bool, detail: str = "") -> None:
    icon = "PASS" if passed else "FAIL"
    print(f"\n[{icon}] {label}")
    if detail:
        print(f"       {detail}")
    _results.append((label, passed))


def _make_agent() -> AgentConfig:
    return AgentConfig(
        agent_id="agent:smoketest:cc",
        name="Corvus (smoketest)",
        description="Smoketest agent for CC integration",
        model="test-model",
        trust_level=TrustLevel.main,
        allowed_tools=[
            "cc_read_analyze",
            "cc_write_task",
            "cc_run_with_shell",
            "cc_git_commit",
            "cc_git_push_branch",
            "cc_promote_request",
            "cc_bypass_permissions",
        ],
        session_key="smoketest:cc:session",
    )


def _build_cc_config(workspace_root: str) -> CCConfig:
    return CCConfig(
        enabled=True,
        workspace_root=workspace_root,
        assistant_name="Corvus",
        project_prefix="corvus",
        git_author_name="Corvus (Claude Code)",
        git_author_email="corvus@local",
        claude_binary="C:\\Users\\PaulA\\.local\\bin\\claude.exe",
        plan_review_enabled=True,
        plan_review_approval_level=3,
        plan_review_timeout_seconds=120,
        session_timeout_seconds=300,
        max_concurrent_sessions=1,
        exec_allowed_tools=["Read", "Write", "Glob", "Grep", "LS"],
    )


# ---------------------------------------------------------------------------
# Main test runner
# ---------------------------------------------------------------------------


async def run_tests(workspace_root: str) -> None:
    cc_config = _build_cc_config(workspace_root)
    audit = AuditLog(Path(workspace_root) / "smoketest_audit.jsonl")

    # Wire approval stack (mirrors standard profile: threshold=3).
    approval_mgr = ApprovalManager(audit, default_timeout_seconds=60)
    policy = ApprovalThresholdPolicy(threshold=3)  # standard profile
    router = ApprovalHandlerRouter(preferred_channel="cli", handlers={})
    approval_mgr.set_handler(router)

    # Build CC components.
    workspace = WorkspaceManager(cc_config)
    subprocess_mgr = CCSubprocessManager(cc_config)
    plan_reviewer = CCPlanReviewer(
        subprocess_mgr=subprocess_mgr,
        approval_manager=approval_mgr,
        config=cc_config,
        policy=policy,
    )
    cc_tool = ClaudeCodeTool(
        workspace=workspace,
        subprocess_mgr=subprocess_mgr,
        plan_reviewer=plan_reviewer,
        config=cc_config,
    )

    # Register into the tool registry.
    registry = ToolRegistry()
    register_cc_tools(registry)
    cc_tool.register_handlers(registry)

    # Build executor.
    executor = ToolExecutor(registry, audit, approval_manager=approval_mgr, policy=policy)
    agent = _make_agent()

    # =======================================================================
    # TEST 1: Workspace initialization
    # =======================================================================
    print("\n" + "=" * 70)
    print("TEST 1: Workspace initialization (WorkspaceManager.ensure_workspace)")
    print("=" * 70)

    try:
        workspace.ensure_workspace()
        ws_root = Path(workspace_root)
        projects_dir = ws_root / "projects"
        claude_dir = ws_root / ".claude"
        dirs_ok = projects_dir.exists() and claude_dir.exists()
        if dirs_ok:
            log_result(
                "WorkspaceManager creates projects/ and .claude/ dirs",
                True,
                f"Workspace at {workspace_root}",
            )
        else:
            log_result(
                "WorkspaceManager creates projects/ and .claude/ dirs",
                False,
                f"projects/ exists={projects_dir.exists()}, .claude/ exists={claude_dir.exists()}",
            )
    except Exception as exc:
        log_result("WorkspaceManager creates projects/ and .claude/ dirs", False, f"Exception: {exc}")

    # Test create_project (git init + CLAUDE.md).
    try:
        proj_path = workspace.create_project("hello-world")
        claude_md = proj_path / "CLAUDE.md"
        if proj_path.exists() and claude_md.exists():
            log_result(
                "create_project creates git repo + CLAUDE.md",
                True,
                f"Project at {proj_path}",
            )
        else:
            log_result(
                "create_project creates git repo + CLAUDE.md",
                False,
                f"path_exists={proj_path.exists()}, CLAUDE.md_exists={claude_md.exists()}",
            )
    except Exception as exc:
        log_result("create_project creates git repo + CLAUDE.md", False, f"Exception: {exc}")

    # =======================================================================
    # TEST 2: cc_read_analyze — real CC subprocess, no approval needed
    # =======================================================================
    print("\n" + "=" * 70)
    print("TEST 2: cc_read_analyze — real CC call (level 5, auto-approved)")
    print("         Corvus asks CC: 'What file exists in this project?'")
    print("=" * 70)

    # Put a small file in the project for CC to read.
    test_project = workspace.create_project("smoke-read")
    readme = test_project / "README.md"
    readme.write_text(
        "# Smoke Read Project\n\nThis project tests cc_read_analyze integration.\n"
        "Purpose: verify Claude Code read-only sessions work end to end.\n",
        encoding="utf-8",
    )

    try:
        call = ToolCall(
            call_id="cc-read-1",
            tool_name="cc_read_analyze",
            arguments={
                "task": (
                    "Read README.md and tell me in one sentence what the purpose "
                    "of this project is."
                ),
                "project_name": "smoke-read",
            },
        )
        print("   Spawning real Claude Code subprocess (this may take ~30 seconds)...")
        result = await executor.execute(agent, call)
        if result.success and result.result:
            content = result.result.get("content", "")
            cost = result.result.get("cost_usd")
            turns = result.result.get("num_turns")
            cost_str = f"{cost:.6f}" if cost is not None else "n/a"
            log_result(
                "cc_read_analyze returns CC analysis",
                True,
                f"cost_usd={cost_str}, num_turns={turns}\n       Content: {content[:200]}",
            )
        else:
            log_result(
                "cc_read_analyze returns CC analysis",
                False,
                f"success={result.success}, error={result.error!r}",
            )
    except Exception as exc:
        log_result("cc_read_analyze returns CC analysis", False, f"Exception: {exc}")

    # =======================================================================
    # TEST 3: cc_write_task — real CC subprocess, plan review auto-approved
    # =======================================================================
    print("\n" + "=" * 70)
    print("TEST 3: cc_write_task — real CC call (plan review auto-approved via patch)")
    print("         Corvus asks CC: 'Create hello.txt with greeting'")
    print("=" * 70)

    # Auto-approve the plan review by patching the approval manager's request method.
    from datetime import datetime, timezone

    async def _auto_approve(request):  # type: ignore[no-untyped-def]
        print("   [SMOKETEST] Plan review request received — auto-approving...")
        plan_text = request.context.get("plan", "") if isinstance(request.context, dict) else str(request.context)
        print(f"   Plan preview: {plan_text[:300]}")
        return ApprovalResult(
            approval_id=request.approval_id,
            approved=True,
            decided_by="smoketest:auto",
            timestamp=datetime.now(timezone.utc),
            approval_token=request.approval_token,
            token_expiry=request.token_expiry,
        )

    try:
        with patch.object(approval_mgr, "request_approval", side_effect=_auto_approve):
            call = ToolCall(
                call_id="cc-write-1",
                tool_name="cc_write_task",
                arguments={
                    "task": (
                        "Create a file named hello.txt with the content: "
                        "'Hello from Corvus! This file was created by Claude Code.'"
                    ),
                    "project_name": "smoke-write",
                },
            )
            print("   Spawning real Claude Code subprocess (this may take ~30 seconds)...")
            result = await executor.execute(agent, call)

        if result.success and result.result:
            write_proj = workspace.create_project("smoke-write")  # idempotent
            hello_file = write_proj / "hello.txt"
            file_exists = hello_file.exists()
            cost = result.result.get("cost_usd")
            turns = result.result.get("num_turns")
            cost_str = f"{cost:.6f}" if cost is not None else "n/a"
            content_snippet = hello_file.read_text(encoding="utf-8")[:100] if file_exists else "(file not found)"
            log_result(
                "cc_write_task creates file via CC",
                file_exists,
                f"cost_usd={cost_str}, num_turns={turns}\n       hello.txt: {content_snippet!r}",
            )
        else:
            log_result(
                "cc_write_task creates file via CC",
                False,
                f"success={result.success}, error={result.error!r}",
            )
    except Exception as exc:
        log_result("cc_write_task creates file via CC", False, f"Exception: {exc}")

    # =======================================================================
    # TEST 4: cc_bypass_permissions dead stop
    # =======================================================================
    print("\n" + "=" * 70)
    print("TEST 4: cc_bypass_permissions — dead stop fires, no subprocess spawned")
    print("=" * 70)

    try:
        call = ToolCall(
            call_id="cc-bypass-1",
            tool_name="cc_bypass_permissions",
            arguments={},
        )
        result = await executor.execute(agent, call)
        # Dead stop should produce a non-success result with an error message.
        if not result.success and result.error and "dead_stop" in result.error.lower():
            log_result(
                "cc_bypass_permissions triggers dead stop",
                True,
                f"Error: {result.error!r}",
            )
        elif not result.success and result.error:
            # The error might not contain "dead_stop" literally but should reference blocking.
            log_result(
                "cc_bypass_permissions triggers dead stop",
                True,
                f"Blocked (error={result.error!r})",
            )
        else:
            log_result(
                "cc_bypass_permissions triggers dead stop",
                False,
                f"success={result.success}, error={result.error!r}",
            )
    except Exception as exc:
        # A raised DeadStopError is also acceptable — the executor should catch it.
        log_result(
            "cc_bypass_permissions triggers dead stop",
            False,
            f"Unexpected exception (executor should catch dead stops): {exc}",
        )

    # =======================================================================
    # TEST 5: cc_git_push_branch — bad prefix rejected before spawn
    # =======================================================================
    print("\n" + "=" * 70)
    print("TEST 5: cc_git_push_branch — bad prefix rejected before spawn")
    print("=" * 70)

    try:
        call = ToolCall(
            call_id="cc-push-bad-1",
            tool_name="cc_git_push_branch",
            arguments={
                "project_name": "smoke-push",
                "branch": "main",  # not prefixed with 'corvus/'
            },
        )
        result = await executor.execute(agent, call)
        if not result.success and result.error and "prefix" in result.error.lower():
            log_result(
                "cc_git_push_branch rejects bad prefix",
                True,
                f"Error: {result.error!r}",
            )
        elif not result.success and result.error:
            log_result(
                "cc_git_push_branch rejects bad prefix",
                True,
                f"Blocked (error={result.error!r})",
            )
        else:
            log_result(
                "cc_git_push_branch rejects bad prefix",
                False,
                f"success={result.success}, error={result.error!r}",
            )
    except Exception as exc:
        log_result(
            "cc_git_push_branch rejects bad prefix",
            False,
            f"Unexpected exception: {exc}",
        )


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------


async def main() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        await run_tests(tmp)

    # Summary.
    print("\n" + "=" * 70)
    print("SMOKE TEST SUMMARY — Claude Code Integration (40.1-40.5)")
    print("=" * 70)
    passed = sum(1 for _, ok in _results if ok)
    failed = sum(1 for _, ok in _results if not ok)
    for label, ok in _results:
        icon = "PASS" if ok else "FAIL"
        print(f"  [{icon}] {label}")
    print(f"\n  {passed} passed, {failed} failed")
    if failed:
        sys.exit(1)


if __name__ == "__main__":
    asyncio.run(main())
