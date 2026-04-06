"""Smoketest for the Universal Action Approval Framework (39.1–39.5).

Run with:
    .venv/Scripts/python smoketest_approval.py

Tests three scenarios against the real executor + approval stack:
  1. Level-5 tool (file_read)  — auto-approved, no prompt
  2. Level-3 tool (file_write) — prompted, approved  → file written
  3. Level-3 tool (file_write) — prompted, denied    → file NOT written

CLIApprovalHandler._read_input is patched to simulate y/n responses so the
test can run non-interactively in the sandbox.  All other code paths are real:
real ToolExecutor, real ApprovalManager, real ApprovalThresholdPolicy, real
file I/O, real audit logging.
"""

from __future__ import annotations

import asyncio
import sys
import tempfile
from pathlib import Path
from unittest.mock import patch

from openrattler.models.agents import AgentConfig, TrustLevel
from openrattler.models.tools import ToolCall
from openrattler.security.action_levels import ApprovalThresholdPolicy
from openrattler.security.approval import ApprovalHandlerRouter, ApprovalManager, CLIApprovalHandler
from openrattler.storage.audit import AuditLog
from openrattler.tools.executor import ToolExecutor
from openrattler.tools.registry import ToolRegistry
import openrattler.tools.builtin.file_ops as file_ops_module
from openrattler.tools.builtin.file_ops import configure_allowed_directories


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
        agent_id="agent:smoketest:main",
        name="Smoketest",
        description="Smoketest agent for approval framework",
        model="test-model",
        trust_level=TrustLevel.main,
        allowed_tools=["file_read", "file_write"],
        session_key="smoketest:session",
    )


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------


async def run_tests(tmp_path: Path) -> None:
    # --- Configure file I/O allowlist to the temp dir ---
    configure_allowed_directories([tmp_path])

    # --- Wire approval system (mirrors standard profile: threshold=3) ---
    audit = AuditLog(tmp_path / "audit.jsonl")
    manager = ApprovalManager(audit, default_timeout_seconds=10)
    policy = ApprovalThresholdPolicy(threshold=3)  # standard profile
    # Preferred channel "cli" with no Slack/Email — CLIApprovalHandler is the fallback
    router = ApprovalHandlerRouter(preferred_channel="cli", handlers={})
    manager.set_handler(router)

    # --- Build registry with real file tools ---
    # Register via the _tool_definition attribute attached by the @tool decorator.
    # This is import-order-safe: no dependency on _default_registry state.
    registry = ToolRegistry()
    registry.register(file_ops_module.file_read._tool_definition, file_ops_module.file_read)  # type: ignore[attr-defined]
    registry.register(file_ops_module.file_write._tool_definition, file_ops_module.file_write)  # type: ignore[attr-defined]

    executor = ToolExecutor(registry, audit, approval_manager=manager, policy=policy)
    agent = _make_agent()

    # -----------------------------------------------------------------------
    # Test 1: Level-5 tool (file_read) — should auto-approve, no prompt
    # -----------------------------------------------------------------------
    print("\n" + "=" * 60)
    print("TEST 1: file_read (level 5) — expect auto-approve, no prompt shown")
    print("=" * 60)

    test_file = tmp_path / "hello.txt"
    test_file.write_text("hello from the smoketest", encoding="utf-8")

    prompt_fired = False

    def _track_and_approve() -> str:
        nonlocal prompt_fired
        prompt_fired = True
        return "y"

    with patch.object(CLIApprovalHandler, "_read_input", staticmethod(_track_and_approve)):
        call1 = ToolCall(call_id="t1", tool_name="file_read", arguments={"path": str(test_file)})
        result1 = await executor.execute(agent, call1)

    if result1.success and not prompt_fired and result1.result == "hello from the smoketest":
        log_result(
            "file_read auto-approved (level 5, threshold 3)",
            True,
            f"Result: {result1.result!r}",
        )
    else:
        log_result(
            "file_read auto-approved (level 5, threshold 3)",
            False,
            f"success={result1.success}  prompt_shown={prompt_fired}  error={result1.error!r}",
        )

    # -----------------------------------------------------------------------
    # Test 2: Level-3 tool (file_write) — prompt shown, user approves
    # -----------------------------------------------------------------------
    print("\n" + "=" * 60)
    print("TEST 2: file_write (level 3) — prompt shown, simulating 'y'")
    print("=" * 60)

    approved_file = tmp_path / "approved.txt"
    approve_prompt_fired = False

    def _approve() -> str:
        nonlocal approve_prompt_fired
        approve_prompt_fired = True
        print("       [SMOKETEST] Simulating user input: y")
        return "y"

    with patch.object(CLIApprovalHandler, "_read_input", staticmethod(_approve)):
        call2 = ToolCall(
            call_id="t2",
            tool_name="file_write",
            arguments={"path": str(approved_file), "content": "smoketest-approved"},
        )
        result2 = await executor.execute(agent, call2)

    file_written = approved_file.exists() and approved_file.read_text(encoding="utf-8") == "smoketest-approved"
    if result2.success and approve_prompt_fired and file_written:
        log_result(
            "file_write approved -> file written (level 3, threshold 3)",
            True,
            f"File content: {approved_file.read_text(encoding='utf-8')!r}",
        )
    else:
        log_result(
            "file_write approved -> file written (level 3, threshold 3)",
            False,
            f"success={result2.success}  prompt_shown={approve_prompt_fired}  "
            f"file_exists={approved_file.exists()}  error={result2.error!r}",
        )

    # -----------------------------------------------------------------------
    # Test 3: Level-3 tool (file_write) — prompt shown, user denies
    # -----------------------------------------------------------------------
    print("\n" + "=" * 60)
    print("TEST 3: file_write (level 3) — prompt shown, simulating 'n'")
    print("=" * 60)

    denied_file = tmp_path / "denied.txt"
    deny_prompt_fired = False

    def _deny() -> str:
        nonlocal deny_prompt_fired
        deny_prompt_fired = True
        print("       [SMOKETEST] Simulating user input: n")
        return "n"

    with patch.object(CLIApprovalHandler, "_read_input", staticmethod(_deny)):
        call3 = ToolCall(
            call_id="t3",
            tool_name="file_write",
            arguments={"path": str(denied_file), "content": "should-not-exist"},
        )
        result3 = await executor.execute(agent, call3)

    file_not_written = not denied_file.exists()
    if not result3.success and deny_prompt_fired and file_not_written:
        log_result(
            "file_write denied -> execution blocked (level 3, threshold 3)",
            True,
            f"Error: {result3.error!r}",
        )
    else:
        log_result(
            "file_write denied -> execution blocked (level 3, threshold 3)",
            False,
            f"success={result3.success}  prompt_shown={deny_prompt_fired}  "
            f"file_exists={denied_file.exists()}  error={result3.error!r}",
        )


async def main() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        await run_tests(Path(tmp))

    # --- Summary ---
    print("\n" + "=" * 60)
    print("SMOKE TEST SUMMARY")
    print("=" * 60)
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
