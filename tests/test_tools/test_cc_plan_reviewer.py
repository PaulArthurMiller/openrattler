"""Tests for CCPlanReviewer (piece 40.4).

All external calls are mocked:
- ``CCSubprocessManager.spawn`` — returns a ``CCResult`` with controlled stdout.
- ``ApprovalManager.request_approval`` — returns a controlled ``ApprovalResult``.
- ``ApprovalThresholdPolicy.requires_approval`` — returns a controlled bool.

No real CC binary, no real approval handler, and no real file I/O are used.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from openrattler.config.loader import CCConfig
from openrattler.security.action_levels import ApprovalThresholdPolicy
from openrattler.security.approval import ApprovalResult
from openrattler.tools.claude_code.output_parser import CCOutputParser
from openrattler.tools.claude_code.plan_reviewer import (
    CCPlanReviewer,
    PlanReviewResult,
    _PLAN_PHASE_TOOLS,
    _PLAN_PROMPT_PREFIX,
)
from openrattler.tools.claude_code.subprocess_mgr import CCResult

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_PROJECT_PATH = Path("C:/fake/workspace/or-auth-fix")
_ENV: dict[str, str] = {
    "CLAUDE_CONFIG_DIR": "C:/fake/workspace/.claude",
    "GIT_AUTHOR_NAME": "Test Bot",
    "GIT_AUTHOR_EMAIL": "testbot@local",
}
_TASK = "Fix the login validation bug in auth/validator.py"

_PLAN_TEXT = (
    "I will modify auth/validator.py to fix the null-check in validate_token().\n"
    "Files to modify: auth/validator.py\n"
    "Files to create: tests/test_auth_regression.py\n"
    "Shell commands: none\n"
    "Reasoning: The bug is caused by a missing None guard before calling .split()."
)


def _make_config(**overrides: Any) -> CCConfig:
    defaults: dict[str, Any] = dict(
        enabled=True,
        workspace_root="C:/fake/workspace",
        assistant_name="TestBot",
        project_prefix="tb",
        git_author_name="TestBot (Claude Code)",
        git_author_email="testbot@local",
        plan_review_enabled=True,
        plan_review_approval_level=3,
        plan_review_timeout_seconds=120,
        session_timeout_seconds=300,
        claude_binary="claude",
    )
    defaults.update(overrides)
    return CCConfig(**defaults)


def _make_cc_result(plan_text: str = _PLAN_TEXT, is_error: bool = False) -> CCResult:
    """Return a CCResult whose stdout is CC's --output-format json payload."""
    payload = {
        "type": "result",
        "subtype": "success" if not is_error else "error_during_execution",
        "result": plan_text,
        "session_id": "mock-session-abc",
        "cost_usd": 0.002,
        "num_turns": 2,
        "is_error": is_error,
    }
    return CCResult(stdout=json.dumps(payload), returncode=0)


def _make_approval_result(approved: bool) -> ApprovalResult:
    return ApprovalResult(
        approval_id="plan-approval-001",
        approved=approved,
        decided_by="cli:user" if approved else "cli:user",
        timestamp=datetime.now(timezone.utc),
        approval_token="fake-token" if approved else None,
        token_expiry=None,
    )


def _make_policy(requires: bool) -> MagicMock:
    policy = MagicMock(spec=ApprovalThresholdPolicy)
    policy.requires_approval.return_value = requires
    policy.threshold = 3
    return policy


def _make_subprocess_mgr(result: CCResult) -> MagicMock:
    mgr = MagicMock()
    mgr.spawn = AsyncMock(return_value=result)
    return mgr


def _make_approval_manager(result: ApprovalResult) -> MagicMock:
    mgr = MagicMock()
    mgr.request_approval = AsyncMock(return_value=result)
    return mgr


def _make_reviewer(
    *,
    cc_result: CCResult | None = None,
    approval_approved: bool = True,
    policy_requires: bool = True,
    config_overrides: dict[str, Any] | None = None,
) -> tuple[CCPlanReviewer, MagicMock, MagicMock]:
    """Create a CCPlanReviewer with all dependencies mocked.

    Returns (reviewer, subprocess_mgr_mock, approval_manager_mock).
    """
    if cc_result is None:
        cc_result = _make_cc_result()
    subprocess_mgr = _make_subprocess_mgr(cc_result)
    approval_manager = _make_approval_manager(_make_approval_result(approval_approved))
    config = _make_config(**(config_overrides or {}))
    policy = _make_policy(policy_requires)
    reviewer = CCPlanReviewer(
        subprocess_mgr=subprocess_mgr,
        approval_manager=approval_manager,
        config=config,
        policy=policy,
    )
    return reviewer, subprocess_mgr, approval_manager


# ---------------------------------------------------------------------------
# Tests: plan review disabled
# ---------------------------------------------------------------------------


async def test_review_disabled_returns_approved_true_immediately() -> None:
    """When plan_review_enabled=False, return approved=True without any subprocess."""
    reviewer, subprocess_mgr, approval_manager = _make_reviewer(
        config_overrides={"plan_review_enabled": False}
    )

    result = await reviewer.review(task=_TASK, project_path=_PROJECT_PATH, env=_ENV)

    assert result.approved is True
    assert result.plan is None
    # No subprocess was spawned and no approval was requested.
    subprocess_mgr.spawn.assert_not_called()
    approval_manager.request_approval.assert_not_called()


async def test_review_disabled_does_not_call_approval_manager() -> None:
    """Disabled plan review never touches the approval manager."""
    reviewer, _, approval_manager = _make_reviewer(config_overrides={"plan_review_enabled": False})
    await reviewer.review(task=_TASK, project_path=_PROJECT_PATH, env=_ENV)
    approval_manager.request_approval.assert_not_called()


# ---------------------------------------------------------------------------
# Tests: read-only tool list
# ---------------------------------------------------------------------------


async def test_review_passes_readonly_tools_to_subprocess() -> None:
    """The read-only tool list is passed to spawn; write tools must not appear."""
    reviewer, subprocess_mgr, _ = _make_reviewer()
    await reviewer.review(task=_TASK, project_path=_PROJECT_PATH, env=_ENV)

    call_args = subprocess_mgr.spawn.call_args
    allowed_tools: list[str] = call_args.kwargs.get("allowed_tools") or call_args.args[2]
    assert set(allowed_tools) == set(_PLAN_PHASE_TOOLS)
    assert "Write" not in allowed_tools
    assert "Bash" not in allowed_tools


async def test_readonly_tool_list_contains_expected_tools() -> None:
    """The plan-phase tool constant includes only read-only CC tools."""
    assert "Read" in _PLAN_PHASE_TOOLS
    assert "Glob" in _PLAN_PHASE_TOOLS
    assert "Grep" in _PLAN_PHASE_TOOLS
    assert "LS" in _PLAN_PHASE_TOOLS
    assert "Write" not in _PLAN_PHASE_TOOLS
    assert "Bash" not in _PLAN_PHASE_TOOLS


# ---------------------------------------------------------------------------
# Tests: plan prompt prefix
# ---------------------------------------------------------------------------


async def test_review_prefixes_task_with_plan_prompt() -> None:
    """The task passed to spawn should begin with the plan-phase instruction."""
    reviewer, subprocess_mgr, _ = _make_reviewer()
    await reviewer.review(task=_TASK, project_path=_PROJECT_PATH, env=_ENV)

    call_args = subprocess_mgr.spawn.call_args
    spawned_task: str = call_args.kwargs.get("task") or call_args.args[0]
    assert spawned_task.startswith(_PLAN_PROMPT_PREFIX)
    assert _TASK in spawned_task


async def test_plan_prompt_contains_do_not_change_instruction() -> None:
    """Plan prompt instructs CC not to make changes."""
    assert "Do not make any changes" in _PLAN_PROMPT_PREFIX


# ---------------------------------------------------------------------------
# Tests: approval when required by policy
# ---------------------------------------------------------------------------


async def test_review_enabled_approval_granted_returns_approved_true() -> None:
    """When plan review is enabled and approval is granted, return approved=True."""
    reviewer, _, _ = _make_reviewer(approval_approved=True, policy_requires=True)
    result = await reviewer.review(task=_TASK, project_path=_PROJECT_PATH, env=_ENV)

    assert result.approved is True
    assert result.plan == _PLAN_TEXT


async def test_review_enabled_approval_denied_returns_approved_false() -> None:
    """When the user denies the plan, return approved=False."""
    reviewer, _, _ = _make_reviewer(approval_approved=False, policy_requires=True)
    result = await reviewer.review(task=_TASK, project_path=_PROJECT_PATH, env=_ENV)

    assert result.approved is False
    assert result.plan == _PLAN_TEXT


async def test_review_calls_approval_manager_when_policy_requires_it() -> None:
    """When policy.requires_approval returns True, request_approval must be called."""
    reviewer, _, approval_manager = _make_reviewer(policy_requires=True)
    await reviewer.review(task=_TASK, project_path=_PROJECT_PATH, env=_ENV)

    approval_manager.request_approval.assert_called_once()


# ---------------------------------------------------------------------------
# Tests: plan text in ApprovalRequest
# ---------------------------------------------------------------------------


async def test_plan_text_appears_in_approval_request_context() -> None:
    """Plan text must appear in context (action block), not only in rationale."""
    reviewer, _, approval_manager = _make_reviewer(policy_requires=True)
    await reviewer.review(task=_TASK, project_path=_PROJECT_PATH, env=_ENV)

    request = approval_manager.request_approval.call_args.args[0]
    # Plan text must be in context (displayed as action description).
    assert "plan" in request.context
    assert _PLAN_TEXT in request.context["plan"]


async def test_plan_approval_request_has_correct_operation() -> None:
    """ApprovalRequest.operation must be 'cc_plan_review'."""
    reviewer, _, approval_manager = _make_reviewer(policy_requires=True)
    await reviewer.review(task=_TASK, project_path=_PROJECT_PATH, env=_ENV)

    request = approval_manager.request_approval.call_args.args[0]
    assert request.operation == "cc_plan_review"


async def test_plan_approval_request_action_level_matches_config() -> None:
    """ApprovalRequest.action_level must match plan_review_approval_level from config."""
    reviewer, _, approval_manager = _make_reviewer(
        policy_requires=True,
        config_overrides={"plan_review_approval_level": 2},
    )
    await reviewer.review(task=_TASK, project_path=_PROJECT_PATH, env=_ENV)

    request = approval_manager.request_approval.call_args.args[0]
    assert request.action_level == 2


async def test_plan_approval_request_rationale_contains_task() -> None:
    """ApprovalRequest.rationale must include the original task description."""
    reviewer, _, approval_manager = _make_reviewer(policy_requires=True)
    await reviewer.review(task=_TASK, project_path=_PROJECT_PATH, env=_ENV)

    request = approval_manager.request_approval.call_args.args[0]
    assert _TASK in (request.rationale or "")


async def test_plan_approval_request_timeout_matches_config() -> None:
    """ApprovalRequest.timeout_seconds must come from plan_review_timeout_seconds."""
    reviewer, _, approval_manager = _make_reviewer(
        policy_requires=True,
        config_overrides={"plan_review_timeout_seconds": 60},
    )
    await reviewer.review(task=_TASK, project_path=_PROJECT_PATH, env=_ENV)

    request = approval_manager.request_approval.call_args.args[0]
    assert request.timeout_seconds == 60


# ---------------------------------------------------------------------------
# Tests: policy auto-approval
# ---------------------------------------------------------------------------


async def test_review_auto_approved_when_policy_does_not_require_approval() -> None:
    """When policy says no approval needed, return approved=True without calling manager."""
    reviewer, _, approval_manager = _make_reviewer(policy_requires=False)
    result = await reviewer.review(task=_TASK, project_path=_PROJECT_PATH, env=_ENV)

    assert result.approved is True
    assert result.plan == _PLAN_TEXT
    approval_manager.request_approval.assert_not_called()


async def test_review_subprocess_still_runs_when_policy_does_not_require_approval() -> None:
    """Even when policy auto-approves, CC read-only plan phase must still run."""
    reviewer, subprocess_mgr, _ = _make_reviewer(policy_requires=False)
    await reviewer.review(task=_TASK, project_path=_PROJECT_PATH, env=_ENV)

    subprocess_mgr.spawn.assert_called_once()


# ---------------------------------------------------------------------------
# Tests: error handling
# ---------------------------------------------------------------------------


async def test_review_returns_not_approved_when_cc_returns_error() -> None:
    """If CC's plan phase returns an error, return approved=False with plan=None."""
    error_result = _make_cc_result(is_error=True, plan_text="something went wrong")
    reviewer, _, approval_manager = _make_reviewer(cc_result=error_result)
    result = await reviewer.review(task=_TASK, project_path=_PROJECT_PATH, env=_ENV)

    assert result.approved is False
    assert result.plan is None
    # No approval request should be raised for a failed plan phase.
    approval_manager.request_approval.assert_not_called()


async def test_review_returns_not_approved_when_cc_produces_empty_output() -> None:
    """If CC produces no stdout, return approved=False."""
    empty_result = CCResult(stdout="", returncode=0)
    reviewer, _, approval_manager = _make_reviewer(cc_result=empty_result)
    result = await reviewer.review(task=_TASK, project_path=_PROJECT_PATH, env=_ENV)

    assert result.approved is False
    assert result.plan is None
    approval_manager.request_approval.assert_not_called()


async def test_review_returns_not_approved_when_cc_produces_invalid_json() -> None:
    """If CC produces non-JSON output, return approved=False."""
    bad_result = CCResult(stdout="this is not json", returncode=0)
    reviewer, _, approval_manager = _make_reviewer(cc_result=bad_result)
    result = await reviewer.review(task=_TASK, project_path=_PROJECT_PATH, env=_ENV)

    assert result.approved is False
    assert result.plan is None


# ---------------------------------------------------------------------------
# Tests: project path and env forwarded correctly
# ---------------------------------------------------------------------------


async def test_review_passes_project_path_to_subprocess() -> None:
    """project_path must be forwarded to subprocess_mgr.spawn unchanged."""
    reviewer, subprocess_mgr, _ = _make_reviewer()
    await reviewer.review(task=_TASK, project_path=_PROJECT_PATH, env=_ENV)

    call_args = subprocess_mgr.spawn.call_args
    spawned_path = call_args.kwargs.get("project_path") or call_args.args[1]
    assert spawned_path == _PROJECT_PATH


async def test_review_passes_env_to_subprocess() -> None:
    """env dict must be forwarded to subprocess_mgr.spawn unchanged."""
    reviewer, subprocess_mgr, _ = _make_reviewer()
    await reviewer.review(task=_TASK, project_path=_PROJECT_PATH, env=_ENV)

    call_args = subprocess_mgr.spawn.call_args
    spawned_env = call_args.kwargs.get("env") or call_args.args[3]
    assert spawned_env == _ENV


# ---------------------------------------------------------------------------
# Tests: PlanReviewResult shape
# ---------------------------------------------------------------------------


def test_plan_review_result_approved_false_has_correct_shape() -> None:
    result = PlanReviewResult(approved=False, plan=None)
    assert result.approved is False
    assert result.plan is None


def test_plan_review_result_approved_true_with_plan() -> None:
    result = PlanReviewResult(approved=True, plan="step 1: do stuff")
    assert result.approved is True
    assert result.plan == "step 1: do stuff"
