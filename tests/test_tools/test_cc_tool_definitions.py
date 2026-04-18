"""Tests for cc_* tool definitions and dead-stop extensions (piece 40.2).

Verifies:
- All six cc_* tools are present in ALL_CC_TOOLS and have valid action levels.
- register_cc_tools() registers all tools into a fresh registry when enabled.
- No cc_* tools appear in the registry when CCConfig.enabled is False.
- cc_bypass_permissions and cc_push_main are in DEAD_STOP_ACTIONS.
- cc_promote_request is level 1 (always requires approval).
- cc_bypass_permissions sentinel is registered but has no handler.
- Specific action levels match the plan table.
"""

from __future__ import annotations

import pytest

from openrattler.security.action_levels import DEAD_STOP_ACTIONS
from openrattler.tools.claude_code.tool import (
    ALL_CC_TOOLS,
    CC_BYPASS_PERMISSIONS,
    CC_GIT_COMMIT,
    CC_GIT_PUSH_BRANCH,
    CC_PROMOTE_REQUEST,
    CC_READ_ANALYZE,
    CC_RUN_WITH_SHELL,
    CC_WRITE_TASK,
    register_cc_tools,
)
from openrattler.tools.registry import ToolRegistry

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _fresh_registry() -> ToolRegistry:
    return ToolRegistry()


# ---------------------------------------------------------------------------
# Dead-stop registry
# ---------------------------------------------------------------------------


class TestDeadStopExtensions:
    def test_cc_bypass_permissions_in_dead_stop_actions(self) -> None:
        assert "cc_bypass_permissions" in DEAD_STOP_ACTIONS

    def test_cc_push_main_in_dead_stop_actions(self) -> None:
        assert "cc_push_main" in DEAD_STOP_ACTIONS

    def test_dead_stop_actions_is_frozenset(self) -> None:
        assert isinstance(DEAD_STOP_ACTIONS, frozenset)

    def test_original_dead_stops_still_present(self) -> None:
        # Regression: extending DEAD_STOP_ACTIONS must not remove prior entries.
        assert "force_push_main" in DEAD_STOP_ACTIONS
        assert "drop_table" in DEAD_STOP_ACTIONS
        assert "rm_workspace_recursive" in DEAD_STOP_ACTIONS


# ---------------------------------------------------------------------------
# ALL_CC_TOOLS list
# ---------------------------------------------------------------------------


class TestAllCcTools:
    def test_all_cc_tools_contains_six_definitions(self) -> None:
        # CC_BYPASS_PERMISSIONS sentinel is included — seven total in ALL_CC_TOOLS,
        # but cc_push_main is not a registered tool (it's only in DEAD_STOP_ACTIONS).
        names = {t.name for t in ALL_CC_TOOLS}
        expected = {
            "cc_read_analyze",
            "cc_write_task",
            "cc_run_with_shell",
            "cc_git_commit",
            "cc_git_push_branch",
            "cc_promote_request",
            "cc_bypass_permissions",
        }
        assert names == expected

    def test_all_cc_tools_action_levels_in_valid_range(self) -> None:
        for tool_def in ALL_CC_TOOLS:
            assert (
                1 <= tool_def.action_level <= 5
            ), f"{tool_def.name} has action_level={tool_def.action_level} outside 1–5"

    def test_cc_read_analyze_is_level_5(self) -> None:
        assert CC_READ_ANALYZE.action_level == 5

    def test_cc_write_task_is_level_3(self) -> None:
        assert CC_WRITE_TASK.action_level == 3

    def test_cc_run_with_shell_is_level_2(self) -> None:
        assert CC_RUN_WITH_SHELL.action_level == 2

    def test_cc_git_commit_is_level_3(self) -> None:
        assert CC_GIT_COMMIT.action_level == 3

    def test_cc_git_push_branch_is_level_2(self) -> None:
        assert CC_GIT_PUSH_BRANCH.action_level == 2

    def test_cc_promote_request_is_level_1(self) -> None:
        # Always requires human approval under every profile.
        assert CC_PROMOTE_REQUEST.action_level == 1

    def test_cc_bypass_permissions_is_level_1(self) -> None:
        assert CC_BYPASS_PERMISSIONS.action_level == 1

    def test_all_tools_have_non_empty_descriptions(self) -> None:
        for tool_def in ALL_CC_TOOLS:
            assert tool_def.description.strip(), f"{tool_def.name} has empty description"

    def test_all_tools_have_non_empty_security_notes(self) -> None:
        for tool_def in ALL_CC_TOOLS:
            assert tool_def.security_notes.strip(), f"{tool_def.name} has empty security_notes"


# ---------------------------------------------------------------------------
# Parameter schema validation
# ---------------------------------------------------------------------------


class TestCcToolParameters:
    def test_cc_read_analyze_requires_task_and_project_name(self) -> None:
        required = CC_READ_ANALYZE.parameters.get("required", [])
        assert "task" in required
        assert "project_name" in required

    def test_cc_write_task_requires_task_and_project_name(self) -> None:
        required = CC_WRITE_TASK.parameters.get("required", [])
        assert "task" in required
        assert "project_name" in required

    def test_cc_run_with_shell_requires_task_and_project_name(self) -> None:
        required = CC_RUN_WITH_SHELL.parameters.get("required", [])
        assert "task" in required
        assert "project_name" in required

    def test_cc_git_commit_requires_project_name_and_message(self) -> None:
        required = CC_GIT_COMMIT.parameters.get("required", [])
        assert "project_name" in required
        assert "message" in required

    def test_cc_git_push_branch_requires_project_name_and_branch(self) -> None:
        required = CC_GIT_PUSH_BRANCH.parameters.get("required", [])
        assert "project_name" in required
        assert "branch" in required

    def test_cc_promote_request_requires_project_name_and_branch(self) -> None:
        required = CC_PROMOTE_REQUEST.parameters.get("required", [])
        assert "project_name" in required
        assert "branch" in required

    def test_cc_promote_request_has_optional_target(self) -> None:
        # 'target' defaults to 'main' — must be a property but not required.
        props = CC_PROMOTE_REQUEST.parameters.get("properties", {})
        assert "target" in props
        required = CC_PROMOTE_REQUEST.parameters.get("required", [])
        assert "target" not in required

    def test_cc_bypass_permissions_has_no_required_params(self) -> None:
        required = CC_BYPASS_PERMISSIONS.parameters.get("required", [])
        assert required == []


# ---------------------------------------------------------------------------
# register_cc_tools — enabled path
# ---------------------------------------------------------------------------


class TestRegisterCcToolsEnabled:
    def test_all_cc_tool_names_appear_in_registry_after_register(self) -> None:
        registry = _fresh_registry()
        register_cc_tools(registry)
        registered_names = {t.name for t in registry.list_tools()}
        for tool_def in ALL_CC_TOOLS:
            assert (
                tool_def.name in registered_names
            ), f"{tool_def.name} not found in registry after register_cc_tools()"

    def test_registry_contains_exactly_cc_tools_after_register(self) -> None:
        registry = _fresh_registry()
        register_cc_tools(registry)
        registered_names = {t.name for t in registry.list_tools()}
        expected_names = {t.name for t in ALL_CC_TOOLS}
        assert registered_names == expected_names

    def test_cc_bypass_permissions_has_no_handler(self) -> None:
        registry = _fresh_registry()
        register_cc_tools(registry)
        handler = registry.get_handler("cc_bypass_permissions")
        assert handler is None

    def test_registered_tool_definitions_match_originals(self) -> None:
        registry = _fresh_registry()
        register_cc_tools(registry)
        for tool_def in ALL_CC_TOOLS:
            retrieved = registry.get(tool_def.name)
            assert retrieved is not None
            assert retrieved.name == tool_def.name
            assert retrieved.action_level == tool_def.action_level

    def test_register_cc_tools_is_idempotent(self) -> None:
        # Second call silently overwrites; no exception, count stays the same.
        registry = _fresh_registry()
        register_cc_tools(registry)
        register_cc_tools(registry)
        assert len(registry.list_tools()) == len(ALL_CC_TOOLS)


# ---------------------------------------------------------------------------
# Disabled path — registry stays empty
# ---------------------------------------------------------------------------


class TestCcToolsDisabled:
    def test_no_cc_tools_when_register_not_called(self) -> None:
        # Simulates CCConfig.enabled=False: startup.py doesn't call register_cc_tools.
        registry = _fresh_registry()
        registered_names = {t.name for t in registry.list_tools()}
        cc_names = {t.name for t in ALL_CC_TOOLS}
        assert registered_names.isdisjoint(
            cc_names
        ), "cc_* tools appeared in registry without being registered"

    def test_get_returns_none_for_cc_tool_when_not_registered(self) -> None:
        registry = _fresh_registry()
        assert registry.get("cc_read_analyze") is None
        assert registry.get("cc_write_task") is None
        assert registry.get("cc_promote_request") is None


# ---------------------------------------------------------------------------
# Approval profile behaviour
# ---------------------------------------------------------------------------


class TestCcToolApprovalLevels:
    """Verify that the action levels produce the expected approval behaviour
    for each security profile.  Uses ApprovalThresholdPolicy directly."""

    def _policy(self, threshold: int):
        from openrattler.security.action_levels import ApprovalThresholdPolicy

        return ApprovalThresholdPolicy(threshold=threshold)

    def test_paranoid_requires_approval_for_all_cc_tools(self) -> None:
        policy = self._policy(5)  # paranoid threshold
        for tool_def in ALL_CC_TOOLS:
            assert policy.requires_approval(
                tool_def.action_level
            ), f"{tool_def.name} should require approval under paranoid profile"

    def test_standard_auto_approves_cc_read_analyze(self) -> None:
        policy = self._policy(3)  # standard threshold
        # cc_read_analyze is level 5 — above threshold, no approval needed.
        assert not policy.requires_approval(CC_READ_ANALYZE.action_level)

    def test_standard_requires_approval_for_cc_write_task(self) -> None:
        policy = self._policy(3)
        assert policy.requires_approval(CC_WRITE_TASK.action_level)

    def test_standard_requires_approval_for_cc_promote_request(self) -> None:
        policy = self._policy(3)
        assert policy.requires_approval(CC_PROMOTE_REQUEST.action_level)

    def test_minimal_auto_approves_cc_write_task(self) -> None:
        policy = self._policy(1)  # minimal threshold
        # cc_write_task is level 3 — above threshold of 1, no approval needed.
        assert not policy.requires_approval(CC_WRITE_TASK.action_level)

    def test_minimal_requires_approval_for_cc_promote_request(self) -> None:
        policy = self._policy(1)
        # cc_promote_request is level 1 — at threshold, always requires approval.
        assert policy.requires_approval(CC_PROMOTE_REQUEST.action_level)
