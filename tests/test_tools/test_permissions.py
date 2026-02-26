"""Tests for the tool permission layer."""

from __future__ import annotations

import pytest

from openrattler.models.agents import AgentConfig, TrustLevel
from openrattler.models.tools import ToolDefinition
from openrattler.tools.permissions import check_permission, needs_approval

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _agent(
    trust: TrustLevel = TrustLevel.main,
    allowed: list[str] | None = None,
    denied: list[str] | None = None,
) -> AgentConfig:
    return AgentConfig(
        agent_id="agent:main:main",
        name="Test Agent",
        description="Test",
        model="test-model",
        trust_level=trust,
        allowed_tools=allowed if allowed is not None else ["web_search", "file_read"],
        denied_tools=denied if denied is not None else [],
    )


def _tool(
    name: str = "web_search",
    trust_required: TrustLevel = TrustLevel.main,
    requires_approval: bool = False,
) -> ToolDefinition:
    return ToolDefinition(
        name=name,
        description="A test tool",
        parameters={},
        trust_level_required=trust_required,
        requires_approval=requires_approval,
    )


# ---------------------------------------------------------------------------
# check_permission — allowlist / denylist
# ---------------------------------------------------------------------------


class TestCheckPermissionAllowDeny:
    def test_allowed_tool_passes(self) -> None:
        agent = _agent(allowed=["web_search"])
        ok, reason = check_permission(agent, "web_search", _tool("web_search"))
        assert ok is True
        assert reason is None

    def test_tool_not_in_allowlist_fails(self) -> None:
        agent = _agent(allowed=["file_read"])
        ok, reason = check_permission(agent, "web_search", _tool("web_search"))
        assert ok is False
        assert reason is not None
        assert "allowed_tools" in reason

    def test_denied_tool_fails(self) -> None:
        agent = _agent(allowed=["web_search"], denied=["web_search"])
        ok, reason = check_permission(agent, "web_search", _tool("web_search"))
        assert ok is False
        assert reason is not None

    def test_denied_overrides_allowed(self) -> None:
        """A tool in both allowed_tools and denied_tools must be rejected."""
        agent = _agent(allowed=["dangerous_tool"], denied=["dangerous_tool"])
        ok, reason = check_permission(agent, "dangerous_tool", _tool("dangerous_tool"))
        assert ok is False
        assert "denied" in (reason or "").lower()

    def test_empty_allowlist_denies_all_tools(self) -> None:
        agent = _agent(allowed=[])
        ok, reason = check_permission(agent, "web_search", _tool("web_search"))
        assert ok is False

    def test_denied_check_runs_before_allowlist_check(self) -> None:
        """Denied takes priority; reason should mention 'denied', not 'allowed_tools'."""
        agent = _agent(allowed=[], denied=["web_search"])
        ok, reason = check_permission(agent, "web_search", _tool("web_search"))
        assert ok is False
        assert "denied" in (reason or "").lower()


# ---------------------------------------------------------------------------
# check_permission — trust level
# ---------------------------------------------------------------------------


class TestCheckPermissionTrustLevel:
    def test_public_agent_can_use_public_tool(self) -> None:
        agent = _agent(trust=TrustLevel.public, allowed=["pub_tool"])
        tool = _tool("pub_tool", trust_required=TrustLevel.public)
        ok, _ = check_permission(agent, "pub_tool", tool)
        assert ok is True

    def test_public_agent_cannot_use_main_tool(self) -> None:
        agent = _agent(trust=TrustLevel.public, allowed=["file_read"])
        tool = _tool("file_read", trust_required=TrustLevel.main)
        ok, reason = check_permission(agent, "file_read", tool)
        assert ok is False
        assert "trust" in (reason or "").lower()

    def test_public_agent_cannot_use_local_tool(self) -> None:
        agent = _agent(trust=TrustLevel.public, allowed=["exec"])
        tool = _tool("exec", trust_required=TrustLevel.local)
        ok, reason = check_permission(agent, "exec", tool)
        assert ok is False

    def test_main_agent_can_use_main_tool(self) -> None:
        agent = _agent(trust=TrustLevel.main, allowed=["file_read"])
        tool = _tool("file_read", trust_required=TrustLevel.main)
        ok, _ = check_permission(agent, "file_read", tool)
        assert ok is True

    def test_main_agent_can_use_public_tool(self) -> None:
        agent = _agent(trust=TrustLevel.main, allowed=["web_search"])
        tool = _tool("web_search", trust_required=TrustLevel.public)
        ok, _ = check_permission(agent, "web_search", tool)
        assert ok is True

    def test_main_agent_cannot_use_local_tool(self) -> None:
        agent = _agent(trust=TrustLevel.main, allowed=["exec"])
        tool = _tool("exec", trust_required=TrustLevel.local)
        ok, reason = check_permission(agent, "exec", tool)
        assert ok is False
        assert reason is not None

    def test_local_agent_can_use_local_tool(self) -> None:
        agent = _agent(trust=TrustLevel.local, allowed=["exec"])
        tool = _tool("exec", trust_required=TrustLevel.local)
        ok, _ = check_permission(agent, "exec", tool)
        assert ok is True

    def test_local_agent_can_use_main_tool(self) -> None:
        agent = _agent(trust=TrustLevel.local, allowed=["file_read"])
        tool = _tool("file_read", trust_required=TrustLevel.main)
        ok, _ = check_permission(agent, "file_read", tool)
        assert ok is True

    def test_local_agent_can_use_public_tool(self) -> None:
        agent = _agent(trust=TrustLevel.local, allowed=["web_search"])
        tool = _tool("web_search", trust_required=TrustLevel.public)
        ok, _ = check_permission(agent, "web_search", tool)
        assert ok is True


# ---------------------------------------------------------------------------
# needs_approval
# ---------------------------------------------------------------------------


class TestNeedsApproval:
    def test_needs_approval_true(self) -> None:
        tool = _tool(requires_approval=True)
        assert needs_approval(tool) is True

    def test_needs_approval_false(self) -> None:
        tool = _tool(requires_approval=False)
        assert needs_approval(tool) is False
