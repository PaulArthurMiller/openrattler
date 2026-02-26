"""Tests for ToolRegistry and the @tool decorator."""

from __future__ import annotations

import pytest

import openrattler.tools.registry as registry_module
from openrattler.models.agents import AgentConfig, TrustLevel
from openrattler.models.tools import ToolDefinition
from openrattler.tools.registry import ToolRegistry, configure_default_registry, tool

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _tool_def(
    name: str = "web_search",
    trust: TrustLevel = TrustLevel.main,
    requires_approval: bool = False,
) -> ToolDefinition:
    return ToolDefinition(
        name=name,
        description="A test tool",
        parameters={},
        trust_level_required=trust,
        requires_approval=requires_approval,
    )


def _agent(
    trust: TrustLevel = TrustLevel.main,
    allowed: list[str] | None = None,
    denied: list[str] | None = None,
) -> AgentConfig:
    return AgentConfig(
        agent_id="agent:main:main",
        name="Test",
        description="Test",
        model="test-model",
        trust_level=trust,
        allowed_tools=allowed if allowed is not None else [],
        denied_tools=denied if denied is not None else [],
    )


async def _noop(**kwargs: object) -> str:
    return "ok"


# ---------------------------------------------------------------------------
# ToolRegistry — register / get / list
# ---------------------------------------------------------------------------


class TestToolRegistry:
    def test_register_and_get(self) -> None:
        reg = ToolRegistry()
        td = _tool_def("my_tool")
        reg.register(td, _noop)
        assert reg.get("my_tool") is td

    def test_get_returns_none_for_unknown(self) -> None:
        reg = ToolRegistry()
        assert reg.get("nonexistent") is None

    def test_get_handler(self) -> None:
        reg = ToolRegistry()
        reg.register(_tool_def("t"), _noop)
        assert reg.get_handler("t") is _noop

    def test_get_handler_returns_none_for_unknown(self) -> None:
        reg = ToolRegistry()
        assert reg.get_handler("nonexistent") is None

    def test_list_tools_empty(self) -> None:
        reg = ToolRegistry()
        assert reg.list_tools() == []

    def test_list_tools_returns_all(self) -> None:
        reg = ToolRegistry()
        names = ["tool_a", "tool_b", "tool_c"]
        for n in names:
            reg.register(_tool_def(n), _noop)
        listed = [t.name for t in reg.list_tools()]
        assert listed == names

    def test_register_overwrites_existing(self) -> None:
        reg = ToolRegistry()
        td1 = ToolDefinition(
            name="my_tool",
            description="v1",
            parameters={},
            trust_level_required=TrustLevel.main,
        )
        td2 = ToolDefinition(
            name="my_tool",
            description="v2",
            parameters={},
            trust_level_required=TrustLevel.main,
        )
        reg.register(td1, _noop)
        reg.register(td2, _noop)
        assert reg.get("my_tool").description == "v2"  # type: ignore[union-attr]

    # ------------------------------------------------------------------
    # list_tools_for_agent
    # ------------------------------------------------------------------

    def test_list_tools_for_agent_filters_by_allowlist(self) -> None:
        reg = ToolRegistry()
        reg.register(_tool_def("web_search"), _noop)
        reg.register(_tool_def("file_read"), _noop)
        agent = _agent(allowed=["web_search"])
        result = [t.name for t in reg.list_tools_for_agent(agent)]
        assert result == ["web_search"]

    def test_list_tools_for_agent_filters_out_denied(self) -> None:
        reg = ToolRegistry()
        reg.register(_tool_def("web_search"), _noop)
        reg.register(_tool_def("file_read"), _noop)
        agent = _agent(allowed=["web_search", "file_read"], denied=["file_read"])
        result = [t.name for t in reg.list_tools_for_agent(agent)]
        assert result == ["web_search"]

    def test_list_tools_for_agent_filters_by_trust_level(self) -> None:
        reg = ToolRegistry()
        reg.register(_tool_def("public_tool", trust=TrustLevel.public), _noop)
        reg.register(_tool_def("exec", trust=TrustLevel.local), _noop)
        agent = _agent(trust=TrustLevel.main, allowed=["public_tool", "exec"])
        result = [t.name for t in reg.list_tools_for_agent(agent)]
        assert "public_tool" in result
        assert "exec" not in result

    def test_list_tools_for_agent_empty_allowlist_returns_none(self) -> None:
        reg = ToolRegistry()
        reg.register(_tool_def("web_search"), _noop)
        agent = _agent(allowed=[])
        assert reg.list_tools_for_agent(agent) == []


# ---------------------------------------------------------------------------
# @tool decorator
# ---------------------------------------------------------------------------


class TestToolDecorator:
    def test_decorator_without_args_registers_tool(self) -> None:
        reg = ToolRegistry()

        @tool(registry=reg)
        async def my_tool(query: str) -> str:
            "Search for something."
            return "result"

        assert reg.get("my_tool") is not None

    def test_decorator_infers_name_from_function(self) -> None:
        reg = ToolRegistry()

        @tool(registry=reg)
        async def cool_search(query: str) -> str:
            "Search."
            return ""

        assert reg.get("cool_search") is not None

    def test_decorator_name_override(self) -> None:
        reg = ToolRegistry()

        @tool(name="search", registry=reg)
        async def web_search_impl(query: str) -> str:
            "Search the web."
            return ""

        assert reg.get("search") is not None
        assert reg.get("web_search_impl") is None

    def test_decorator_description_from_docstring(self) -> None:
        reg = ToolRegistry()

        @tool(registry=reg)
        async def my_tool(x: int) -> str:
            "This is the tool description."
            return ""

        td = reg.get("my_tool")
        assert td is not None
        assert td.description == "This is the tool description."

    def test_decorator_description_override(self) -> None:
        reg = ToolRegistry()

        @tool(description="Override description", registry=reg)
        async def my_tool() -> str:
            "Original docstring."
            return ""

        td = reg.get("my_tool")
        assert td is not None
        assert td.description == "Override description"

    def test_decorator_infers_parameters(self) -> None:
        reg = ToolRegistry()

        @tool(registry=reg)
        async def my_tool(query: str, limit: int = 10) -> str:
            "A tool."
            return ""

        td = reg.get("my_tool")
        assert td is not None
        props = td.parameters.get("properties", {})
        assert "query" in props
        assert "limit" in props
        # query has no default → required; limit has default → not required
        assert "query" in td.parameters.get("required", [])
        assert "limit" not in td.parameters.get("required", [])

    def test_decorator_trust_level_override(self) -> None:
        reg = ToolRegistry()

        @tool(trust_level_required=TrustLevel.local, registry=reg)
        async def exec_tool(cmd: str) -> str:
            "Execute a command."
            return ""

        td = reg.get("exec_tool")
        assert td is not None
        assert td.trust_level_required == TrustLevel.local

    def test_decorator_requires_approval_flag(self) -> None:
        reg = ToolRegistry()

        @tool(requires_approval=True, registry=reg)
        async def dangerous_tool() -> str:
            "Danger."
            return ""

        td = reg.get("dangerous_tool")
        assert td is not None
        assert td.requires_approval is True

    def test_decorator_attaches_definition_to_function(self) -> None:
        reg = ToolRegistry()

        @tool(registry=reg)
        async def tagged_tool() -> str:
            "Tagged."
            return ""

        assert hasattr(tagged_tool, "_tool_definition")
        assert tagged_tool._tool_definition.name == "tagged_tool"

    def test_decorator_no_registry_no_error(self) -> None:
        """If no registry is configured, the decorator still works silently."""
        original = registry_module._default_registry
        try:
            registry_module._default_registry = None

            @tool
            async def standalone_tool() -> str:
                "No registry."
                return ""

            assert hasattr(standalone_tool, "_tool_definition")
        finally:
            registry_module._default_registry = original

    def test_configure_default_registry(self) -> None:
        reg = ToolRegistry()
        original = registry_module._default_registry
        try:
            configure_default_registry(reg)

            @tool
            async def auto_registered() -> str:
                "Auto."
                return ""

            assert reg.get("auto_registered") is not None
        finally:
            registry_module._default_registry = original
