"""Integration tests for the MCP framework — end-to-end wiring.

Test classes:
    TestEndToEndToolCall      — bridge receives and executes MCP tool calls
    TestToolExecutorMCPRouting — ToolExecutor routes mcp: prefixed calls to bridge
    TestStartupWiring          — MCPManager loads manifests and registers tools
    TestShutdown               — disconnect_all cleans up tools and connections
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from openrattler.mcp.bridge import MCPToolBridge
from openrattler.mcp.manager import MCPManager
from openrattler.models.agents import AgentConfig, TrustLevel
from openrattler.models.mcp import (
    MCPPermissions,
    MCPSecurityConfig,
    MCPServerManifest,
    MCPToolManifestEntry,
)
from openrattler.models.tools import ToolCall, ToolResult
from openrattler.storage.audit import AuditLog
from openrattler.tools.executor import ToolExecutor
from openrattler.tools.registry import ToolDefinition, ToolRegistry

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _manifest(
    server_id: str = "weather-mcp",
    trust_tier: str = "bundled",
    tools: list[MCPToolManifestEntry] | None = None,
) -> MCPServerManifest:
    return MCPServerManifest(
        server_id=server_id,
        version="1.0.0",
        publisher="test",
        verified=True,
        trust_tier=trust_tier,  # type: ignore[arg-type]
        tools=tools
        or [
            MCPToolManifestEntry(name="get_forecast"),
            MCPToolManifestEntry(name="get_alerts"),
        ],
        transport="stdio",
        command="python",
        args=["-m", "openrattler.mcp.servers.weather"],
    )


def _tool_def(name: str) -> MCPToolManifestEntry:
    return MCPToolManifestEntry(name=name, requires_approval=False)


def _agent(
    trust_level: TrustLevel = TrustLevel.mcp,
    allowed_tools: list[str] | None = None,
) -> AgentConfig:
    return AgentConfig(
        agent_id="agent:test",
        name="Test",
        description="Integration test agent",
        model="test-model",
        trust_level=trust_level,
        session_key="session-xyz",
        allowed_tools=allowed_tools or [],
    )


def _mock_conn(tools: list[dict[str, Any]] | None = None) -> AsyncMock:
    conn = AsyncMock()
    conn.is_connected = True
    conn.connect = AsyncMock()
    conn.disconnect = AsyncMock()
    conn.list_tools = AsyncMock(
        return_value=tools
        or [
            {"name": "get_forecast", "description": "Get forecast", "inputSchema": {}},
            {"name": "get_alerts", "description": "Get alerts", "inputSchema": {}},
        ]
    )
    conn.call_tool = AsyncMock(return_value={"content": "Sunny, 72°F"})
    return conn


def _make_manager(
    registry: ToolRegistry | None = None,
    audit: AuditLog | None = None,
) -> MCPManager:
    return MCPManager(
        security_config=MCPSecurityConfig(),
        tool_registry=registry or ToolRegistry(),
        audit=audit,
    )


def _manifest_json(server_id: str = "weather-mcp", trust_tier: str = "bundled") -> dict[str, Any]:
    return {
        "server_id": server_id,
        "version": "1.0.0",
        "publisher": "test",
        "verified": True,
        "trust_tier": trust_tier,
        "permissions": {
            "network": {"allowed_domains": [], "deny_all_others": True},
            "data_access": {"read": [], "write": []},
            "file_system": {"read": [], "write": []},
            "exec": False,
            "financial": False,
        },
        "tools": [
            {
                "name": "get_forecast",
                "description": "Forecast",
                "requires_approval": False,
                "cost_estimate": "none",
                "side_effects": "none",
            },
        ],
        "transport": "stdio",
        "command": "python",
        "args": ["-m", "test_server"],
        "env": {},
    }


# ---------------------------------------------------------------------------
# TestEndToEndToolCall
# ---------------------------------------------------------------------------


class TestEndToEndToolCall:
    """MCPToolBridge receives and returns results for MCP tool calls."""

    async def test_bridge_execute_called_with_correct_args(self) -> None:
        """ToolExecutor delegates mcp: tool calls to bridge.execute()."""
        registry = ToolRegistry()
        registry.register(
            ToolDefinition(
                name="mcp:weather-mcp.get_forecast",
                description="[MCP: weather-mcp] Get forecast",
                parameters={},
                trust_level_required=TrustLevel.mcp,
                requires_approval=False,
            ),
            handler=None,
        )

        mock_bridge = AsyncMock(spec=MCPToolBridge)
        expected = ToolResult(call_id="call-1", success=True, result="Sunny")
        mock_bridge.execute = AsyncMock(return_value=expected)

        audit = AuditLog(Path("/dev/null"))
        executor = ToolExecutor(registry, audit, mcp_bridge=mock_bridge)

        agent = _agent(allowed_tools=["mcp:weather-mcp.get_forecast"])
        call = ToolCall(
            call_id="call-1",
            tool_name="mcp:weather-mcp.get_forecast",
            arguments={"latitude": 38.89, "longitude": -77.04},
        )
        result = await executor.execute(agent, call)

        mock_bridge.execute.assert_called_once()
        kwargs = mock_bridge.execute.call_args.kwargs
        assert kwargs["server_id"] == "weather-mcp"
        assert kwargs["tool_name"] == "get_forecast"
        assert kwargs["params"] == {"latitude": 38.89, "longitude": -77.04}
        assert result.success is True
        assert result.result == "Sunny"

    async def test_bridge_result_returned_to_executor(self) -> None:
        """ToolResult from bridge is the result returned by ToolExecutor."""
        registry = ToolRegistry()
        registry.register(
            ToolDefinition(
                name="mcp:test-server.echo",
                description="[MCP: test-server] Echo",
                parameters={},
                trust_level_required=TrustLevel.mcp,
                requires_approval=False,
            ),
            handler=None,
        )

        bridge_result = ToolResult(call_id="c1", success=True, result={"data": "pong"})
        mock_bridge = AsyncMock(spec=MCPToolBridge)
        mock_bridge.execute = AsyncMock(return_value=bridge_result)

        audit = AuditLog(Path("/dev/null"))
        executor = ToolExecutor(registry, audit, mcp_bridge=mock_bridge)

        result = await executor.execute(
            _agent(allowed_tools=["mcp:test-server.echo"]),
            ToolCall(call_id="c1", tool_name="mcp:test-server.echo", arguments={}),
        )
        assert result is bridge_result

    async def test_audit_log_entry_recorded(self, tmp_path: Path) -> None:
        """An audit entry is written for every MCP tool call."""
        registry = ToolRegistry()
        registry.register(
            ToolDefinition(
                name="mcp:weather-mcp.get_forecast",
                description="[MCP: weather-mcp] Forecast",
                parameters={},
                trust_level_required=TrustLevel.mcp,
                requires_approval=False,
            ),
            handler=None,
        )

        mock_bridge = AsyncMock(spec=MCPToolBridge)
        mock_bridge.execute = AsyncMock(
            return_value=ToolResult(call_id="c1", success=True, result="ok")
        )

        audit_path = tmp_path / "audit.jsonl"
        audit = AuditLog(audit_path)
        executor = ToolExecutor(registry, audit, mcp_bridge=mock_bridge)

        await executor.execute(
            _agent(allowed_tools=["mcp:weather-mcp.get_forecast"]),
            ToolCall(call_id="c1", tool_name="mcp:weather-mcp.get_forecast", arguments={}),
        )

        events = await audit.query(limit=10)
        tool_events = [e for e in events if e.event == "tool_execution"]
        assert len(tool_events) == 1
        assert tool_events[0].details["tool"] == "mcp:weather-mcp.get_forecast"


# ---------------------------------------------------------------------------
# TestToolExecutorMCPRouting
# ---------------------------------------------------------------------------


class TestToolExecutorMCPRouting:
    """ToolExecutor routing logic for mcp: vs non-mcp tools."""

    async def test_mcp_prefix_routes_to_bridge(self) -> None:
        """A tool name starting with mcp: is dispatched to MCPToolBridge."""
        registry = ToolRegistry()
        registry.register(
            ToolDefinition(
                name="mcp:srv.do_thing",
                description="[MCP: srv] Do thing",
                parameters={},
                trust_level_required=TrustLevel.mcp,
                requires_approval=False,
            ),
            handler=None,
        )

        mock_bridge = AsyncMock(spec=MCPToolBridge)
        mock_bridge.execute = AsyncMock(
            return_value=ToolResult(call_id="x", success=True, result="done")
        )

        audit = AuditLog(Path("/dev/null"))
        executor = ToolExecutor(registry, audit, mcp_bridge=mock_bridge)

        await executor.execute(
            _agent(allowed_tools=["mcp:srv.do_thing"]),
            ToolCall(call_id="x", tool_name="mcp:srv.do_thing", arguments={}),
        )
        assert mock_bridge.execute.called

    async def test_non_mcp_tool_follows_normal_path(self) -> None:
        """A non-MCP tool with a handler is executed via the handler function."""
        called: list[str] = []

        async def handler() -> str:
            called.append("ok")
            return "local result"

        registry = ToolRegistry()
        registry.register(
            ToolDefinition(
                name="local_tool",
                description="Local test tool",
                parameters={},
                trust_level_required=TrustLevel.main,
                requires_approval=False,
            ),
            handler=handler,
        )

        mock_bridge = AsyncMock(spec=MCPToolBridge)
        audit = AuditLog(Path("/dev/null"))
        executor = ToolExecutor(registry, audit, mcp_bridge=mock_bridge)

        result = await executor.execute(
            AgentConfig(
                agent_id="agent:main",
                name="Main",
                description="Main agent",
                model="test",
                trust_level=TrustLevel.main,
                allowed_tools=["local_tool"],
            ),
            ToolCall(call_id="y", tool_name="local_tool", arguments={}),
        )

        assert mock_bridge.execute.not_called
        assert result.success is True
        assert result.result == "local result"
        assert called == ["ok"]

    async def test_mcp_call_without_bridge_returns_error(self) -> None:
        """mcp: tool call with no bridge configured returns an error ToolResult."""
        registry = ToolRegistry()
        registry.register(
            ToolDefinition(
                name="mcp:srv.tool",
                description="[MCP: srv] Tool",
                parameters={},
                trust_level_required=TrustLevel.mcp,
                requires_approval=False,
            ),
            handler=None,  # No handler — bridge would handle this
        )

        audit = AuditLog(Path("/dev/null"))
        executor = ToolExecutor(registry, audit, mcp_bridge=None)  # No bridge

        result = await executor.execute(
            _agent(allowed_tools=["mcp:srv.tool"]),
            ToolCall(call_id="z", tool_name="mcp:srv.tool", arguments={}),
        )
        assert result.success is False
        assert result.error is not None


# ---------------------------------------------------------------------------
# TestStartupWiring
# ---------------------------------------------------------------------------


class TestStartupWiring:
    """MCPManager loads manifests and registers tools at startup."""

    async def test_manifests_loaded_from_directory(self, tmp_path: Path) -> None:
        """load_manifests_from_directory() loads all valid JSON manifests."""
        manifest_file = tmp_path / "weather-mcp.json"
        manifest_file.write_text(json.dumps(_manifest_json()), encoding="utf-8")

        manager = _make_manager()
        count = await manager.load_manifests_from_directory(tmp_path)

        assert count == 1
        assert manager.get_manifest("weather-mcp").server_id == "weather-mcp"

    async def test_invalid_manifests_are_skipped(self, tmp_path: Path) -> None:
        """Malformed manifest files are logged and skipped."""
        (tmp_path / "bad.json").write_text("{invalid json", encoding="utf-8")
        (tmp_path / "good.json").write_text(json.dumps(_manifest_json()), encoding="utf-8")

        manager = _make_manager()
        count = await manager.load_manifests_from_directory(tmp_path)

        assert count == 1  # Only the good manifest

    async def test_bundled_servers_connected(self, tmp_path: Path) -> None:
        """connect_all_bundled() connects all bundled-tier servers."""
        manifest_file = tmp_path / "weather-mcp.json"
        manifest_file.write_text(json.dumps(_manifest_json()), encoding="utf-8")

        mock_conn = _mock_conn()
        with patch("openrattler.mcp.manager.MCPServerConnection", return_value=mock_conn):
            manager = _make_manager()
            await manager.load_manifests_from_directory(tmp_path)
            await manager.connect_all_bundled()

        mock_conn.connect.assert_called_once()

    async def test_tools_registered_in_registry(self, tmp_path: Path) -> None:
        """MCP tools appear in ToolRegistry under mcp:{server_id}.{tool_name}."""
        manifest_file = tmp_path / "weather-mcp.json"
        manifest_file.write_text(json.dumps(_manifest_json()), encoding="utf-8")

        registry = ToolRegistry()
        mock_conn = _mock_conn()
        with patch("openrattler.mcp.manager.MCPServerConnection", return_value=mock_conn):
            manager = _make_manager(registry=registry)
            await manager.load_manifests_from_directory(tmp_path)
            await manager.connect_all_bundled()

        # The manifest declares "get_forecast" — should be registered as:
        assert registry.get("mcp:weather-mcp.get_forecast") is not None

    async def test_non_bundled_servers_not_auto_connected(self, tmp_path: Path) -> None:
        """connect_all_bundled() does not connect user_installed servers."""
        data = _manifest_json(trust_tier="user_installed")
        (tmp_path / "user-server.json").write_text(json.dumps(data), encoding="utf-8")

        mock_conn = _mock_conn()
        with patch("openrattler.mcp.manager.MCPServerConnection", return_value=mock_conn):
            manager = _make_manager()
            await manager.load_manifests_from_directory(tmp_path)
            await manager.connect_all_bundled()

        mock_conn.connect.assert_not_called()


# ---------------------------------------------------------------------------
# TestShutdown
# ---------------------------------------------------------------------------


class TestShutdown:
    """disconnect_all cleans up connections and unregisters tools."""

    async def test_disconnect_all_disconnects_each_server(self) -> None:
        """disconnect_all() calls disconnect() on every connected server."""
        mock_conn_a = _mock_conn()
        mock_conn_b = _mock_conn()

        with patch("openrattler.mcp.manager.MCPServerConnection") as mock_cls:
            mock_cls.side_effect = [mock_conn_a, mock_conn_b]
            registry = ToolRegistry()
            manager = _make_manager(registry=registry)

            await manager.load_manifest(_manifest(server_id="srv-a", trust_tier="user_installed"))
            await manager.load_manifest(_manifest(server_id="srv-b", trust_tier="user_installed"))
            await manager.connect_server("srv-a")
            await manager.connect_server("srv-b")
            await manager.disconnect_all()

        mock_conn_a.disconnect.assert_called_once()
        mock_conn_b.disconnect.assert_called_once()

    async def test_disconnect_all_unregisters_tools(self) -> None:
        """disconnect_all() removes MCP tools from the ToolRegistry."""
        mock_conn = _mock_conn(
            tools=[{"name": "get_forecast", "description": "Forecast", "inputSchema": {}}]
        )

        with patch("openrattler.mcp.manager.MCPServerConnection", return_value=mock_conn):
            registry = ToolRegistry()
            manager = _make_manager(registry=registry)

            await manager.load_manifest(_manifest(server_id="w", trust_tier="user_installed"))
            await manager.connect_server("w")

            # Tool should be registered now
            assert registry.get("mcp:w.get_forecast") is not None

            await manager.disconnect_all()

        # Tool should be gone after disconnect
        assert registry.get("mcp:w.get_forecast") is None

    async def test_disconnect_all_on_empty_manager_is_safe(self) -> None:
        """disconnect_all() with no connected servers does not raise."""
        manager = _make_manager()
        await manager.disconnect_all()  # Must not raise

    async def test_list_servers_reflects_connection_state(self) -> None:
        """list_servers() reports connected=True only for active connections."""
        mock_conn = _mock_conn()

        with patch("openrattler.mcp.manager.MCPServerConnection", return_value=mock_conn):
            manager = _make_manager()
            await manager.load_manifest(_manifest(server_id="w", trust_tier="user_installed"))

            # Not yet connected
            servers = manager.list_servers()
            assert len(servers) == 1
            assert servers[0]["connected"] is False

            await manager.connect_server("w")
            servers = manager.list_servers()
            assert servers[0]["connected"] is True

            await manager.disconnect_all()
            servers = manager.list_servers()
            assert servers[0]["connected"] is False
