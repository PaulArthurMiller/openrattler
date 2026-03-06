"""Tests for openrattler.mcp.manager — MCPManager."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from openrattler.mcp.manager import MCPManager
from openrattler.models.agents import TrustLevel
from openrattler.models.mcp import (
    MCPPermissions,
    MCPSecurityConfig,
    MCPServerManifest,
    MCPToolManifestEntry,
)
from openrattler.storage.audit import AuditLog
from openrattler.tools.registry import ToolRegistry

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _manifest(
    server_id: str = "weather-mcp",
    trust_tier: str = "user_installed",
    tools: list[MCPToolManifestEntry] | None = None,
    **kwargs: Any,
) -> MCPServerManifest:
    return MCPServerManifest(
        server_id=server_id,
        version="1.0.0",
        publisher="Test Publisher",
        transport="stdio",
        command="/usr/bin/test-server",
        trust_tier=trust_tier,  # type: ignore[arg-type]
        tools=tools or [],
        **kwargs,
    )


def _tool_entry(name: str, requires_approval: bool = False) -> MCPToolManifestEntry:
    return MCPToolManifestEntry(name=name, requires_approval=requires_approval)


def _discovered(name: str, description: str = "") -> dict[str, Any]:
    return {"name": name, "description": description, "inputSchema": {"type": "object"}}


def _make_mock_conn(
    tools: list[dict[str, Any]] | None = None,
    is_connected: bool = True,
) -> AsyncMock:
    conn = AsyncMock()
    conn.is_connected = is_connected
    conn.connect = AsyncMock()
    conn.disconnect = AsyncMock()
    conn.list_tools = AsyncMock(return_value=tools or [])
    return conn


def _make_manager(
    security_config: MCPSecurityConfig | None = None,
    registry: ToolRegistry | None = None,
    audit: AuditLog | None = None,
) -> MCPManager:
    return MCPManager(
        security_config=security_config or MCPSecurityConfig(),
        tool_registry=registry or ToolRegistry(),
        audit=audit,
    )


# ---------------------------------------------------------------------------
# TestManifestLoading
# ---------------------------------------------------------------------------


class TestManifestLoading:
    async def test_valid_manifest_loads(self) -> None:
        manager = _make_manager()
        await manager.load_manifest(_manifest())
        assert "weather-mcp" in manager._manifests

    async def test_bundled_allowed_by_default(self) -> None:
        manager = _make_manager()
        await manager.load_manifest(_manifest(trust_tier="bundled"))
        assert "weather-mcp" in manager._manifests

    async def test_bundled_denied_when_disabled(self) -> None:
        cfg = MCPSecurityConfig(allow_bundled=False)
        manager = _make_manager(security_config=cfg)
        with pytest.raises(PermissionError, match="allow_bundled"):
            await manager.load_manifest(_manifest(trust_tier="bundled"))

    async def test_user_installed_denied_when_disabled(self) -> None:
        cfg = MCPSecurityConfig(allow_user_installed=False)
        manager = _make_manager(security_config=cfg)
        with pytest.raises(PermissionError, match="allow_user_installed"):
            await manager.load_manifest(_manifest(trust_tier="user_installed"))

    async def test_auto_discovered_denied_by_default(self) -> None:
        """Default config denies auto_discovered servers."""
        manager = _make_manager()  # allow_auto_discovered defaults to "deny"
        with pytest.raises(PermissionError, match="auto_discovered"):
            await manager.load_manifest(_manifest(trust_tier="auto_discovered"))

    async def test_auto_discovered_allowed_when_config_allows(self) -> None:
        cfg = MCPSecurityConfig(allow_auto_discovered="allow")
        manager = _make_manager(security_config=cfg)
        await manager.load_manifest(_manifest(trust_tier="auto_discovered"))
        assert "weather-mcp" in manager._manifests

    async def test_auto_discovered_allowed_when_config_prompts(self) -> None:
        cfg = MCPSecurityConfig(allow_auto_discovered="prompt")
        manager = _make_manager(security_config=cfg)
        await manager.load_manifest(_manifest(trust_tier="auto_discovered"))
        assert "weather-mcp" in manager._manifests

    async def test_load_manifest_audit_logged(self, tmp_path: Path) -> None:
        audit = AuditLog(tmp_path / "audit.jsonl")
        manager = _make_manager(audit=audit)
        await manager.load_manifest(_manifest())
        events = await audit.query(event_type="mcp_manifest_loaded")
        assert len(events) == 1
        assert events[0].details["server_id"] == "weather-mcp"

    async def test_multiple_manifests_registered(self) -> None:
        manager = _make_manager()
        await manager.load_manifest(_manifest("weather-mcp"))
        await manager.load_manifest(_manifest("dominos-mcp"))
        assert "weather-mcp" in manager._manifests
        assert "dominos-mcp" in manager._manifests


# ---------------------------------------------------------------------------
# TestServerConnection
# ---------------------------------------------------------------------------


class TestServerConnection:
    async def test_connect_creates_connection(self) -> None:
        mock_conn = _make_mock_conn()
        manager = _make_manager()
        await manager.load_manifest(_manifest())
        with patch("openrattler.mcp.manager.MCPServerConnection", return_value=mock_conn):
            await manager.connect_server("weather-mcp")
        mock_conn.connect.assert_awaited_once()

    async def test_connect_unregistered_server_raises_key_error(self) -> None:
        manager = _make_manager()
        with pytest.raises(KeyError, match="not registered"):
            await manager.connect_server("nonexistent-mcp")

    async def test_connect_discovers_tools(self) -> None:
        tools = [_discovered("get_forecast"), _discovered("get_radar")]
        mock_conn = _make_mock_conn(tools=tools)
        registry = ToolRegistry()
        manager = _make_manager(registry=registry)
        await manager.load_manifest(_manifest())
        with patch("openrattler.mcp.manager.MCPServerConnection", return_value=mock_conn):
            await manager.connect_server("weather-mcp")
        mock_conn.list_tools.assert_awaited_once()

    async def test_connect_registers_tools_in_registry(self) -> None:
        tools = [_discovered("get_forecast"), _discovered("get_radar")]
        mock_conn = _make_mock_conn(tools=tools)
        registry = ToolRegistry()
        manager = _make_manager(registry=registry)
        await manager.load_manifest(_manifest())
        with patch("openrattler.mcp.manager.MCPServerConnection", return_value=mock_conn):
            await manager.connect_server("weather-mcp")
        assert registry.get("mcp:weather-mcp.get_forecast") is not None
        assert registry.get("mcp:weather-mcp.get_radar") is not None

    async def test_disconnect_removes_tools_from_registry(self) -> None:
        tools = [_discovered("get_forecast")]
        mock_conn = _make_mock_conn(tools=tools)
        registry = ToolRegistry()
        manager = _make_manager(registry=registry)
        await manager.load_manifest(_manifest())
        with patch("openrattler.mcp.manager.MCPServerConnection", return_value=mock_conn):
            await manager.connect_server("weather-mcp")
        assert registry.get("mcp:weather-mcp.get_forecast") is not None

        await manager.disconnect_server("weather-mcp")
        assert registry.get("mcp:weather-mcp.get_forecast") is None

    async def test_connect_audit_logged(self, tmp_path: Path) -> None:
        tools = [_discovered("get_forecast")]
        mock_conn = _make_mock_conn(tools=tools)
        audit = AuditLog(tmp_path / "audit.jsonl")
        manager = _make_manager(audit=audit)
        await manager.load_manifest(_manifest())
        with patch("openrattler.mcp.manager.MCPServerConnection", return_value=mock_conn):
            await manager.connect_server("weather-mcp")
        events = await audit.query(event_type="mcp_server_connected")
        assert len(events) == 1
        assert events[0].details["server_id"] == "weather-mcp"
        assert events[0].details["tool_count"] == 1

    async def test_disconnect_audit_logged(self, tmp_path: Path) -> None:
        mock_conn = _make_mock_conn()
        audit = AuditLog(tmp_path / "audit.jsonl")
        manager = _make_manager(audit=audit)
        await manager.load_manifest(_manifest())
        with patch("openrattler.mcp.manager.MCPServerConnection", return_value=mock_conn):
            await manager.connect_server("weather-mcp")
        await manager.disconnect_server("weather-mcp")
        events = await audit.query(event_type="mcp_server_disconnected")
        assert len(events) == 1
        assert events[0].details["server_id"] == "weather-mcp"

    async def test_disconnect_not_connected_is_safe(self) -> None:
        manager = _make_manager()
        await manager.load_manifest(_manifest())
        # disconnect without connecting — should not raise
        await manager.disconnect_server("weather-mcp")


# ---------------------------------------------------------------------------
# TestToolNamespacing
# ---------------------------------------------------------------------------


class TestToolNamespacing:
    async def test_namespaced_as_mcp_server_tool(self) -> None:
        tools = [_discovered("get_forecast")]
        mock_conn = _make_mock_conn(tools=tools)
        registry = ToolRegistry()
        manager = _make_manager(registry=registry)
        await manager.load_manifest(_manifest("weather-mcp"))
        with patch("openrattler.mcp.manager.MCPServerConnection", return_value=mock_conn):
            await manager.connect_server("weather-mcp")
        tool_def = registry.get("mcp:weather-mcp.get_forecast")
        assert tool_def is not None
        assert tool_def.name == "mcp:weather-mcp.get_forecast"

    async def test_description_prefixed(self) -> None:
        tools = [_discovered("get_forecast", description="Get the weather forecast")]
        mock_conn = _make_mock_conn(tools=tools)
        registry = ToolRegistry()
        manager = _make_manager(registry=registry)
        await manager.load_manifest(_manifest("weather-mcp"))
        with patch("openrattler.mcp.manager.MCPServerConnection", return_value=mock_conn):
            await manager.connect_server("weather-mcp")
        tool_def = registry.get("mcp:weather-mcp.get_forecast")
        assert tool_def is not None
        assert "[MCP: weather-mcp]" in tool_def.description
        assert "Get the weather forecast" in tool_def.description

    async def test_trust_level_is_mcp(self) -> None:
        tools = [_discovered("get_forecast")]
        mock_conn = _make_mock_conn(tools=tools)
        registry = ToolRegistry()
        manager = _make_manager(registry=registry)
        await manager.load_manifest(_manifest())
        with patch("openrattler.mcp.manager.MCPServerConnection", return_value=mock_conn):
            await manager.connect_server("weather-mcp")
        tool_def = registry.get("mcp:weather-mcp.get_forecast")
        assert tool_def is not None
        assert tool_def.trust_level_required == TrustLevel.mcp

    async def test_approval_flag_from_manifest_entry(self) -> None:
        entries = [
            _tool_entry("get_forecast", requires_approval=False),
            _tool_entry("place_order", requires_approval=True),
        ]
        tools = [_discovered("get_forecast"), _discovered("place_order")]
        mock_conn = _make_mock_conn(tools=tools)
        registry = ToolRegistry()
        manager = _make_manager(registry=registry)
        await manager.load_manifest(_manifest(tools=entries))
        with patch("openrattler.mcp.manager.MCPServerConnection", return_value=mock_conn):
            await manager.connect_server("weather-mcp")
        assert registry.get("mcp:weather-mcp.get_forecast") is not None
        assert not registry.get("mcp:weather-mcp.get_forecast").requires_approval  # type: ignore
        assert registry.get("mcp:weather-mcp.place_order") is not None
        assert registry.get("mcp:weather-mcp.place_order").requires_approval  # type: ignore

    async def test_handler_is_none(self) -> None:
        """MCP tools have no local handler — MCPToolBridge handles execution."""
        tools = [_discovered("get_forecast")]
        mock_conn = _make_mock_conn(tools=tools)
        registry = ToolRegistry()
        manager = _make_manager(registry=registry)
        await manager.load_manifest(_manifest())
        with patch("openrattler.mcp.manager.MCPServerConnection", return_value=mock_conn):
            await manager.connect_server("weather-mcp")
        assert registry.get_handler("mcp:weather-mcp.get_forecast") is None

    async def test_input_schema_stored_as_parameters(self) -> None:
        schema = {"type": "object", "properties": {"city": {"type": "string"}}}
        tool = _discovered("get_forecast")
        tool["inputSchema"] = schema
        mock_conn = _make_mock_conn(tools=[tool])
        registry = ToolRegistry()
        manager = _make_manager(registry=registry)
        await manager.load_manifest(_manifest())
        with patch("openrattler.mcp.manager.MCPServerConnection", return_value=mock_conn):
            await manager.connect_server("weather-mcp")
        tool_def = registry.get("mcp:weather-mcp.get_forecast")
        assert tool_def is not None
        assert tool_def.parameters == schema


# ---------------------------------------------------------------------------
# TestManifestCrossValidation
# ---------------------------------------------------------------------------


class TestManifestCrossValidation:
    async def test_undeclared_tool_on_user_installed_forced_approval(self) -> None:
        """Tools found on user_installed servers but not in manifest get requires_approval=True."""
        # Manifest declares nothing; server reports get_forecast
        mock_conn = _make_mock_conn(tools=[_discovered("get_forecast")])
        registry = ToolRegistry()
        manager = _make_manager(registry=registry)
        await manager.load_manifest(_manifest(trust_tier="user_installed", tools=[]))
        with patch("openrattler.mcp.manager.MCPServerConnection", return_value=mock_conn):
            await manager.connect_server("weather-mcp")
        tool_def = registry.get("mcp:weather-mcp.get_forecast")
        assert tool_def is not None
        assert tool_def.requires_approval is True

    async def test_undeclared_tool_on_auto_discovered_not_registered(self) -> None:
        """Undeclared tools on auto_discovered servers are rejected (not registered)."""
        cfg = MCPSecurityConfig(allow_auto_discovered="allow")
        mock_conn = _make_mock_conn(tools=[_discovered("get_forecast")])
        registry = ToolRegistry()
        manager = _make_manager(security_config=cfg, registry=registry)
        # Manifest has no tools — server reports get_forecast (undeclared)
        await manager.load_manifest(_manifest(trust_tier="auto_discovered", tools=[]))
        with patch("openrattler.mcp.manager.MCPServerConnection", return_value=mock_conn):
            await manager.connect_server("weather-mcp")
        assert registry.get("mcp:weather-mcp.get_forecast") is None

    async def test_declared_tool_on_auto_discovered_registered(self) -> None:
        """Declared tools on auto_discovered servers ARE registered."""
        cfg = MCPSecurityConfig(allow_auto_discovered="allow")
        entries = [_tool_entry("get_forecast")]
        mock_conn = _make_mock_conn(tools=[_discovered("get_forecast")])
        registry = ToolRegistry()
        manager = _make_manager(security_config=cfg, registry=registry)
        await manager.load_manifest(_manifest(trust_tier="auto_discovered", tools=entries))
        with patch("openrattler.mcp.manager.MCPServerConnection", return_value=mock_conn):
            await manager.connect_server("weather-mcp")
        assert registry.get("mcp:weather-mcp.get_forecast") is not None

    async def test_undeclared_tool_on_bundled_registered_allowed(self) -> None:
        """Undeclared tools on bundled servers are registered (bundled is fully trusted)."""
        mock_conn = _make_mock_conn(tools=[_discovered("get_forecast")])
        registry = ToolRegistry()
        manager = _make_manager(registry=registry)
        # Bundled manifest with no tools declared
        await manager.load_manifest(_manifest(trust_tier="bundled", tools=[]))
        with patch("openrattler.mcp.manager.MCPServerConnection", return_value=mock_conn):
            await manager.connect_server("weather-mcp")
        assert registry.get("mcp:weather-mcp.get_forecast") is not None

    async def test_missing_server_tool_does_not_raise(self) -> None:
        """Tool declared in manifest but absent from server is silently skipped."""
        # Manifest declares get_forecast; server reports nothing
        entries = [_tool_entry("get_forecast")]
        mock_conn = _make_mock_conn(tools=[])
        registry = ToolRegistry()
        manager = _make_manager(registry=registry)
        await manager.load_manifest(_manifest(tools=entries))
        with patch("openrattler.mcp.manager.MCPServerConnection", return_value=mock_conn):
            await manager.connect_server("weather-mcp")
        # No error; tool is simply not registered
        assert registry.get("mcp:weather-mcp.get_forecast") is None


# ---------------------------------------------------------------------------
# TestBundledAutoConnect
# ---------------------------------------------------------------------------


class TestBundledAutoConnect:
    async def test_connect_all_bundled_connects_only_bundled(self) -> None:
        bundled_conn = _make_mock_conn()
        user_conn = _make_mock_conn()

        manager = _make_manager()
        await manager.load_manifest(_manifest("bundled-mcp", trust_tier="bundled"))
        await manager.load_manifest(_manifest("user-mcp", trust_tier="user_installed"))

        def _conn_factory(manifest: Any, **kwargs: Any) -> Any:
            if manifest.server_id == "bundled-mcp":
                return bundled_conn
            return user_conn  # pragma: no cover

        with patch("openrattler.mcp.manager.MCPServerConnection", side_effect=_conn_factory):
            await manager.connect_all_bundled()

        bundled_conn.connect.assert_awaited_once()
        user_conn.connect.assert_not_awaited()

    async def test_connect_all_bundled_skips_non_bundled(self) -> None:
        mock_conn = _make_mock_conn()
        manager = _make_manager()
        await manager.load_manifest(_manifest("user-mcp", trust_tier="user_installed"))

        with patch("openrattler.mcp.manager.MCPServerConnection", return_value=mock_conn):
            await manager.connect_all_bundled()

        mock_conn.connect.assert_not_awaited()

    async def test_disconnect_all_disconnects_all_connected(self) -> None:
        conn1 = _make_mock_conn()
        conn2 = _make_mock_conn()

        manager = _make_manager()
        await manager.load_manifest(_manifest("server-a"))
        await manager.load_manifest(_manifest("server-b"))

        call_count = 0

        def _factory(manifest: Any, **kwargs: Any) -> Any:
            nonlocal call_count
            call_count += 1
            return conn1 if call_count == 1 else conn2

        with patch("openrattler.mcp.manager.MCPServerConnection", side_effect=_factory):
            await manager.connect_server("server-a")
            await manager.connect_server("server-b")

        await manager.disconnect_all()

        conn1.disconnect.assert_awaited_once()
        conn2.disconnect.assert_awaited_once()


# ---------------------------------------------------------------------------
# TestLifecycle
# ---------------------------------------------------------------------------


class TestLifecycle:
    async def test_connect_then_disconnect_is_clean(self) -> None:
        tools = [_discovered("get_forecast")]
        mock_conn = _make_mock_conn(tools=tools)
        registry = ToolRegistry()
        manager = _make_manager(registry=registry)
        await manager.load_manifest(_manifest())
        with patch("openrattler.mcp.manager.MCPServerConnection", return_value=mock_conn):
            await manager.connect_server("weather-mcp")
        assert registry.get("mcp:weather-mcp.get_forecast") is not None

        await manager.disconnect_server("weather-mcp")
        assert registry.get("mcp:weather-mcp.get_forecast") is None
        assert "weather-mcp" not in manager._connections

    async def test_connect_twice_is_idempotent(self) -> None:
        mock_conn = _make_mock_conn()
        manager = _make_manager()
        await manager.load_manifest(_manifest())
        with patch("openrattler.mcp.manager.MCPServerConnection", return_value=mock_conn):
            await manager.connect_server("weather-mcp")
            await manager.connect_server("weather-mcp")  # second call — no-op
        # connect() called only once
        mock_conn.connect.assert_awaited_once()

    async def test_get_connection_returns_active_connection(self) -> None:
        mock_conn = _make_mock_conn()
        manager = _make_manager()
        await manager.load_manifest(_manifest())
        with patch("openrattler.mcp.manager.MCPServerConnection", return_value=mock_conn):
            await manager.connect_server("weather-mcp")
        assert manager.get_connection("weather-mcp") is mock_conn

    async def test_get_connection_raises_if_not_connected(self) -> None:
        manager = _make_manager()
        await manager.load_manifest(_manifest())
        with pytest.raises(KeyError, match="not connected"):
            manager.get_connection("weather-mcp")

    async def test_get_manifest_returns_manifest(self) -> None:
        manager = _make_manager()
        manifest = _manifest()
        await manager.load_manifest(manifest)
        assert manager.get_manifest("weather-mcp") is manifest

    async def test_get_manifest_raises_if_not_registered(self) -> None:
        manager = _make_manager()
        with pytest.raises(KeyError, match="not registered"):
            manager.get_manifest("nonexistent-mcp")

    async def test_list_servers_shows_all_registered(self) -> None:
        mock_conn = _make_mock_conn(tools=[_discovered("get_forecast")])
        manager = _make_manager()
        await manager.load_manifest(_manifest("weather-mcp"))
        await manager.load_manifest(_manifest("dominos-mcp"))
        with patch("openrattler.mcp.manager.MCPServerConnection", return_value=mock_conn):
            await manager.connect_server("weather-mcp")
        servers = manager.list_servers()
        assert len(servers) == 2
        by_id = {s["server_id"]: s for s in servers}
        assert by_id["weather-mcp"]["connected"] is True
        assert by_id["weather-mcp"]["tool_count"] == 1
        assert by_id["dominos-mcp"]["connected"] is False

    async def test_load_manifests_from_directory(self, tmp_path: Path) -> None:
        manifest_data = {
            "server_id": "weather-mcp",
            "version": "1.0.0",
            "publisher": "Test",
            "transport": "stdio",
            "command": "/usr/bin/weather",
            "trust_tier": "bundled",
        }
        (tmp_path / "weather-mcp.json").write_text(json.dumps(manifest_data), encoding="utf-8")
        manager = _make_manager()
        count = await manager.load_manifests_from_directory(tmp_path)
        assert count == 1
        assert "weather-mcp" in manager._manifests

    async def test_load_manifests_from_directory_skips_invalid(self, tmp_path: Path) -> None:
        (tmp_path / "bad.json").write_text("{not valid json", encoding="utf-8")
        (tmp_path / "also-bad.json").write_text(
            '{"server_id": "INVALID ID WITH SPACES"}', encoding="utf-8"
        )
        manager = _make_manager()
        count = await manager.load_manifests_from_directory(tmp_path)
        assert count == 0
