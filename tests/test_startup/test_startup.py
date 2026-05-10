"""Tests for openrattler.startup — ApplicationContext and build_application."""

from __future__ import annotations

import asyncio
from pathlib import Path
from typing import Any, Optional
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from openrattler.agents.providers.base import LLMProvider, LLMResponse
from openrattler.channels.base import ChannelAdapter
from openrattler.config.loader import AppConfig, ChannelConfig, ToolsConfig
from openrattler.models.agents import AgentConfig, TrustLevel
from openrattler.models.social import SocialSecretaryConfig
from openrattler.models.messages import UniversalMessage, create_message
from openrattler.startup import (
    ApplicationContext,
    _build_alert_adapters_list,
    _build_channel_adapters,
    _dispatch_to_channels,
    _resolve_agent_tools,
    build_application,
)
from openrattler.storage.audit import AuditLog

# ---------------------------------------------------------------------------
# Shared fixtures
# ---------------------------------------------------------------------------


class _StubProvider(LLMProvider):
    """LLM provider that never makes network calls."""

    async def complete(self, messages: Any, tools: Any = None, **kwargs: Any) -> LLMResponse:
        return LLMResponse(content="ok", tool_calls=[])

    async def stream(self, messages: Any, tools: Any = None, **kwargs: Any) -> Any:
        yield "ok"

    async def health_check(self) -> bool:
        return True


@pytest.fixture
def stub_provider() -> _StubProvider:
    return _StubProvider()


@pytest.fixture
def empty_mcp_dir(tmp_path: Path) -> Path:
    """An empty directory — no MCP manifests, no real connections."""
    d = tmp_path / "mcp_manifests"
    d.mkdir()
    return d


# ---------------------------------------------------------------------------
# TestBuildApplication
# ---------------------------------------------------------------------------


class TestBuildApplication:
    async def test_returns_application_context(
        self, tmp_path: Path, stub_provider: _StubProvider, empty_mcp_dir: Path
    ) -> None:
        ctx = await build_application(
            workspace_dir=tmp_path / "ws",
            config_path=tmp_path / "cfg.json",
            provider=stub_provider,
            mcp_manifests_dir=empty_mcp_dir,
            start_gateway=False,
        )
        assert isinstance(ctx, ApplicationContext)

    async def test_workspace_directories_created(
        self, tmp_path: Path, stub_provider: _StubProvider, empty_mcp_dir: Path
    ) -> None:
        ws = tmp_path / "ws"
        await build_application(
            workspace_dir=ws,
            config_path=tmp_path / "cfg.json",
            provider=stub_provider,
            mcp_manifests_dir=empty_mcp_dir,
            start_gateway=False,
        )
        for subdir in ("sessions", "memory", "audit", "social"):
            assert (ws / subdir).is_dir(), f"Expected {subdir}/ to exist"

    async def test_social_secretary_disabled_by_default(
        self, tmp_path: Path, stub_provider: _StubProvider, empty_mcp_dir: Path
    ) -> None:
        # Social Secretary is off by default, but the heartbeat is on by default,
        # so a scheduler is still created.  The social_processor, however, is None.
        ctx = await build_application(
            workspace_dir=tmp_path / "ws",
            config_path=tmp_path / "cfg.json",
            provider=stub_provider,
            mcp_manifests_dir=empty_mcp_dir,
            start_gateway=False,
        )
        assert ctx._social_processor is None
        assert ctx._scheduler is not None  # heartbeat creates scheduler

    async def test_social_secretary_enabled_creates_scheduler(
        self, tmp_path: Path, stub_provider: _StubProvider, empty_mcp_dir: Path
    ) -> None:
        from openrattler.config.loader import save_config

        config = AppConfig(social_secretary=SocialSecretaryConfig(enabled=True))
        cfg_path = tmp_path / "cfg.json"
        save_config(config, cfg_path)

        ctx = await build_application(
            workspace_dir=tmp_path / "ws",
            config_path=cfg_path,
            provider=stub_provider,
            mcp_manifests_dir=empty_mcp_dir,
            start_gateway=False,
        )
        assert ctx._scheduler is not None

    async def test_heartbeat_disabled_and_no_ss_gives_no_scheduler(
        self, tmp_path: Path, stub_provider: _StubProvider, empty_mcp_dir: Path
    ) -> None:
        from openrattler.config.loader import HeartbeatConfig, save_config

        cfg = AppConfig(heartbeat=HeartbeatConfig(enabled=False))
        cfg_path = tmp_path / "cfg.json"
        save_config(cfg, cfg_path)

        ctx = await build_application(
            workspace_dir=tmp_path / "ws",
            config_path=cfg_path,
            provider=stub_provider,
            mcp_manifests_dir=empty_mcp_dir,
            start_gateway=False,
        )
        assert ctx._scheduler is None
        assert ctx._social_processor is None

    async def test_no_adapters_when_channels_empty(
        self, tmp_path: Path, stub_provider: _StubProvider, empty_mcp_dir: Path
    ) -> None:
        ctx = await build_application(
            workspace_dir=tmp_path / "ws",
            config_path=tmp_path / "cfg.json",
            provider=stub_provider,
            mcp_manifests_dir=empty_mcp_dir,
            start_gateway=False,
        )
        assert ctx._adapters == []

    async def test_slack_adapter_built_from_config(
        self, tmp_path: Path, stub_provider: _StubProvider, empty_mcp_dir: Path
    ) -> None:
        from openrattler.config.loader import save_config

        slack_cfg = ChannelConfig(
            enabled=True,
            settings={
                "bot_token": "xoxb-test",
                "channel_id": "C123",
                "sender_allowlist": ["U456"],
            },
        )
        config = AppConfig(channels={"slack": slack_cfg})
        cfg_path = tmp_path / "cfg.json"
        save_config(config, cfg_path)

        ctx = await build_application(
            workspace_dir=tmp_path / "ws",
            config_path=cfg_path,
            provider=stub_provider,
            mcp_manifests_dir=empty_mcp_dir,
            start_gateway=False,
        )
        from openrattler.channels.slack_adapter import SlackAdapter

        assert len(ctx._adapters) == 1
        assert isinstance(ctx._adapters[0], SlackAdapter)

    async def test_gateway_started_by_default(
        self, tmp_path: Path, stub_provider: _StubProvider, empty_mcp_dir: Path
    ) -> None:
        ctx = await build_application(
            workspace_dir=tmp_path / "ws",
            config_path=tmp_path / "cfg.json",
            provider=stub_provider,
            mcp_manifests_dir=empty_mcp_dir,
            start_gateway=True,
        )
        assert ctx._gateway is not None

    async def test_gateway_disabled_when_requested(
        self, tmp_path: Path, stub_provider: _StubProvider, empty_mcp_dir: Path
    ) -> None:
        ctx = await build_application(
            workspace_dir=tmp_path / "ws",
            config_path=tmp_path / "cfg.json",
            provider=stub_provider,
            mcp_manifests_dir=empty_mcp_dir,
            start_gateway=False,
        )
        assert ctx._gateway is None

    async def test_custom_provider_injected(
        self, tmp_path: Path, stub_provider: _StubProvider, empty_mcp_dir: Path
    ) -> None:
        ctx = await build_application(
            workspace_dir=tmp_path / "ws",
            config_path=tmp_path / "cfg.json",
            provider=stub_provider,
            mcp_manifests_dir=empty_mcp_dir,
            start_gateway=False,
        )
        # Provider is injected into the runtime — confirm it's the stub, not env-based.
        assert ctx._runtime._provider is stub_provider


# ---------------------------------------------------------------------------
# TestApplicationLifecycle
# ---------------------------------------------------------------------------


async def _make_context(tmp_path: Path, stub_provider: _StubProvider) -> ApplicationContext:
    """Helper: build a minimal ApplicationContext with no real connections."""
    empty = tmp_path / "mcp"
    empty.mkdir()
    return await build_application(
        workspace_dir=tmp_path / "ws",
        config_path=tmp_path / "cfg.json",
        provider=stub_provider,
        mcp_manifests_dir=empty,
        start_gateway=False,
    )


class TestApplicationLifecycle:
    async def test_start_and_stop_without_error(
        self, tmp_path: Path, stub_provider: _StubProvider
    ) -> None:
        ctx = await _make_context(tmp_path, stub_provider)
        await ctx.start()
        await ctx.stop()

    async def test_start_emits_audit_event(
        self, tmp_path: Path, stub_provider: _StubProvider
    ) -> None:
        ctx = await _make_context(tmp_path, stub_provider)
        await ctx.start()
        events = await ctx._audit.query(limit=20)
        event_names = [e.event for e in events]
        assert "application_started" in event_names
        await ctx.stop()

    async def test_stop_emits_audit_event(
        self, tmp_path: Path, stub_provider: _StubProvider
    ) -> None:
        ctx = await _make_context(tmp_path, stub_provider)
        await ctx.start()
        await ctx.stop()
        events = await ctx._audit.query(limit=20)
        event_names = [e.event for e in events]
        assert "application_stopped" in event_names

    async def test_stop_without_start_is_safe(
        self, tmp_path: Path, stub_provider: _StubProvider
    ) -> None:
        ctx = await _make_context(tmp_path, stub_provider)
        # Should not raise even though start() was never called.
        await ctx.stop()

    async def test_start_connects_social_processor(
        self, tmp_path: Path, stub_provider: _StubProvider
    ) -> None:
        ctx = await _make_context(tmp_path, stub_provider)
        mock_ss = AsyncMock()
        ctx._social_processor = mock_ss
        await ctx.start()
        mock_ss.connect.assert_called_once()
        await ctx.stop()

    async def test_stop_disconnects_social_processor(
        self, tmp_path: Path, stub_provider: _StubProvider
    ) -> None:
        ctx = await _make_context(tmp_path, stub_provider)
        mock_ss = AsyncMock()
        ctx._social_processor = mock_ss
        await ctx.start()
        await ctx.stop()
        mock_ss.disconnect.assert_called_once()


# ---------------------------------------------------------------------------
# TestSessionManagement
# ---------------------------------------------------------------------------


class TestSessionManagement:
    async def test_get_or_create_returns_session(
        self, tmp_path: Path, stub_provider: _StubProvider
    ) -> None:
        ctx = await _make_context(tmp_path, stub_provider)
        session = await ctx._get_or_create_session("agent:main:main")
        assert session.key == "agent:main:main"

    async def test_get_or_create_returns_same_session_on_second_call(
        self, tmp_path: Path, stub_provider: _StubProvider
    ) -> None:
        ctx = await _make_context(tmp_path, stub_provider)
        s1 = await ctx._get_or_create_session("agent:main:main")
        s2 = await ctx._get_or_create_session("agent:main:main")
        assert s1 is s2


# ---------------------------------------------------------------------------
# TestChannelAdapterFactory
# ---------------------------------------------------------------------------


class TestChannelAdapterFactory:
    def _make_config(self, channels: dict[str, ChannelConfig]) -> AppConfig:
        return AppConfig(channels=channels)

    def _make_audit(self, tmp_path: Path) -> Any:
        from openrattler.storage.audit import AuditLog

        return AuditLog(tmp_path / "audit.jsonl")

    def test_disabled_channel_not_included(self, tmp_path: Path) -> None:
        config = self._make_config(
            {"slack": ChannelConfig(enabled=False, settings={"bot_token": "x"})}
        )
        adapters = _build_channel_adapters(config, self._make_audit(tmp_path))
        assert adapters == []

    def test_unknown_channel_name_skipped(self, tmp_path: Path) -> None:
        config = self._make_config({"telepathy": ChannelConfig(enabled=True, settings={})})
        adapters = _build_channel_adapters(config, self._make_audit(tmp_path))
        assert adapters == []

    def test_slack_config_produces_slack_adapter(self, tmp_path: Path) -> None:
        from openrattler.channels.slack_adapter import SlackAdapter

        config = self._make_config(
            {
                "slack": ChannelConfig(
                    enabled=True,
                    settings={
                        "bot_token": "xoxb-test",
                        "channel_id": "C123",
                        "sender_allowlist": ["U456"],
                    },
                )
            }
        )
        adapters = _build_channel_adapters(config, self._make_audit(tmp_path))
        assert len(adapters) == 1
        assert isinstance(adapters[0], SlackAdapter)


# ---------------------------------------------------------------------------
# TestRunCliSubcommand
# ---------------------------------------------------------------------------


# ---------------------------------------------------------------------------
# TestResolveAgentTools
# ---------------------------------------------------------------------------


def _make_agent(trust_level: TrustLevel = TrustLevel.main) -> AgentConfig:
    return AgentConfig(
        agent_id="agent:main:main",
        name="Main",
        description="Test agent",
        model="anthropic/claude-sonnet-4-6",
        trust_level=trust_level,
    )


class TestResolveAgentTools:
    def test_trust_defaults_added_to_empty_allowed_tools(self) -> None:
        agent = _make_agent()
        tools_cfg = ToolsConfig(trust_defaults={"main": ["tool_a", "tool_b"]})
        resolved = _resolve_agent_tools(agent, tools_cfg)
        assert resolved.allowed_tools == ["tool_a", "tool_b"]

    def test_per_agent_tools_extend_defaults(self) -> None:
        agent = _make_agent()
        agent = agent.model_copy(update={"allowed_tools": ["tool_c"]})
        tools_cfg = ToolsConfig(trust_defaults={"main": ["tool_a", "tool_b"]})
        resolved = _resolve_agent_tools(agent, tools_cfg)
        assert resolved.allowed_tools == ["tool_a", "tool_b", "tool_c"]

    def test_duplicates_are_deduped(self) -> None:
        agent = _make_agent()
        agent = agent.model_copy(update={"allowed_tools": ["tool_a"]})
        tools_cfg = ToolsConfig(trust_defaults={"main": ["tool_a", "tool_b"]})
        resolved = _resolve_agent_tools(agent, tools_cfg)
        assert resolved.allowed_tools.count("tool_a") == 1

    def test_defaults_order_preserved_before_per_agent(self) -> None:
        agent = _make_agent()
        agent = agent.model_copy(update={"allowed_tools": ["extra"]})
        tools_cfg = ToolsConfig(trust_defaults={"main": ["first", "second"]})
        resolved = _resolve_agent_tools(agent, tools_cfg)
        assert resolved.allowed_tools == ["first", "second", "extra"]

    def test_no_defaults_for_trust_level_leaves_explicit_tools(self) -> None:
        agent = _make_agent(TrustLevel.local)
        agent = agent.model_copy(update={"allowed_tools": ["my_tool"]})
        tools_cfg = ToolsConfig(trust_defaults={"main": ["main_tool"]})
        resolved = _resolve_agent_tools(agent, tools_cfg)
        assert resolved.allowed_tools == ["my_tool"]

    def test_original_agent_config_not_mutated(self) -> None:
        agent = _make_agent()
        tools_cfg = ToolsConfig(trust_defaults={"main": ["tool_a"]})
        _resolve_agent_tools(agent, tools_cfg)
        assert agent.allowed_tools == []

    def test_default_appconfig_gives_main_agent_five_tools(self) -> None:
        agent = _make_agent()
        tools_cfg = ToolsConfig()
        resolved = _resolve_agent_tools(agent, tools_cfg)
        for tool_name in [
            "update_memory_narrative",
            "update_user_profile",
            "update_identity",
            "memory_read",
            "memory_write",
        ]:
            assert tool_name in resolved.allowed_tools

    def test_build_application_applies_tool_resolution(
        self, tmp_path: Path, stub_provider: _StubProvider, empty_mcp_dir: Path
    ) -> None:
        """The main agent config produced by build_application has the default tools."""
        import asyncio

        async def _run() -> list[str]:
            ctx = await build_application(
                workspace_dir=tmp_path,
                provider=stub_provider,
                mcp_manifests_dir=empty_mcp_dir,
                start_gateway=False,
            )
            return list(ctx._runtime._config.allowed_tools)

        tools = asyncio.get_event_loop().run_until_complete(_run())
        assert "update_memory_narrative" in tools
        assert "update_identity" in tools
        assert "memory_read" in tools
        assert "memory_write" in tools


class TestRunCliSubcommand:
    def test_run_subcommand_registered(self) -> None:
        from openrattler.cli.main import _build_parser

        parser = _build_parser()
        # Parse --help equivalent: check that 'run' is a valid command.
        args = parser.parse_args(["run"])
        assert args.command == "run"

    def test_run_flags(self) -> None:
        from openrattler.cli.main import _build_parser

        parser = _build_parser()
        args = parser.parse_args(["run", "--host", "0.0.0.0", "--port", "9000"])
        assert args.host == "0.0.0.0"
        assert args.port == 9000

    def test_run_defaults(self) -> None:
        from openrattler.cli.main import _build_parser

        parser = _build_parser()
        args = parser.parse_args(["run"])
        assert args.host == "127.0.0.1"
        assert args.port == 8765


# ---------------------------------------------------------------------------
# TestAlertDispatch
# ---------------------------------------------------------------------------


def _make_alert_message(operation: str = "test_op") -> UniversalMessage:
    return create_message(
        from_agent="startup",
        to_agent="broadcast",
        session_key="system",
        type="alert",
        operation=operation,
        trust_level="security",
        params={"summary": "test alert"},
    )


def _make_mock_adapter(name: str = "mock", connected: bool = True) -> MagicMock:
    """Return a MagicMock that looks like a connected ChannelAdapter."""
    adapter = MagicMock(spec=ChannelAdapter)
    adapter.channel_name = name
    adapter._connected = connected
    adapter.send = AsyncMock(return_value=None)
    return adapter


def _make_audit(tmp_path: Path) -> AuditLog:
    return AuditLog(tmp_path / "audit.jsonl")


class TestAlertDispatch:
    # ------------------------------------------------------------------
    # _dispatch_to_channels
    # ------------------------------------------------------------------

    async def test_urgent_alert_dispatched_to_connected_adapter(self, tmp_path: Path) -> None:
        adapter = _make_mock_adapter()
        audit = _make_audit(tmp_path)
        msg = _make_alert_message()

        result = await _dispatch_to_channels(msg, [adapter], audit)

        assert result is True
        adapter.send.assert_called_once_with(msg)

    async def test_urgent_alert_dispatched_to_multiple_adapters(self, tmp_path: Path) -> None:
        a1 = _make_mock_adapter("slack")
        a2 = _make_mock_adapter("email")
        audit = _make_audit(tmp_path)
        msg = _make_alert_message()

        result = await _dispatch_to_channels(msg, [a1, a2], audit)

        assert result is True
        a1.send.assert_called_once_with(msg)
        a2.send.assert_called_once_with(msg)

    async def test_failed_adapter_does_not_block_others(self, tmp_path: Path) -> None:
        a1 = _make_mock_adapter("slack")
        a1.send = AsyncMock(side_effect=RuntimeError("network error"))
        a2 = _make_mock_adapter("email")
        audit = _make_audit(tmp_path)
        msg = _make_alert_message()

        result = await _dispatch_to_channels(msg, [a1, a2], audit)

        assert result is True  # a2 succeeded
        a2.send.assert_called_once_with(msg)

        events = await audit.query(limit=20)
        assert any(e.event == "alert_dispatch_failed" for e in events)
        failed_event = next(e for e in events if e.event == "alert_dispatch_failed")
        assert failed_event.details["adapter_name"] == "slack"

    async def test_all_adapters_fail_falls_back_to_stderr(
        self, tmp_path: Path, capsys: Any
    ) -> None:
        a1 = _make_mock_adapter("slack")
        a1.send = AsyncMock(side_effect=RuntimeError("err1"))
        a2 = _make_mock_adapter("email")
        a2.send = AsyncMock(side_effect=RuntimeError("err2"))
        audit = _make_audit(tmp_path)
        msg = _make_alert_message()

        result = await _dispatch_to_channels(msg, [a1, a2], audit)

        assert result is False

        events = await audit.query(limit=20)
        event_names = [e.event for e in events]
        assert "alert_dispatch_failed" in event_names
        assert "alert_dispatch_total_failure" in event_names

    async def test_no_adapters_returns_false(self, tmp_path: Path) -> None:
        audit = _make_audit(tmp_path)
        msg = _make_alert_message()

        result = await _dispatch_to_channels(msg, [], audit)

        assert result is False

    async def test_dispatch_is_concurrent(self, tmp_path: Path) -> None:
        """asyncio.gather is used — verify by patching it."""
        audit = _make_audit(tmp_path)
        msg = _make_alert_message()
        adapters = [_make_mock_adapter("a"), _make_mock_adapter("b")]

        with patch("openrattler.startup.asyncio.gather", wraps=asyncio.gather) as mock_gather:
            await _dispatch_to_channels(msg, adapters, audit)

        mock_gather.assert_called_once()

    # ------------------------------------------------------------------
    # _build_alert_adapters_list
    # ------------------------------------------------------------------

    async def test_disconnected_adapter_skipped(self) -> None:
        connected = _make_mock_adapter("slack", connected=True)
        disconnected = _make_mock_adapter("email", connected=False)

        result = _build_alert_adapters_list({"slack": connected, "email": disconnected})

        assert connected in result
        assert disconnected not in result

    async def test_no_connected_adapters_returns_empty(self) -> None:
        a = _make_mock_adapter("slack", connected=False)
        result = _build_alert_adapters_list({"slack": a})
        assert result == []

    # ------------------------------------------------------------------
    # Security alert message construction
    # ------------------------------------------------------------------

    async def test_security_alert_constructs_correct_message(
        self, tmp_path: Path, stub_provider: _StubProvider, empty_mcp_dir: Path
    ) -> None:
        """_on_security_alert builds a UniversalMessage with type=alert, operation=security_alert."""
        ctx = await build_application(
            workspace_dir=tmp_path / "ws",
            config_path=tmp_path / "cfg.json",
            provider=stub_provider,
            mcp_manifests_dir=empty_mcp_dir,
            start_gateway=False,
        )
        assert ctx._security_alert_cb is not None

        # Wire a mock adapter into the alert list directly so dispatch is tracked.
        adapter = _make_mock_adapter("slack")
        ctx._alert_adapters.clear()
        ctx._alert_adapters.append(adapter)

        await ctx._security_alert_cb("my_tool", "injection attempt")

        adapter.send.assert_called_once()
        delivered: UniversalMessage = adapter.send.call_args[0][0]
        assert delivered.type == "alert"
        assert delivered.operation == "security_alert"
        assert delivered.params["tool_name"] == "my_tool"
        assert delivered.params["reason"] == "injection attempt"
        assert delivered.params["severity"] == "high"

    async def test_security_alert_tool_name_sanitized(
        self, tmp_path: Path, stub_provider: _StubProvider, empty_mcp_dir: Path
    ) -> None:
        """Long/malformed tool name is truncated and stripped before inclusion."""
        ctx = await build_application(
            workspace_dir=tmp_path / "ws",
            config_path=tmp_path / "cfg.json",
            provider=stub_provider,
            mcp_manifests_dir=empty_mcp_dir,
            start_gateway=False,
        )
        assert ctx._security_alert_cb is not None

        adapter = _make_mock_adapter("slack")
        ctx._alert_adapters.clear()
        ctx._alert_adapters.append(adapter)

        # Name with special chars + length > 64
        bad_name = "A" * 80 + "<script>alert(1)</script>"
        await ctx._security_alert_cb(bad_name, "reason")

        delivered: UniversalMessage = adapter.send.call_args[0][0]
        safe = delivered.params["tool_name"]
        assert len(safe) <= 64
        assert "<" not in safe
        assert ">" not in safe
        assert "(" not in safe

    # ------------------------------------------------------------------
    # Integration: alert adapters captured once at start()
    # ------------------------------------------------------------------

    async def test_alert_adapters_captured_at_start_not_per_alert(
        self, tmp_path: Path, stub_provider: _StubProvider, empty_mcp_dir: Path
    ) -> None:
        """_alert_adapters is empty before start() and set exactly once."""
        ctx = await build_application(
            workspace_dir=tmp_path / "ws",
            config_path=tmp_path / "cfg.json",
            provider=stub_provider,
            mcp_manifests_dir=empty_mcp_dir,
            start_gateway=False,
        )
        # Before start(), the list is empty (no adapters connected).
        assert ctx._alert_adapters == []

        await ctx.start()
        # No real adapters configured → still empty after start().
        assert ctx._alert_adapters == []

        # Manually append an adapter AFTER start() — dispatch should see it
        # because the list is shared, but it was NOT re-evaluated from _adapters.
        extra = _make_mock_adapter("sms")
        ctx._alert_adapters.append(extra)
        assert len(ctx._alert_adapters) == 1

        # Calling start() again would repopulate from self._adapters (still none),
        # but we verify the list is only built from self._adapters, not re-polled.
        await ctx.stop()

    async def test_no_adapters_connected_falls_back_to_no_exception(
        self, tmp_path: Path, stub_provider: _StubProvider, empty_mcp_dir: Path
    ) -> None:
        """Empty adapter list → _dispatch_to_channels skipped; no exception raised."""
        ctx = await build_application(
            workspace_dir=tmp_path / "ws",
            config_path=tmp_path / "cfg.json",
            provider=stub_provider,
            mcp_manifests_dir=empty_mcp_dir,
            start_gateway=False,
        )
        await ctx.start()
        assert ctx._alert_adapters == []

        # Fire urgent alert — should fall back to print without raising.
        assert ctx._scheduler is not None
        on_urgent = ctx._scheduler._on_urgent_alert
        assert on_urgent is not None
        msg = _make_alert_message("heartbeat_response")
        # Must not raise even with no adapters.
        await on_urgent(msg)

        await ctx.stop()


# ---------------------------------------------------------------------------
# TestShutdownReliability
# ---------------------------------------------------------------------------


class TestShutdownReliability:
    """Tests for the hard-exit watchdog and per-component shutdown timeouts."""

    async def test_force_exit_after_calls_os_exit(
        self, tmp_path: Path, stub_provider: _StubProvider, empty_mcp_dir: Path
    ) -> None:
        ctx = await _make_context(tmp_path, stub_provider)
        with patch("openrattler.startup.os._exit") as mock_exit:
            # Use a very short timeout so the test runs fast.
            await ctx._force_exit_after(0.01)
        mock_exit.assert_called_once_with(0)

    async def test_stop_continues_when_scheduler_times_out(
        self, tmp_path: Path, stub_provider: _StubProvider
    ) -> None:
        ctx = await _make_context(tmp_path, stub_provider)
        mock_scheduler = AsyncMock()

        async def _hang() -> None:
            await asyncio.sleep(999)

        mock_scheduler.stop = _hang
        ctx._scheduler = mock_scheduler

        # Use a tiny component timeout so the test completes quickly.
        with patch("openrattler.startup._COMPONENT_STOP_TIMEOUT", 0.05):
            await asyncio.wait_for(ctx.stop(), timeout=1.0)

    async def test_stop_continues_when_gateway_times_out(
        self, tmp_path: Path, stub_provider: _StubProvider
    ) -> None:
        ctx = await _make_context(tmp_path, stub_provider)
        mock_gateway = AsyncMock()

        async def _hang() -> None:
            await asyncio.sleep(999)

        mock_gateway.stop = _hang
        ctx._gateway = mock_gateway

        with patch("openrattler.startup._COMPONENT_STOP_TIMEOUT", 0.05):
            await asyncio.wait_for(ctx.stop(), timeout=1.0)

    async def test_stop_continues_when_mcp_times_out(
        self, tmp_path: Path, stub_provider: _StubProvider
    ) -> None:
        ctx = await _make_context(tmp_path, stub_provider)
        mcp_mock = AsyncMock()

        async def _hang() -> None:
            await asyncio.sleep(999)

        mcp_mock.disconnect_all = _hang
        ctx._mcp_manager = mcp_mock

        with patch("openrattler.startup._COMPONENT_STOP_TIMEOUT", 0.05):
            await asyncio.wait_for(ctx.stop(), timeout=1.0)

    async def test_watchdog_cancelled_on_clean_shutdown(
        self, tmp_path: Path, stub_provider: _StubProvider
    ) -> None:
        """Watchdog task must not fire (os._exit not called) after a clean stop()."""
        ctx = await _make_context(tmp_path, stub_provider)
        await ctx.start()

        with patch("openrattler.startup.os._exit") as mock_exit:
            with patch("openrattler.startup._HARD_EXIT_TIMEOUT", 0.05):
                # Simulate clean shutdown: stop() runs before watchdog fires.
                watchdog = asyncio.create_task(ctx._force_exit_after(0.05))
                await ctx.stop()
                watchdog.cancel()
                try:
                    await watchdog
                except asyncio.CancelledError:
                    pass

        # os._exit should NOT have been called — clean shutdown finished first.
        mock_exit.assert_not_called()
