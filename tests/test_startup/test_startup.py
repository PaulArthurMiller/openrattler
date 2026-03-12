"""Tests for openrattler.startup — ApplicationContext and build_application."""

from __future__ import annotations

import asyncio
from pathlib import Path
from typing import Any, Optional
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from openrattler.agents.providers.base import LLMProvider, LLMResponse
from openrattler.channels.base import ChannelAdapter
from openrattler.config.loader import AppConfig, ChannelConfig
from openrattler.models.social import SocialSecretaryConfig
from openrattler.startup import ApplicationContext, _build_channel_adapters, build_application

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
        ctx = await build_application(
            workspace_dir=tmp_path / "ws",
            config_path=tmp_path / "cfg.json",
            provider=stub_provider,
            mcp_manifests_dir=empty_mcp_dir,
            start_gateway=False,
        )
        assert ctx._scheduler is None

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
