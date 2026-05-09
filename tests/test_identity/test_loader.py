"""Tests for IdentityLoader — prompt assembly, file resolution, bootstrap detection."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock

import pytest

from openrattler.identity.loader import IdentityLoader, TEMPLATE_FILES, RUNTIME_FILES
from openrattler.models.agents import AgentConfig, TrustLevel
from openrattler.models.tools import ToolDefinition
from openrattler.tools.registry import ToolRegistry


def _make_app_config(
    profile: str = "standard",
    channels: dict[str, bool] | None = None,
) -> MagicMock:
    """Build a minimal AppConfig mock for loader tests."""
    mock = MagicMock()
    mock.security.profile = profile
    ch: dict[str, MagicMock] = {}
    for name, enabled in (channels or {}).items():
        ch_mock = MagicMock()
        ch_mock.enabled = enabled
        ch[name] = ch_mock
    mock.channels = ch
    return mock


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_config(allowed: list[str] | None = None) -> AgentConfig:
    return AgentConfig(
        agent_id="agent:main:main",
        name="Main",
        description="Test agent",
        model="test-model",
        trust_level=TrustLevel.main,
        allowed_tools=allowed or [],
    )


def _make_registry(*tool_names: str) -> ToolRegistry:
    reg = ToolRegistry()
    for name in tool_names:
        reg.register(
            ToolDefinition(
                name=name,
                description=f"Tool {name}",
                parameters={"type": "object", "properties": {}, "required": []},
                trust_level_required=TrustLevel.main,
            )
        )
    return reg


def _make_loader(
    tmp_path: Path,
    config: AgentConfig | None = None,
    registry: ToolRegistry | None = None,
) -> IdentityLoader:
    return IdentityLoader(
        identity_dir=tmp_path,
        agent_config=config or _make_config(),
        tool_registry=registry or _make_registry(),
    )


# ---------------------------------------------------------------------------
# Template fallback
# ---------------------------------------------------------------------------


class TestTemplateResolution:
    async def test_uses_user_copy_when_present(self, tmp_path: Path) -> None:
        (tmp_path / "SOUL.md").write_text("Custom soul.", encoding="utf-8")
        loader = _make_loader(tmp_path)
        prompt = await loader.load_system_prompt()
        assert "Custom soul." in prompt

    async def test_falls_back_to_package_template_when_absent(self, tmp_path: Path) -> None:
        # No files written — should fall back to bundled templates.
        loader = _make_loader(tmp_path)
        prompt = await loader.load_system_prompt()
        # SOUL.md template contains "Soul" heading.
        assert "Soul" in prompt

    async def test_user_copy_takes_precedence_over_template(self, tmp_path: Path) -> None:
        (tmp_path / "IDENTITY.md").write_text("Override identity.", encoding="utf-8")
        loader = _make_loader(tmp_path)
        prompt = await loader.load_system_prompt()
        assert "Override identity." in prompt
        # The bundled IDENTITY.md text should NOT appear.
        assert "OpenRattler" not in prompt

    async def test_all_template_files_defined(self) -> None:
        assert "SOUL.md" in TEMPLATE_FILES
        assert "IDENTITY.md" in TEMPLATE_FILES
        assert "BOOTSTRAP.md" in TEMPLATE_FILES
        assert "HEARTBEAT.md" in TEMPLATE_FILES

    async def test_all_runtime_files_defined(self) -> None:
        assert "USER.md" in RUNTIME_FILES
        assert "MEMORY.md" in RUNTIME_FILES


# ---------------------------------------------------------------------------
# Bootstrap detection
# ---------------------------------------------------------------------------


class TestBootstrapDetection:
    async def test_bootstrap_injected_when_user_md_absent(self, tmp_path: Path) -> None:
        loader = _make_loader(tmp_path)
        prompt = await loader.load_system_prompt()
        # BOOTSTRAP.md content contains this phrase in the new template.
        assert "No memory yet" in prompt

    async def test_bootstrap_injected_when_user_md_empty(self, tmp_path: Path) -> None:
        (tmp_path / "USER.md").write_text("   \n  ", encoding="utf-8")
        loader = _make_loader(tmp_path)
        prompt = await loader.load_system_prompt()
        assert "No memory yet" in prompt

    async def test_user_md_injected_when_populated(self, tmp_path: Path) -> None:
        (tmp_path / "USER.md").write_text("Name: Alice\nTimezone: UTC", encoding="utf-8")
        loader = _make_loader(tmp_path)
        prompt = await loader.load_system_prompt()
        assert "Alice" in prompt
        assert "No memory yet" not in prompt

    async def test_bootstrap_not_injected_once_user_md_has_content(self, tmp_path: Path) -> None:
        (tmp_path / "USER.md").write_text("Anything meaningful.", encoding="utf-8")
        loader = _make_loader(tmp_path)
        prompt = await loader.load_system_prompt()
        assert "No memory yet" not in prompt


# ---------------------------------------------------------------------------
# Context section generation
# ---------------------------------------------------------------------------


class TestContextSection:
    async def test_context_section_present(self, tmp_path: Path) -> None:
        loader = _make_loader(tmp_path)
        prompt = await loader.load_system_prompt()
        assert "## Context" in prompt

    async def test_datetime_in_context(self, tmp_path: Path) -> None:
        loader = _make_loader(tmp_path)
        prompt = await loader.load_system_prompt()
        assert "UTC" in prompt

    async def test_permitted_tools_listed(self, tmp_path: Path) -> None:
        config = _make_config(allowed=["web_search"])
        reg = _make_registry("web_search")
        loader = _make_loader(tmp_path, config=config, registry=reg)
        prompt = await loader.load_system_prompt()
        assert "web_search" in prompt

    async def test_unpermitted_tools_not_listed(self, tmp_path: Path) -> None:
        # Agent has no allowed_tools — empty list means no tools permitted.
        config = _make_config(allowed=[])
        reg = _make_registry("secret_tool")
        loader = _make_loader(tmp_path, config=config, registry=reg)
        prompt = await loader.load_system_prompt()
        assert "secret_tool" not in prompt

    async def test_no_tools_message_when_empty(self, tmp_path: Path) -> None:
        config = _make_config(allowed=[])
        loader = _make_loader(tmp_path, config=config, registry=_make_registry())
        prompt = await loader.load_system_prompt()
        assert "no tools currently permitted" in prompt


# ---------------------------------------------------------------------------
# MEMORY.md inclusion
# ---------------------------------------------------------------------------


class TestMemoryMdInclusion:
    async def test_memory_md_included_when_present(self, tmp_path: Path) -> None:
        (tmp_path / "MEMORY.md").write_text("Currently working on project X.", encoding="utf-8")
        loader = _make_loader(tmp_path)
        prompt = await loader.load_system_prompt()
        assert "project X" in prompt
        assert "Working Memory" in prompt

    async def test_memory_md_omitted_when_empty(self, tmp_path: Path) -> None:
        (tmp_path / "MEMORY.md").write_text("", encoding="utf-8")
        loader = _make_loader(tmp_path)
        prompt = await loader.load_system_prompt()
        assert "Working Memory" not in prompt

    async def test_memory_md_omitted_when_absent(self, tmp_path: Path) -> None:
        loader = _make_loader(tmp_path)
        prompt = await loader.load_system_prompt()
        assert "Working Memory" not in prompt


# ---------------------------------------------------------------------------
# Heartbeat
# ---------------------------------------------------------------------------


class TestHeartbeat:
    async def test_heartbeat_section_loads(self, tmp_path: Path) -> None:
        loader = _make_loader(tmp_path)
        section = await loader.load_heartbeat_section()
        # HEARTBEAT.md template contains "Scheduled Check-In".
        assert "Scheduled Check-In" in section

    async def test_user_heartbeat_override(self, tmp_path: Path) -> None:
        (tmp_path / "HEARTBEAT.md").write_text("Custom heartbeat.", encoding="utf-8")
        loader = _make_loader(tmp_path)
        section = await loader.load_heartbeat_section()
        assert "Custom heartbeat." in section
        assert "Scheduled Check-In" not in section

    async def test_heartbeat_not_in_normal_prompt(self, tmp_path: Path) -> None:
        loader = _make_loader(tmp_path)
        prompt = await loader.load_system_prompt()
        # HEARTBEAT.md should only be loaded explicitly, not injected into
        # the standard system prompt.
        assert "Scheduled Check-In" not in prompt


# ---------------------------------------------------------------------------
# Prompt assembly order
# ---------------------------------------------------------------------------


class TestPromptOrder:
    async def test_soul_before_identity(self, tmp_path: Path) -> None:
        (tmp_path / "SOUL.md").write_text("AAA soul content.", encoding="utf-8")
        (tmp_path / "IDENTITY.md").write_text("BBB identity content.", encoding="utf-8")
        (tmp_path / "USER.md").write_text("CCC user content.", encoding="utf-8")
        loader = _make_loader(tmp_path)
        prompt = await loader.load_system_prompt()
        assert prompt.index("AAA") < prompt.index("BBB") < prompt.index("CCC")

    async def test_user_before_context(self, tmp_path: Path) -> None:
        (tmp_path / "USER.md").write_text("USER_MARKER", encoding="utf-8")
        loader = _make_loader(tmp_path)
        prompt = await loader.load_system_prompt()
        assert prompt.index("USER_MARKER") < prompt.index("## Context")

    async def test_context_before_memory(self, tmp_path: Path) -> None:
        (tmp_path / "MEMORY.md").write_text("MEMORY_MARKER", encoding="utf-8")
        (tmp_path / "USER.md").write_text("user content", encoding="utf-8")
        loader = _make_loader(tmp_path)
        prompt = await loader.load_system_prompt()
        assert prompt.index("## Context") < prompt.index("MEMORY_MARKER")


# ---------------------------------------------------------------------------
# Workspace block
# ---------------------------------------------------------------------------


class TestWorkspaceBlock:
    async def test_workspace_path_in_prompt(self, tmp_path: Path) -> None:
        loader = _make_loader(tmp_path)
        prompt = await loader.load_system_prompt()
        # identity_dir.parent is the workspace path shown in the block.
        assert str(tmp_path.parent) in prompt

    async def test_agent_id_in_prompt(self, tmp_path: Path) -> None:
        config = _make_config()
        loader = _make_loader(tmp_path, config=config)
        prompt = await loader.load_system_prompt()
        assert "agent:main:main" in prompt

    async def test_security_profile_from_config(self, tmp_path: Path) -> None:
        app_cfg = _make_app_config(profile="paranoid")
        loader = IdentityLoader(
            identity_dir=tmp_path,
            agent_config=_make_config(),
            tool_registry=_make_registry(),
            config=app_cfg,
        )
        prompt = await loader.load_system_prompt()
        assert "paranoid" in prompt

    async def test_security_profile_unknown_without_config(self, tmp_path: Path) -> None:
        loader = _make_loader(tmp_path)
        prompt = await loader.load_system_prompt()
        assert "unknown" in prompt

    async def test_init_date_read_from_file(self, tmp_path: Path) -> None:
        (tmp_path / ".init_date").write_text("2025-01-15", encoding="utf-8")
        loader = _make_loader(tmp_path)
        prompt = await loader.load_system_prompt()
        assert "2025-01-15" in prompt

    async def test_init_date_unknown_when_absent(self, tmp_path: Path) -> None:
        loader = _make_loader(tmp_path)
        prompt = await loader.load_system_prompt()
        # No .init_date file — should show "unknown".
        assert "unknown" in prompt


# ---------------------------------------------------------------------------
# Channels block
# ---------------------------------------------------------------------------


class TestChannelsBlock:
    async def test_channels_block_always_present(self, tmp_path: Path) -> None:
        loader = _make_loader(tmp_path)
        prompt = await loader.load_system_prompt()
        assert "### Channels" in prompt

    async def test_enabled_channel_listed(self, tmp_path: Path) -> None:
        app_cfg = _make_app_config(channels={"slack": True})
        loader = IdentityLoader(
            identity_dir=tmp_path,
            agent_config=_make_config(),
            tool_registry=_make_registry(),
            config=app_cfg,
        )
        prompt = await loader.load_system_prompt()
        assert "slack" in prompt

    async def test_disabled_channel_not_listed(self, tmp_path: Path) -> None:
        app_cfg = _make_app_config(channels={"slack": False})
        loader = IdentityLoader(
            identity_dir=tmp_path,
            agent_config=_make_config(),
            tool_registry=_make_registry(),
            config=app_cfg,
        )
        prompt = await loader.load_system_prompt()
        assert "slack" not in prompt

    async def test_no_channels_without_config(self, tmp_path: Path) -> None:
        # Without AppConfig, no dynamic channel rows appear (only the CLI row).
        loader = _make_loader(tmp_path)
        prompt = await loader.load_system_prompt()
        assert "### Channels" in prompt
        assert "CLI" in prompt


# ---------------------------------------------------------------------------
# Tools block — trust level grouping
# ---------------------------------------------------------------------------


def _make_registry_multi() -> ToolRegistry:
    """Registry with tools at three different trust levels."""
    reg = ToolRegistry()
    reg.register(
        ToolDefinition(
            name="public_tool",
            description="Available to all",
            parameters={"type": "object", "properties": {}, "required": []},
            trust_level_required=TrustLevel.public,
        )
    )
    reg.register(
        ToolDefinition(
            name="main_tool",
            description="Needs main trust",
            parameters={"type": "object", "properties": {}, "required": []},
            trust_level_required=TrustLevel.main,
        )
    )
    reg.register(
        ToolDefinition(
            name="local_tool",
            description="Needs local trust",
            parameters={"type": "object", "properties": {}, "required": []},
            trust_level_required=TrustLevel.local,
            requires_approval=True,
        )
    )
    return reg


def _make_local_agent_config(allowed: list[str]) -> AgentConfig:
    """Agent config at local trust level — can use tools up to local trust."""
    return AgentConfig(
        agent_id="agent:main:main",
        name="Main",
        description="Test agent",
        model="test-model",
        trust_level=TrustLevel.local,
        allowed_tools=allowed,
    )


class TestToolsBlock:
    async def test_tools_grouped_by_trust_level(self, tmp_path: Path) -> None:
        config = _make_local_agent_config(["public_tool", "main_tool", "local_tool"])
        reg = _make_registry_multi()
        loader = _make_loader(tmp_path, config=config, registry=reg)
        prompt = await loader.load_system_prompt()
        assert "public_tool" in prompt
        assert "main_tool" in prompt
        assert "local_tool" in prompt

    async def test_trust_level_headings_in_prompt(self, tmp_path: Path) -> None:
        config = _make_config(allowed=["public_tool", "main_tool"])
        reg = _make_registry_multi()
        loader = _make_loader(tmp_path, config=config, registry=reg)
        prompt = await loader.load_system_prompt()
        assert "`public` trust required" in prompt
        assert "`main` trust required" in prompt

    async def test_authorized_tiers_for_public(self, tmp_path: Path) -> None:
        # public trust = all tiers authorized.
        config = _make_config(allowed=["public_tool"])
        reg = _make_registry_multi()
        loader = _make_loader(tmp_path, config=config, registry=reg)
        prompt = await loader.load_system_prompt()
        assert "`public`" in prompt
        assert "`main`" in prompt
        assert "`local`" in prompt
        assert "`security`" in prompt

    async def test_authorized_tiers_for_local(self, tmp_path: Path) -> None:
        # local trust = only local + security authorized.
        config = _make_local_agent_config(["local_tool"])
        reg = _make_registry_multi()
        loader = _make_loader(tmp_path, config=config, registry=reg)
        prompt = await loader.load_system_prompt()
        # local and security appear in the authorized list for local_tool.
        assert "`local` trust required" in prompt
        # public and main should NOT appear as authorized for this group.
        # (check via the "authorized:" suffix line for local group)
        local_section_start = prompt.index("`local` trust required")
        local_section = prompt[local_section_start : local_section_start + 200]
        assert "`local`" in local_section
        assert "`security`" in local_section

    async def test_authorized_tiers_for_mcp(self, tmp_path: Path) -> None:
        # mcp trust = main and above are authorized (not empty!).
        # Regression for bug where _TRUST_ORDER[mcp]=4 caused _authorized_tiers
        # to return [] for mcp-level tools, making them appear "not enabled".
        reg = ToolRegistry()
        reg.register(
            ToolDefinition(
                name="mcp_tool",
                description="MCP weather tool",
                parameters={"type": "object", "properties": {}, "required": []},
                trust_level_required=TrustLevel.mcp,
            )
        )
        config = _make_config(allowed=["mcp_tool"])
        loader = _make_loader(tmp_path, config=config, registry=reg)
        prompt = await loader.load_system_prompt()
        mcp_section_start = prompt.index("`mcp` trust required")
        mcp_section = prompt[mcp_section_start : mcp_section_start + 200]
        # main, local, and security are all authorized to call mcp-level tools.
        assert "`main`" in mcp_section
        assert "`local`" in mcp_section
        assert "`security`" in mcp_section
        # public is not authorized.
        assert "`public`" not in mcp_section

    async def test_approval_flag_shown(self, tmp_path: Path) -> None:
        config = _make_config(allowed=["local_tool"])
        reg = _make_registry_multi()
        loader = _make_loader(tmp_path, config=config, registry=reg)
        prompt = await loader.load_system_prompt()
        assert "Yes" in prompt  # requires_approval=True tool.

    async def test_no_approval_flag_for_normal_tool(self, tmp_path: Path) -> None:
        config = _make_config(allowed=["main_tool"])
        reg = _make_registry_multi()
        loader = _make_loader(tmp_path, config=config, registry=reg)
        prompt = await loader.load_system_prompt()
        assert "No" in prompt  # requires_approval=False (default).


# ---------------------------------------------------------------------------
# Security notes block
# ---------------------------------------------------------------------------


class TestSecurityNotesBlock:
    async def test_security_notes_always_present(self, tmp_path: Path) -> None:
        loader = _make_loader(tmp_path)
        prompt = await loader.load_system_prompt()
        assert "### Security Notes" in prompt

    async def test_profile_in_security_notes(self, tmp_path: Path) -> None:
        app_cfg = _make_app_config(profile="minimal")
        loader = IdentityLoader(
            identity_dir=tmp_path,
            agent_config=_make_config(),
            tool_registry=_make_registry(),
            config=app_cfg,
        )
        prompt = await loader.load_system_prompt()
        assert "minimal" in prompt
