"""Tests for IdentityLoader — prompt assembly, file resolution, bootstrap detection."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock

import pytest

from openrattler.identity.loader import IdentityLoader, TEMPLATE_FILES, RUNTIME_FILES
from openrattler.models.agents import AgentConfig, TrustLevel
from openrattler.models.tools import ToolDefinition
from openrattler.tools.registry import ToolRegistry

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
        # BOOTSTRAP.md content contains "First-Run Setup".
        assert "First-Run Setup" in prompt

    async def test_bootstrap_injected_when_user_md_empty(self, tmp_path: Path) -> None:
        (tmp_path / "USER.md").write_text("   \n  ", encoding="utf-8")
        loader = _make_loader(tmp_path)
        prompt = await loader.load_system_prompt()
        assert "First-Run Setup" in prompt

    async def test_user_md_injected_when_populated(self, tmp_path: Path) -> None:
        (tmp_path / "USER.md").write_text("Name: Alice\nTimezone: UTC", encoding="utf-8")
        loader = _make_loader(tmp_path)
        prompt = await loader.load_system_prompt()
        assert "Alice" in prompt
        assert "First-Run Setup" not in prompt

    async def test_bootstrap_not_injected_once_user_md_has_content(self, tmp_path: Path) -> None:
        (tmp_path / "USER.md").write_text("Anything meaningful.", encoding="utf-8")
        loader = _make_loader(tmp_path)
        prompt = await loader.load_system_prompt()
        assert "First-Run Setup" not in prompt


# ---------------------------------------------------------------------------
# Context section generation
# ---------------------------------------------------------------------------


class TestContextSection:
    async def test_context_section_present(self, tmp_path: Path) -> None:
        loader = _make_loader(tmp_path)
        prompt = await loader.load_system_prompt()
        assert "Available Context" in prompt

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
        assert "none" in prompt.lower()


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
        assert prompt.index("USER_MARKER") < prompt.index("Available Context")

    async def test_context_before_memory(self, tmp_path: Path) -> None:
        (tmp_path / "MEMORY.md").write_text("MEMORY_MARKER", encoding="utf-8")
        (tmp_path / "USER.md").write_text("user content", encoding="utf-8")
        loader = _make_loader(tmp_path)
        prompt = await loader.load_system_prompt()
        assert prompt.index("Available Context") < prompt.index("MEMORY_MARKER")
