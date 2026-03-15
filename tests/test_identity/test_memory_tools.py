"""Tests for NarrativeMemoryTools — update_memory_narrative and update_user_profile."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import AsyncMock, MagicMock

import pytest

from openrattler.config.loader import MemoryConfig
from openrattler.security.memory_security import MemorySecurityAgent, SecurityResult
from openrattler.storage.audit import AuditLog
from openrattler.tools.builtin.memory_tools import (
    NarrativeMemoryTools,
    _approx_tokens,
    _atomic_write,
    _PRUNE_WARNING_THRESHOLD,
)
from openrattler.tools.registry import ToolRegistry

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _clean_security_agent() -> MemorySecurityAgent:
    """A security agent that always approves writes."""
    agent = MagicMock(spec=MemorySecurityAgent)
    agent.review_memory_change = AsyncMock(
        return_value=SecurityResult(suspicious=False, reason=None, confidence=0)
    )
    return agent


def _blocking_security_agent(reason: str = "test block") -> MemorySecurityAgent:
    """A security agent that always blocks writes."""
    agent = MagicMock(spec=MemorySecurityAgent)
    agent.review_memory_change = AsyncMock(
        return_value=SecurityResult(suspicious=True, reason=reason, confidence=100)
    )
    return agent


def _make_tools(
    tmp_path: Path,
    *,
    max_tokens: int = 2000,
    max_write_tokens: int = 300,
    user_max_tokens: int = 500,
    security_agent: MemorySecurityAgent | None = None,
) -> tuple[NarrativeMemoryTools, ToolRegistry]:
    config = MemoryConfig(
        narrative_max_tokens=max_tokens,
        narrative_max_write_tokens=max_write_tokens,
        user_profile_max_tokens=user_max_tokens,
    )
    audit = MagicMock(spec=AuditLog)
    audit.log = AsyncMock()
    tools = NarrativeMemoryTools(
        identity_dir=tmp_path,
        memory_config=config,
        security_agent=security_agent or _clean_security_agent(),
        audit=audit,
    )
    reg = ToolRegistry()
    tools.register_all(reg)
    return tools, reg


# ---------------------------------------------------------------------------
# Token approximation
# ---------------------------------------------------------------------------


class TestApproxTokens:
    def test_empty_string_returns_one(self) -> None:
        assert _approx_tokens("") == 1

    def test_four_chars_is_one_token(self) -> None:
        assert _approx_tokens("abcd") == 1

    def test_eight_chars_is_two_tokens(self) -> None:
        assert _approx_tokens("abcdefgh") == 2

    def test_large_string(self) -> None:
        text = "a" * 4000
        assert _approx_tokens(text) == 1000


# ---------------------------------------------------------------------------
# Tool registration
# ---------------------------------------------------------------------------


class TestRegistration:
    def test_update_memory_narrative_registered(self, tmp_path: Path) -> None:
        _, reg = _make_tools(tmp_path)
        assert reg.get("update_memory_narrative") is not None

    def test_update_user_profile_registered(self, tmp_path: Path) -> None:
        _, reg = _make_tools(tmp_path)
        assert reg.get("update_user_profile") is not None

    def test_narrative_tool_has_enum_for_mode(self, tmp_path: Path) -> None:
        _, reg = _make_tools(tmp_path)
        td = reg.get("update_memory_narrative")
        assert td is not None
        mode_schema = td.parameters["properties"]["mode"]
        assert "enum" in mode_schema
        assert set(mode_schema["enum"]) == {"append", "replace"}


# ---------------------------------------------------------------------------
# update_memory_narrative — append mode
# ---------------------------------------------------------------------------


class TestUpdateMemoryNarrativeAppend:
    async def test_append_creates_file_if_absent(self, tmp_path: Path) -> None:
        tools, _ = _make_tools(tmp_path)
        result = await tools._update_memory_narrative(mode="append", content="First entry.")
        assert "Written" in result
        assert (tmp_path / "MEMORY.md").read_text(encoding="utf-8") == "First entry."

    async def test_append_adds_to_existing_content(self, tmp_path: Path) -> None:
        (tmp_path / "MEMORY.md").write_text("Existing.", encoding="utf-8")
        tools, _ = _make_tools(tmp_path)
        await tools._update_memory_narrative(mode="append", content="New entry.")
        content = (tmp_path / "MEMORY.md").read_text(encoding="utf-8")
        assert "Existing." in content
        assert "New entry." in content

    async def test_append_reports_token_usage(self, tmp_path: Path) -> None:
        tools, _ = _make_tools(tmp_path)
        result = await tools._update_memory_narrative(mode="append", content="Hello.")
        assert "/" in result  # "X/2000 tokens"

    async def test_append_write_limit_enforced(self, tmp_path: Path) -> None:
        tools, _ = _make_tools(tmp_path, max_write_tokens=5)
        big = "a" * 100  # ~25 tokens
        result = await tools._update_memory_narrative(mode="append", content=big)
        assert "Error" in result
        assert "per-write limit" in result
        assert not (tmp_path / "MEMORY.md").exists()

    async def test_append_file_limit_enforced(self, tmp_path: Path) -> None:
        tools, _ = _make_tools(tmp_path, max_tokens=10, max_write_tokens=300)
        existing = "x" * 39  # ~9 tokens — file almost full
        (tmp_path / "MEMORY.md").write_text(existing, encoding="utf-8")
        result = await tools._update_memory_narrative(
            mode="append", content="y" * 20  # ~5 tokens — would push past 10
        )
        assert "Error" in result
        assert "file limit" in result

    async def test_near_full_warning_triggered(self, tmp_path: Path) -> None:
        # max_tokens=100, write ~85 tokens (≥80% threshold)
        tools, _ = _make_tools(tmp_path, max_tokens=100, max_write_tokens=400)
        content = "z" * 340  # ~85 tokens
        result = await tools._update_memory_narrative(mode="append", content=content)
        assert "nearing its limit" in result

    async def test_no_warning_below_threshold(self, tmp_path: Path) -> None:
        tools, _ = _make_tools(tmp_path, max_tokens=1000, max_write_tokens=400)
        content = "a" * 40  # ~10 tokens
        result = await tools._update_memory_narrative(mode="append", content=content)
        assert "nearing" not in result


# ---------------------------------------------------------------------------
# update_memory_narrative — replace mode
# ---------------------------------------------------------------------------


class TestUpdateMemoryNarrativeReplace:
    async def test_replace_overwrites_existing(self, tmp_path: Path) -> None:
        (tmp_path / "MEMORY.md").write_text("Old content.", encoding="utf-8")
        tools, _ = _make_tools(tmp_path)
        await tools._update_memory_narrative(mode="replace", content="Completely new.")
        assert (tmp_path / "MEMORY.md").read_text(encoding="utf-8") == "Completely new."

    async def test_replace_reports_written(self, tmp_path: Path) -> None:
        tools, _ = _make_tools(tmp_path)
        result = await tools._update_memory_narrative(mode="replace", content="New content.")
        assert "Written" in result

    async def test_replace_file_limit_enforced(self, tmp_path: Path) -> None:
        tools, _ = _make_tools(tmp_path, max_tokens=5, max_write_tokens=300)
        big = "b" * 80  # ~20 tokens
        result = await tools._update_memory_narrative(mode="replace", content=big)
        assert "Error" in result
        assert "file limit" in result


# ---------------------------------------------------------------------------
# update_memory_narrative — invalid mode
# ---------------------------------------------------------------------------


class TestInvalidMode:
    async def test_invalid_mode_returns_error(self, tmp_path: Path) -> None:
        tools, _ = _make_tools(tmp_path)
        result = await tools._update_memory_narrative(mode="upsert", content="hello")
        assert "Error" in result
        assert "mode" in result


# ---------------------------------------------------------------------------
# update_memory_narrative — security gate
# ---------------------------------------------------------------------------


class TestSecurityGate:
    async def test_blocked_write_returns_error(self, tmp_path: Path) -> None:
        tools, _ = _make_tools(
            tmp_path, security_agent=_blocking_security_agent("injection detected")
        )
        result = await tools._update_memory_narrative(mode="append", content="Safe text.")
        assert "Error" in result
        assert "security review" in result
        assert not (tmp_path / "MEMORY.md").exists()

    async def test_security_agent_called_with_content(self, tmp_path: Path) -> None:
        agent = _clean_security_agent()
        tools, _ = _make_tools(tmp_path, security_agent=agent)
        await tools._update_memory_narrative(mode="append", content="Check this.")
        agent.review_memory_change.assert_called_once()
        call_kwargs = agent.review_memory_change.call_args
        # The diff passed to the agent should contain the new content.
        diff_arg = call_kwargs[1]["diff"] if call_kwargs[1] else call_kwargs[0][1]
        assert "Check this." in str(diff_arg)

    async def test_approved_write_persists(self, tmp_path: Path) -> None:
        tools, _ = _make_tools(tmp_path, security_agent=_clean_security_agent())
        await tools._update_memory_narrative(mode="append", content="Approved content.")
        assert "Approved content." in (tmp_path / "MEMORY.md").read_text(encoding="utf-8")


# ---------------------------------------------------------------------------
# update_user_profile
# ---------------------------------------------------------------------------


class TestUpdateUserProfile:
    async def test_creates_user_md(self, tmp_path: Path) -> None:
        tools, _ = _make_tools(tmp_path)
        result = await tools._update_user_profile(content="Name: Alice\nTimezone: UTC")
        assert "Written" in result
        assert "Alice" in (tmp_path / "USER.md").read_text(encoding="utf-8")

    async def test_replaces_existing_user_md(self, tmp_path: Path) -> None:
        (tmp_path / "USER.md").write_text("Old profile.", encoding="utf-8")
        tools, _ = _make_tools(tmp_path)
        await tools._update_user_profile(content="New profile.")
        assert (tmp_path / "USER.md").read_text(encoding="utf-8") == "New profile."

    async def test_token_limit_enforced(self, tmp_path: Path) -> None:
        tools, _ = _make_tools(tmp_path, user_max_tokens=5)
        big = "x" * 100  # ~25 tokens
        result = await tools._update_user_profile(content=big)
        assert "Error" in result
        assert not (tmp_path / "USER.md").exists()

    async def test_security_gate_blocks_write(self, tmp_path: Path) -> None:
        tools, _ = _make_tools(
            tmp_path, security_agent=_blocking_security_agent("suspicious content")
        )
        result = await tools._update_user_profile(content="Innocent profile.")
        assert "Error" in result
        assert "security review" in result

    async def test_reports_token_usage(self, tmp_path: Path) -> None:
        tools, _ = _make_tools(tmp_path)
        result = await tools._update_user_profile(content="Name: Bob")
        assert "/" in result  # token usage fraction


# ---------------------------------------------------------------------------
# Atomic write helper
# ---------------------------------------------------------------------------


class TestAtomicWrite:
    def test_creates_file(self, tmp_path: Path) -> None:
        target = tmp_path / "test.md"
        _atomic_write(target, "hello world")
        assert target.read_text(encoding="utf-8") == "hello world"

    def test_overwrites_existing(self, tmp_path: Path) -> None:
        target = tmp_path / "test.md"
        target.write_text("old content", encoding="utf-8")
        _atomic_write(target, "new content")
        assert target.read_text(encoding="utf-8") == "new content"

    def test_no_tmp_file_left_on_success(self, tmp_path: Path) -> None:
        target = tmp_path / "test.md"
        _atomic_write(target, "data")
        tmp = target.with_suffix(target.suffix + ".tmp")
        assert not tmp.exists()


# ---------------------------------------------------------------------------
# MemoryConfig defaults
# ---------------------------------------------------------------------------


class TestMemoryConfig:
    def test_default_narrative_max_tokens(self) -> None:
        cfg = MemoryConfig()
        assert cfg.narrative_max_tokens == 2000

    def test_default_narrative_max_write_tokens(self) -> None:
        cfg = MemoryConfig()
        assert cfg.narrative_max_write_tokens == 300

    def test_default_user_profile_max_tokens(self) -> None:
        cfg = MemoryConfig()
        assert cfg.user_profile_max_tokens == 500

    def test_custom_values_accepted(self) -> None:
        cfg = MemoryConfig(
            narrative_max_tokens=5000,
            narrative_max_write_tokens=600,
            user_profile_max_tokens=1000,
        )
        assert cfg.narrative_max_tokens == 5000
        assert cfg.narrative_max_write_tokens == 600
        assert cfg.user_profile_max_tokens == 1000
