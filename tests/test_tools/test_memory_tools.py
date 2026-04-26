"""Tests for NarrativeMemoryTools — HEARTBEAT.md and MEMORY.md update paths."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import AsyncMock, MagicMock

import pytest

from openrattler.config.loader import MemoryConfig
from openrattler.tools.builtin.memory_tools import NarrativeMemoryTools

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_security_agent(suspicious: bool = False, reason: str = "") -> MagicMock:
    result = MagicMock()
    result.suspicious = suspicious
    result.reason = reason
    agent = MagicMock()
    agent.review_memory_change = AsyncMock(return_value=result)
    return agent


def _make_tools(
    tmp_path: Path,
    suspicious: bool = False,
    reason: str = "",
) -> NarrativeMemoryTools:
    audit = MagicMock()
    audit.log = MagicMock()
    return NarrativeMemoryTools(
        identity_dir=tmp_path,
        memory_config=MemoryConfig(),
        security_agent=_make_security_agent(suspicious=suspicious, reason=reason),
        audit=audit,
    )


_VALID_HEARTBEAT_CONTENT = "# Heartbeat\n\nCheck pending alerts every hour."
_VALID_RATIONALE = "Observed 3 false positives on budget_review topic in the last 7 cycles."


# ---------------------------------------------------------------------------
# TestUpdateHeartbeat
# ---------------------------------------------------------------------------


class TestUpdateHeartbeat:
    async def test_missing_rationale_returns_error_before_security_agent(
        self, tmp_path: Path
    ) -> None:
        tools = _make_tools(tmp_path)
        result = await tools._update_heartbeat(content=_VALID_HEARTBEAT_CONTENT, rationale="")
        assert "rationale" in result.lower()
        assert "Error" in result
        # Security agent must NOT have been called.
        tools._security_agent.review_memory_change.assert_not_awaited()

    async def test_whitespace_only_rationale_returns_error(self, tmp_path: Path) -> None:
        tools = _make_tools(tmp_path)
        result = await tools._update_heartbeat(content=_VALID_HEARTBEAT_CONTENT, rationale="   ")
        assert "Error" in result
        tools._security_agent.review_memory_change.assert_not_awaited()

    async def test_valid_rationale_routes_to_security_agent(self, tmp_path: Path) -> None:
        tools = _make_tools(tmp_path)
        await tools._update_heartbeat(content=_VALID_HEARTBEAT_CONTENT, rationale=_VALID_RATIONALE)
        tools._security_agent.review_memory_change.assert_awaited_once()

    async def test_approval_metadata_includes_change_type(self, tmp_path: Path) -> None:
        tools = _make_tools(tmp_path)
        await tools._update_heartbeat(content=_VALID_HEARTBEAT_CONTENT, rationale=_VALID_RATIONALE)
        call_kwargs = tools._security_agent.review_memory_change.await_args[1]
        diff_arg = call_kwargs["diff"]
        assert diff_arg.get("change_type") == "autonomous_routine_update"

    async def test_approval_metadata_includes_diff_field(self, tmp_path: Path) -> None:
        # Write an initial HEARTBEAT.md so there is existing content for a real diff.
        heartbeat_path = tmp_path / "HEARTBEAT.md"
        heartbeat_path.write_text("# Old content\n", encoding="utf-8")
        tools = _make_tools(tmp_path)
        await tools._update_heartbeat(content=_VALID_HEARTBEAT_CONTENT, rationale=_VALID_RATIONALE)
        call_kwargs = tools._security_agent.review_memory_change.await_args[1]
        diff_arg = call_kwargs["diff"]
        assert "diff" in diff_arg
        assert diff_arg["diff"]  # non-empty

    async def test_non_heartbeat_files_do_not_include_change_type(self, tmp_path: Path) -> None:
        tools = _make_tools(tmp_path)
        await tools._update_identity(content="# Identity\n\nCorvus the raven.")
        call_kwargs = tools._security_agent.review_memory_change.await_args[1]
        diff_arg = call_kwargs["diff"]
        # Non-HEARTBEAT tools use _build_diff which does not include change_type.
        assert "change_type" not in diff_arg

    async def test_security_blocked_heartbeat_returns_error(self, tmp_path: Path) -> None:
        tools = _make_tools(tmp_path, suspicious=True, reason="scope creep detected")
        result = await tools._update_heartbeat(
            content=_VALID_HEARTBEAT_CONTENT, rationale=_VALID_RATIONALE
        )
        assert "blocked" in result.lower() or "Error" in result
        assert "scope creep" in result

    async def test_security_approved_heartbeat_writes_file(self, tmp_path: Path) -> None:
        tools = _make_tools(tmp_path)
        result = await tools._update_heartbeat(
            content=_VALID_HEARTBEAT_CONTENT, rationale=_VALID_RATIONALE
        )
        assert "Written" in result
        heartbeat_path = tmp_path / "HEARTBEAT.md"
        assert heartbeat_path.exists()
        assert "Check pending alerts" in heartbeat_path.read_text(encoding="utf-8")

    async def test_approval_metadata_includes_rationale(self, tmp_path: Path) -> None:
        tools = _make_tools(tmp_path)
        await tools._update_heartbeat(content=_VALID_HEARTBEAT_CONTENT, rationale=_VALID_RATIONALE)
        call_kwargs = tools._security_agent.review_memory_change.await_args[1]
        diff_arg = call_kwargs["diff"]
        assert diff_arg.get("rationale") == _VALID_RATIONALE


# ---------------------------------------------------------------------------
# TestUpdateMemoryNarrative
# ---------------------------------------------------------------------------


def _make_tools_with_limits(
    tmp_path: Path,
    max_write: int = 300,
    max_file: int = 4000,
) -> NarrativeMemoryTools:
    """Build tools with explicit token limits for limit-boundary tests."""
    audit = MagicMock()
    audit.log = MagicMock()
    config = MemoryConfig(narrative_max_write_tokens=max_write, narrative_max_tokens=max_file)
    return NarrativeMemoryTools(
        identity_dir=tmp_path,
        memory_config=config,
        security_agent=_make_security_agent(suspicious=False),
        audit=audit,
    )


class TestUpdateMemoryNarrative:
    async def test_append_over_write_limit_returns_error(self, tmp_path: Path) -> None:
        # Content that exceeds narrative_max_write_tokens should be rejected for append.
        tools = _make_tools_with_limits(tmp_path, max_write=10, max_file=4000)
        long_content = "x" * 200  # 50 approx tokens — well over limit of 10
        result = await tools._update_memory_narrative(mode="append", content=long_content)
        assert "Error" in result
        assert "per-write limit" in result

    async def test_replace_over_write_limit_succeeds_if_under_file_limit(
        self, tmp_path: Path
    ) -> None:
        # Replace mode must NOT be blocked by narrative_max_write_tokens.
        # This was the consolidation bug: a near-full file could not be pruned because
        # the replacement content (> 300 write tokens) hit the per-write limit first.
        tools = _make_tools_with_limits(tmp_path, max_write=10, max_file=4000)
        condensed_content = "x" * 200  # 50 approx tokens — over write limit but under file limit
        result = await tools._update_memory_narrative(mode="replace", content=condensed_content)
        assert "Written" in result

    async def test_replace_over_file_limit_returns_error(self, tmp_path: Path) -> None:
        # Replace mode is still capped by the file limit.
        tools = _make_tools_with_limits(tmp_path, max_write=300, max_file=10)
        oversized = "x" * 200  # 50 approx tokens — over the file limit of 10
        result = await tools._update_memory_narrative(mode="replace", content=oversized)
        assert "Error" in result
        assert "file limit" in result

    async def test_append_within_limits_writes_file(self, tmp_path: Path) -> None:
        tools = _make_tools_with_limits(tmp_path, max_write=300, max_file=4000)
        result = await tools._update_memory_narrative(
            mode="append", content="## Session 11\n\nAll good."
        )
        assert "Written" in result
        memory_path = tmp_path / "MEMORY.md"
        assert "Session 11" in memory_path.read_text(encoding="utf-8")
