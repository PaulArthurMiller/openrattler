"""Tests for NarrativeMemoryTools — HEARTBEAT.md and MEMORY.md update paths."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock

import pytest

from openrattler.config.loader import MemoryConfig
from openrattler.tools.builtin.memory_tools import (
    NarrativeMemoryTools,
    _extract_section_date,
    _split_sections,
)

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


# ---------------------------------------------------------------------------
# TestExtractSectionDate (unit tests for module-level helper)
# ---------------------------------------------------------------------------


class TestExtractSectionDate:
    def test_date_in_heading_returns_datetime(self) -> None:
        section = "## Entry 2026-05-01\n\nContent here."
        result = _extract_section_date(section)
        assert result is not None
        assert result.year == 2026
        assert result.month == 5
        assert result.day == 1

    def test_date_in_heading_is_utc(self) -> None:
        section = "## Heartbeat 2026-01-15 — no alerts\n\nContent."
        result = _extract_section_date(section)
        assert result is not None
        assert result.tzinfo is timezone.utc

    def test_no_date_in_heading_returns_none(self) -> None:
        section = "## General Notes\n\nNo date here."
        result = _extract_section_date(section)
        assert result is None

    def test_date_only_searched_in_first_line(self) -> None:
        # Date in second line should not be found.
        section = "## General Notes\n\n2026-05-01 something."
        result = _extract_section_date(section)
        assert result is None


# ---------------------------------------------------------------------------
# TestSplitSections (unit tests for module-level helper)
# ---------------------------------------------------------------------------


class TestSplitSections:
    def test_preamble_before_first_heading_extracted(self) -> None:
        content = "# MEMORY\n\nIntro text.\n\n## Section 2026-01-01\n\nBody."
        preamble, sections = _split_sections(content)
        assert "Intro text" in preamble
        assert len(sections) == 1

    def test_no_preamble_when_content_starts_with_heading(self) -> None:
        content = "## Section 2026-01-01\n\nBody."
        preamble, sections = _split_sections(content)
        assert preamble == ""
        assert len(sections) == 1

    def test_subsections_not_split(self) -> None:
        # ### sub-headings must stay inside their parent section.
        content = (
            "## Section 2026-01-01\n\n### Sub-heading\n\nBody.\n\n## Section 2026-01-08\n\nMore."
        )
        _, sections = _split_sections(content)
        assert len(sections) == 2
        assert "### Sub-heading" in sections[0][1]

    def test_dated_section_paired_with_date(self) -> None:
        content = "## Entry 2026-03-15\n\nContent."
        _, sections = _split_sections(content)
        assert len(sections) == 1
        date, _ = sections[0]
        assert date is not None
        assert date.day == 15

    def test_undated_section_paired_with_none(self) -> None:
        content = "## Standing Notes\n\nContent."
        _, sections = _split_sections(content)
        date, _ = sections[0]
        assert date is None


# ---------------------------------------------------------------------------
# TestConsolidateMemoryHistory
# ---------------------------------------------------------------------------


def _old_date(days: int = 30) -> str:
    """Return a date string `days` days ago."""
    return (datetime.now(timezone.utc) - timedelta(days=days)).strftime("%Y-%m-%d")


def _recent_date() -> str:
    """Return today's date string."""
    return datetime.now(timezone.utc).strftime("%Y-%m-%d")


class TestConsolidateMemoryHistory:
    def _write_memory(self, tmp_path: Path, content: str) -> None:
        (tmp_path / "MEMORY.md").write_text(content, encoding="utf-8")

    async def test_no_memory_file_returns_message(self, tmp_path: Path) -> None:
        tools = _make_tools(tmp_path)
        result = await tools._consolidate_memory_history(days_to_keep=7)
        assert "does not exist" in result
        print(f"[test] result: {result}")

    async def test_empty_memory_file_returns_message(self, tmp_path: Path) -> None:
        self._write_memory(tmp_path, "   ")
        tools = _make_tools(tmp_path)
        result = await tools._consolidate_memory_history(days_to_keep=7)
        assert "empty" in result.lower() or "nothing" in result.lower()
        print(f"[test] result: {result}")

    async def test_days_to_keep_zero_returns_error(self, tmp_path: Path) -> None:
        tools = _make_tools(tmp_path)
        result = await tools._consolidate_memory_history(days_to_keep=0)
        assert "Error" in result
        print(f"[test] result: {result}")

    async def test_no_old_entries_returns_nothing_to_consolidate(self, tmp_path: Path) -> None:
        today = _recent_date()
        content = f"## Entry {today}\n\nRecent content."
        self._write_memory(tmp_path, content)
        tools = _make_tools(tmp_path)
        result = await tools._consolidate_memory_history(days_to_keep=7)
        assert "nothing to consolidate" in result.lower()
        print(f"[test] result: {result}")

    async def test_old_entries_routed_through_update_memory_narrative(self, tmp_path: Path) -> None:
        # Verify the consolidation call chain goes through _update_memory_narrative.
        content = f"## Entry {_old_date(30)}\n\nOld content."
        self._write_memory(tmp_path, content)
        tools = _make_tools(tmp_path)
        # Patch the internal method to spy on calls.
        tools._update_memory_narrative = AsyncMock(
            return_value="Written. MEMORY.md is now approximately 10/4000 tokens."
        )
        await tools._consolidate_memory_history(days_to_keep=7)
        tools._update_memory_narrative.assert_awaited_once()
        call_args = tools._update_memory_narrative.await_args
        assert call_args.kwargs.get("mode") == "replace"
        print("[test] _update_memory_narrative called with mode='replace'")

    async def test_recent_entries_retained_verbatim(self, tmp_path: Path) -> None:
        today = _recent_date()
        content = (
            f"## Entry {_old_date(30)}\n\nOld content.\n\n" f"## Entry {today}\n\nRecent content."
        )
        self._write_memory(tmp_path, content)
        tools = _make_tools(tmp_path)
        await tools._consolidate_memory_history(days_to_keep=7)
        written = (tmp_path / "MEMORY.md").read_text(encoding="utf-8")
        assert f"## Entry {today}" in written
        assert "Recent content" in written
        print(f"[test] recent entry preserved in written MEMORY.md")

    async def test_old_entries_compressed_into_week_summary(self, tmp_path: Path) -> None:
        content = f"## Entry {_old_date(30)}\n\nOld content."
        self._write_memory(tmp_path, content)
        tools = _make_tools(tmp_path)
        await tools._consolidate_memory_history(days_to_keep=7)
        written = (tmp_path / "MEMORY.md").read_text(encoding="utf-8")
        assert "Old content" not in written
        assert "(consolidated)" in written
        print(f"[test] old entry compressed: {written[:150]}")

    async def test_multiple_weeks_produce_separate_summaries(self, tmp_path: Path) -> None:
        # Two entries in different ISO weeks, both older than 7 days.
        entry1 = _old_date(30)
        entry2 = _old_date(60)
        content = f"## Entry {entry2}\n\nOldest.\n\n" f"## Entry {entry1}\n\nOlder."
        self._write_memory(tmp_path, content)
        tools = _make_tools(tmp_path)
        await tools._consolidate_memory_history(days_to_keep=7)
        written = (tmp_path / "MEMORY.md").read_text(encoding="utf-8")
        assert written.count("(consolidated)") == 2
        print(f"[test] two week summaries present")

    async def test_preamble_preserved_in_consolidated_output(self, tmp_path: Path) -> None:
        content = (
            "# Working Memory\n\nPreamble text.\n\n" f"## Entry {_old_date(30)}\n\nOld content."
        )
        self._write_memory(tmp_path, content)
        tools = _make_tools(tmp_path)
        await tools._consolidate_memory_history(days_to_keep=7)
        written = (tmp_path / "MEMORY.md").read_text(encoding="utf-8")
        assert "Preamble text" in written
        print(f"[test] preamble preserved")

    async def test_security_blocked_returns_error(self, tmp_path: Path) -> None:
        content = f"## Entry {_old_date(30)}\n\nContent."
        self._write_memory(tmp_path, content)
        tools = _make_tools(tmp_path, suspicious=True, reason="injection detected")
        result = await tools._consolidate_memory_history(days_to_keep=7)
        assert "Error" in result
        print(f"[test] security block propagated: {result}")

    async def test_return_message_includes_consolidated_count(self, tmp_path: Path) -> None:
        content = f"## Entry {_old_date(30)}\n\nOld content."
        self._write_memory(tmp_path, content)
        tools = _make_tools(tmp_path)
        result = await tools._consolidate_memory_history(days_to_keep=7)
        assert "1" in result
        assert "consolidat" in result.lower()
        print(f"[test] return message: {result}")
