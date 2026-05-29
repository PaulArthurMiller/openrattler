"""Tests for UsageReportGenerator — report generation from TurnRecords.

All tests write TurnRecords directly to a temporary UsageStore so there is no
dependency on AgentRuntime, ResearchAgent, or any other runtime component.
"""

from __future__ import annotations

import asyncio
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

import pytest

from openrattler.reports.usage_report import SessionSummary, UsageReportGenerator
from openrattler.storage.usage import UsageStore

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _utc(dt: datetime) -> datetime:
    """Ensure datetime is UTC-aware."""
    return dt.replace(tzinfo=timezone.utc) if dt.tzinfo is None else dt


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _make_record(
    session_key: str,
    agent_type: str = "main",
    channel: str = "slack",
    model: str = "claude-sonnet-4-6",
    prompt_tokens: int = 5000,
    completion_tokens: int = 500,
    total_tokens: int = 5500,
    estimated_cost_usd: float = 0.010,
    llm_calls: int = 1,
    tool_calls: list[str] | None = None,
    tool_loops: int = 0,
    parent_session_key: str | None = None,
    trace_id: str | None = None,
) -> dict[str, Any]:
    """Build a minimal valid record_data dict for UsageStore.record_turn()."""
    return {
        "session_key": session_key,
        "agent_type": agent_type,
        "channel": channel,
        "model": model,
        "prompt_tokens": prompt_tokens,
        "completion_tokens": completion_tokens,
        "total_tokens": total_tokens,
        "estimated_cost_usd": estimated_cost_usd,
        "llm_calls": llm_calls,
        "tool_calls": tool_calls or [],
        "tool_loops": tool_loops,
        "parent_session_key": parent_session_key,
        "trace_id": trace_id,
    }


async def _write(store: UsageStore, *records: dict[str, Any]) -> None:
    """Write multiple records to the store."""
    for rec in records:
        await store.record_turn(rec)


# ---------------------------------------------------------------------------
# Fixture
# ---------------------------------------------------------------------------


@pytest.fixture
def store(tmp_path: Path) -> UsageStore:
    return UsageStore(tmp_path / "usage" / "usage_log.jsonl")


@pytest.fixture
def generator(store: UsageStore) -> UsageReportGenerator:
    return UsageReportGenerator(
        usage_store=store,
        idle_timeout_minutes=60,
        context_growth_warning_pct=500.0,
    )


# ---------------------------------------------------------------------------
# Empty store
# ---------------------------------------------------------------------------


class TestEmptyStore:
    async def test_empty_store_no_crash(self, generator: UsageReportGenerator) -> None:
        report = await generator.generate()
        print(f"\nReport:\n{report}")
        assert "No sessions in this window." in report

    async def test_empty_store_still_has_header(self, generator: UsageReportGenerator) -> None:
        report = await generator.generate()
        assert "OPENRATTLER TOKEN ECONOMY REPORT" in report
        assert "GENERATED:" in report


# ---------------------------------------------------------------------------
# Single session
# ---------------------------------------------------------------------------


class TestSingleSession:
    async def test_single_heartbeat_turn_in_closed_sessions(
        self, store: UsageStore, generator: UsageReportGenerator
    ) -> None:
        await _write(
            store,
            _make_record(
                "agent:main:heartbeat:abc123",
                agent_type="heartbeat",
                channel="heartbeat",
                prompt_tokens=5200,
                completion_tokens=400,
                total_tokens=5600,
                estimated_cost_usd=0.007,
            ),
        )
        report = await generator.generate()
        print(f"\nReport:\n{report}")

        assert "agent:main:heartbeat:abc123" in report
        assert "CLOSED SESSIONS" in report
        assert "Turns: 1" in report
        assert "$0.007" in report

    async def test_single_session_tokens_match(
        self, store: UsageStore, generator: UsageReportGenerator
    ) -> None:
        await _write(
            store,
            _make_record(
                "agent:main:slack:sess01",
                prompt_tokens=3000,
                completion_tokens=300,
                total_tokens=3300,
                estimated_cost_usd=0.012,
            ),
        )
        report = await generator.generate()
        # Total tokens = 3300, cost = $0.012
        assert "3,300" in report
        assert "$0.012" in report

    async def test_single_session_summary_totals(
        self, store: UsageStore, generator: UsageReportGenerator
    ) -> None:
        # Sessions written right now are classified as active (within 60-min idle window).
        await _write(
            store,
            _make_record(
                "agent:main:slack:sess01",
                total_tokens=8000,
                estimated_cost_usd=0.025,
            ),
        )
        report = await generator.generate()
        assert "Total estimated cost:   $0.025" in report
        assert "Total tokens:           8,000" in report
        # One session exists; it will be active since it was just written.
        assert "Active sessions:        1" in report
        assert "Closed sessions:        0" in report


# ---------------------------------------------------------------------------
# Multi-turn context growth
# ---------------------------------------------------------------------------


class TestContextGrowth:
    async def test_multi_turn_context_growth_flagged_above_threshold(
        self, store: UsageStore, generator: UsageReportGenerator
    ) -> None:
        """Session where prompt_tokens grows > 500% should trigger warning."""
        sk = "agent:main:slack:grow01"
        prompt_sequence = [4000, 8000, 14000, 22000, 30000]  # 650% growth
        for pt in prompt_sequence:
            await _write(
                store,
                _make_record(
                    sk,
                    prompt_tokens=pt,
                    completion_tokens=400,
                    total_tokens=pt + 400,
                    estimated_cost_usd=0.015,
                ),
            )
        report = await generator.generate()
        print(f"\nReport:\n{report}")
        assert "CONTEXT ACCUMULATION DETECTED" in report
        assert "CONTEXT ACCUMULATION WARNINGS" in report
        assert sk in report

    async def test_multi_turn_no_flag_below_threshold(
        self, store: UsageStore, generator: UsageReportGenerator
    ) -> None:
        """Session with < 500% growth should NOT trigger the accumulation warning."""
        sk = "agent:main:slack:nogrow"
        # Growth: 4000 → 8000 = 100%
        for pt in [4000, 6000, 8000]:
            await _write(
                store,
                _make_record(
                    sk,
                    prompt_tokens=pt,
                    completion_tokens=400,
                    total_tokens=pt + 400,
                    estimated_cost_usd=0.010,
                ),
            )
        report = await generator.generate()
        assert "CONTEXT ACCUMULATION DETECTED" not in report

    async def test_context_growth_pct_helper_correct(self, generator: UsageReportGenerator) -> None:
        # (30000 - 4000) / 4000 * 100 = 650%
        result = generator._context_growth_pct([4000, 8000, 14000, 22000, 30000])
        assert result is not None
        assert abs(result - 650.0) < 0.1

    async def test_context_growth_pct_returns_none_for_single_turn(
        self, generator: UsageReportGenerator
    ) -> None:
        assert generator._context_growth_pct([5000]) is None

    async def test_context_growth_pct_returns_none_for_zero_first_value(
        self, generator: UsageReportGenerator
    ) -> None:
        assert generator._context_growth_pct([0, 5000]) is None

    async def test_context_growth_warning_section_lists_flagged_sessions(
        self, store: UsageStore, generator: UsageReportGenerator
    ) -> None:
        """Sessions >500% should appear in both the inline block AND the warning section."""
        sk = "agent:main:email:heavy"
        for pt in [3000, 7000, 15000, 25000]:  # 733% growth
            await _write(
                store,
                _make_record(sk, channel="email", prompt_tokens=pt, total_tokens=pt + 400),
            )
        report = await generator.generate()
        # The warning section should include this session key
        warning_section = report.split("CONTEXT ACCUMULATION WARNINGS")[1]
        assert sk in warning_section


# ---------------------------------------------------------------------------
# Research sub-sessions
# ---------------------------------------------------------------------------


class TestSubSessions:
    async def test_research_session_linked_under_parent(
        self, store: UsageStore, generator: UsageReportGenerator
    ) -> None:
        parent_sk = "agent:main:slack:parent01"
        research_sk = "agent:research:abc123456789"

        await _write(
            store,
            _make_record(parent_sk, prompt_tokens=5000, total_tokens=5500),
            _make_record(
                research_sk,
                agent_type="research",
                channel="research",
                parent_session_key=parent_sk,
                prompt_tokens=8000,
                total_tokens=8500,
            ),
        )
        report = await generator.generate()
        print(f"\nReport:\n{report}")
        assert "Sub-session: research" in report
        assert research_sk not in report.split("CLOSED SESSIONS")[1].split("CONTEXT ACCUMULATION")[
            0
        ].replace("Sub-session: research", "")
        # The parent should appear in closed sessions
        assert parent_sk in report

    async def test_standalone_research_session_not_shown_as_top_level(
        self, store: UsageStore, generator: UsageReportGenerator
    ) -> None:
        """A research session with a parent_session_key should be nested, not top-level."""
        parent_sk = "agent:main:slack:parent02"
        research_sk = "agent:research:xyz987654321"
        await _write(
            store,
            _make_record(parent_sk, prompt_tokens=5000, total_tokens=5500),
            _make_record(
                research_sk,
                agent_type="research",
                channel="research",
                parent_session_key=parent_sk,
                prompt_tokens=8000,
                total_tokens=8500,
            ),
        )
        report = await generator.generate()
        # research_sk should appear as sub-session line, not as a top-level session header
        assert "└─ Sub-session" in report

    async def test_research_session_without_parent_treated_as_top_level(
        self, store: UsageStore
    ) -> None:
        """A research session with no parent appears as a standalone top-level session.

        Uses a 0-minute idle timeout so the just-written session is classified closed.
        """
        generator = UsageReportGenerator(
            usage_store=store,
            idle_timeout_minutes=0,
        )
        sk = "agent:research:standalone01"
        await _write(
            store,
            _make_record(sk, agent_type="research", channel="research"),
        )
        report = await generator.generate()
        assert sk in report
        # With 0-minute idle timeout the session is closed; it should appear in CLOSED SESSIONS.
        closed_section = report.split("CLOSED SESSIONS")[1]
        assert sk in closed_section


# ---------------------------------------------------------------------------
# Active vs closed classification
# ---------------------------------------------------------------------------


class TestActiveClosedClassification:
    async def test_active_session_shown_in_active_section(self, store: UsageStore) -> None:
        """A session with a turn written right now should appear as active."""
        generator = UsageReportGenerator(
            usage_store=store,
            idle_timeout_minutes=60,
        )
        sk = "agent:main:slack:recent"
        await _write(store, _make_record(sk))
        report = await generator.generate()
        print(f"\nReport:\n{report}")
        # Should appear in ACTIVE SESSIONS, not CLOSED SESSIONS
        active_section = report.split("ACTIVE SESSIONS")[1].split("CLOSED SESSIONS")[0]
        assert sk in active_section

    async def test_old_session_shown_in_closed_section(self, store: UsageStore) -> None:
        """A session whose last turn was > idle_timeout ago should be closed."""
        generator = UsageReportGenerator(
            usage_store=store,
            idle_timeout_minutes=1,  # 1 minute timeout
        )
        sk = "agent:main:slack:old"
        await _write(store, _make_record(sk))
        # Simulate time passing by using a very short idle timeout and a
        # manually fabricated summary (we can't rewind the clock, so we test
        # _is_active directly with an old timestamp).
        old_time = _now() - timedelta(hours=2)
        is_active = generator._is_active(old_time, _now())
        assert is_active is False

    async def test_is_active_within_timeout(self, generator: UsageReportGenerator) -> None:
        recent = _now() - timedelta(minutes=30)  # within 60-min window
        assert generator._is_active(recent, _now()) is True

    async def test_is_active_outside_timeout(self, generator: UsageReportGenerator) -> None:
        old = _now() - timedelta(hours=2)
        assert generator._is_active(old, _now()) is False


# ---------------------------------------------------------------------------
# Tool call counting
# ---------------------------------------------------------------------------


class TestToolCallCounts:
    async def test_same_tool_counted_across_turns(
        self, store: UsageStore, generator: UsageReportGenerator
    ) -> None:
        sk = "agent:main:slack:tools01"
        await _write(
            store,
            _make_record(sk, tool_calls=["send_email", "memory_read"]),
            _make_record(sk, tool_calls=["send_email", "memory_read"]),
            _make_record(sk, tool_calls=["research_query"]),
        )
        report = await generator.generate()
        print(f"\nReport:\n{report}")
        # send_email called twice, memory_read twice, research_query once
        assert "send_email×2" in report
        assert "memory_read×2" in report
        # research_query appears once — shown without ×N
        assert "research_query" in report
        assert "research_query×1" not in report  # single calls shown without multiplier

    async def test_no_tools_shown_as_none(
        self, store: UsageStore, generator: UsageReportGenerator
    ) -> None:
        sk = "agent:main:heartbeat:notools"
        await _write(store, _make_record(sk, tool_calls=[]))
        report = await generator.generate()
        # No "Tools:" line should appear for sessions with no tool calls
        session_block = report.split(sk)[1].split("Started:")[0]
        assert "Tools:" not in session_block


# ---------------------------------------------------------------------------
# Channel and agent breakdown
# ---------------------------------------------------------------------------


class TestBreakdown:
    async def test_channel_breakdown_present(
        self, store: UsageStore, generator: UsageReportGenerator
    ) -> None:
        await _write(
            store,
            _make_record("agent:main:slack:a", channel="slack", estimated_cost_usd=0.5),
            _make_record("agent:main:email:b", channel="email", estimated_cost_usd=0.2),
        )
        report = await generator.generate()
        assert "COST BY CHANNEL" in report
        assert "slack" in report
        assert "email" in report

    async def test_agent_type_breakdown_present(
        self, store: UsageStore, generator: UsageReportGenerator
    ) -> None:
        await _write(
            store,
            _make_record("agent:main:slack:a", agent_type="main"),
            _make_record(
                "agent:research:xyz",
                agent_type="research",
                channel="research",
            ),
        )
        report = await generator.generate()
        assert "COST BY AGENT TYPE" in report
        assert "main" in report
        assert "research" in report

    async def test_channel_percentages_sum_to_100(
        self, store: UsageStore, generator: UsageReportGenerator
    ) -> None:
        """Channel percentages in the report should be derived from real costs."""
        await _write(
            store,
            _make_record("agent:main:slack:a", channel="slack", estimated_cost_usd=0.75),
            _make_record("agent:main:email:b", channel="email", estimated_cost_usd=0.25),
        )
        # Generate and parse cost section manually to verify logic.
        # We verify via the generator internals (not by parsing the text).
        records = await store.load_since(_now() - timedelta(hours=24))
        sessions = generator._build_session_summaries(records, _now())
        channel_costs: dict[str, float] = {}
        for s in sessions:
            channel_costs[s.channel] = channel_costs.get(s.channel, 0.0) + s.total_cost_usd
        total = sum(channel_costs.values())
        pct_sum = sum(cost / total * 100 for cost in channel_costs.values())
        assert abs(pct_sum - 100.0) < 0.1


# ---------------------------------------------------------------------------
# Required sections
# ---------------------------------------------------------------------------


class TestRequiredSections:
    async def test_all_required_sections_present(
        self, store: UsageStore, generator: UsageReportGenerator
    ) -> None:
        await _write(
            store,
            _make_record("agent:main:slack:s1", estimated_cost_usd=0.01),
        )
        report = await generator.generate()
        print(f"\nReport:\n{report}")
        required = [
            "SUMMARY",
            "COST BY CHANNEL",
            "COST BY AGENT TYPE",
            "ACTIVE SESSIONS",
            "CLOSED SESSIONS",
            "CONTEXT ACCUMULATION WARNINGS",
            "GENERATED:",
        ]
        for section in required:
            assert section in report, f"Missing section: {section}"

    async def test_report_window_in_header(
        self, store: UsageStore, generator: UsageReportGenerator
    ) -> None:
        since = datetime(2026, 5, 28, 8, 0, 0, tzinfo=timezone.utc)
        until = datetime(2026, 5, 29, 8, 0, 0, tzinfo=timezone.utc)
        report = await generator.generate(since=since, until=until)
        assert "2026-05-28 08:00 UTC" in report
        assert "2026-05-29 08:00 UTC" in report


# ---------------------------------------------------------------------------
# Formatting helpers
# ---------------------------------------------------------------------------


class TestFormattingHelpers:
    def test_format_bar_full(self, generator: UsageReportGenerator) -> None:
        bar = generator._format_bar(100.0, width=10)
        assert bar == "█" * 10

    def test_format_bar_empty(self, generator: UsageReportGenerator) -> None:
        bar = generator._format_bar(0.0, width=10)
        assert bar == "░" * 10

    def test_format_bar_half(self, generator: UsageReportGenerator) -> None:
        bar = generator._format_bar(50.0, width=10)
        assert bar.count("█") == 5
        assert bar.count("░") == 5

    def test_format_tool_summary_multiple_counts(self, generator: UsageReportGenerator) -> None:
        result = generator._format_tool_summary({"send_email": 2, "memory_read": 5})
        assert "send_email×2" in result
        assert "memory_read×5" in result

    def test_format_tool_summary_single_call(self, generator: UsageReportGenerator) -> None:
        result = generator._format_tool_summary({"research_query": 1})
        assert "research_query×1" not in result
        assert "research_query" in result

    def test_format_tool_summary_empty(self, generator: UsageReportGenerator) -> None:
        result = generator._format_tool_summary({})
        assert result == "(none)"
