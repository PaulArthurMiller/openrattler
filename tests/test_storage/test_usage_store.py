"""Tests for UsageStore and the infer_channel_and_agent helper."""

from __future__ import annotations

import asyncio
from datetime import datetime, timezone, timedelta
from pathlib import Path

import pytest

from openrattler.models.usage import TurnRecord, infer_channel_and_agent
from openrattler.storage.usage import UsageStore

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_BASE_RECORD = {
    "session_key": "agent:main:slack:abc123",
    "agent_type": "main",
    "channel": "slack",
    "model": "claude-sonnet-4-6",
    "prompt_tokens": 1000,
    "completion_tokens": 200,
    "total_tokens": 1200,
    "estimated_cost_usd": 0.012,
    "llm_calls": 1,
    "tool_calls": [],
    "tool_loops": 0,
}


def _make_store(tmp_path: Path) -> UsageStore:
    return UsageStore(tmp_path / "usage" / "usage_log.jsonl")


def _rec(**overrides: object) -> dict:  # type: ignore[type-arg]
    return {**_BASE_RECORD, **overrides}


# ---------------------------------------------------------------------------
# infer_channel_and_agent
# ---------------------------------------------------------------------------


class TestInferChannelAndAgent:
    def test_heartbeat(self) -> None:
        assert infer_channel_and_agent("agent:main:heartbeat:xyz") == ("heartbeat", "heartbeat")

    def test_slack(self) -> None:
        assert infer_channel_and_agent("agent:main:slack:abc") == ("slack", "main")

    def test_email(self) -> None:
        assert infer_channel_and_agent("agent:main:email:def") == ("email", "main")

    def test_cli(self) -> None:
        assert infer_channel_and_agent("agent:main:main") == ("cli", "main")

    def test_research(self) -> None:
        assert infer_channel_and_agent("agent:research:trace123456") == ("research", "research")

    def test_summarizer(self) -> None:
        assert infer_channel_and_agent("agent:summarizer:abc") == ("summarizer", "summarizer")

    def test_unknown_prefix(self) -> None:
        assert infer_channel_and_agent("something:else:here") == ("unknown", "unknown")

    def test_too_short(self) -> None:
        assert infer_channel_and_agent("agent:main") == ("unknown", "unknown")

    def test_completely_unknown(self) -> None:
        assert infer_channel_and_agent("agent:other:channel:key") == ("unknown", "unknown")


# ---------------------------------------------------------------------------
# UsageStore.record_turn — writes parseable JSONL
# ---------------------------------------------------------------------------


class TestRecordTurn:
    def test_writes_parseable_jsonl(self, tmp_path: Path) -> None:
        store = _make_store(tmp_path)
        asyncio.run(store.record_turn(_rec()))
        lines = store._path.read_text(encoding="utf-8").strip().splitlines()
        assert len(lines) == 1
        record = TurnRecord.model_validate_json(lines[0])
        assert record.session_key == "agent:main:slack:abc123"
        print(f"Written turn_number={record.turn_number}, model={record.model}")

    def test_creates_parent_directory(self, tmp_path: Path) -> None:
        store = _make_store(tmp_path)
        assert not store._path.exists()
        asyncio.run(store.record_turn(_rec()))
        assert store._path.exists()

    def test_recorded_at_is_utc(self, tmp_path: Path) -> None:
        store = _make_store(tmp_path)
        asyncio.run(store.record_turn(_rec()))
        lines = store._path.read_text(encoding="utf-8").strip().splitlines()
        record = TurnRecord.model_validate_json(lines[0])
        assert record.recorded_at.tzinfo is not None
        print(f"recorded_at={record.recorded_at}")

    def test_tool_calls_and_loops_stored(self, tmp_path: Path) -> None:
        store = _make_store(tmp_path)
        asyncio.run(
            store.record_turn(
                _rec(
                    tool_calls=["calendar_list_events", "memory_read"],
                    tool_loops=1,
                    llm_calls=2,
                )
            )
        )
        lines = store._path.read_text(encoding="utf-8").strip().splitlines()
        record = TurnRecord.model_validate_json(lines[0])
        assert record.tool_calls == ["calendar_list_events", "memory_read"]
        assert record.tool_loops == 1
        assert record.llm_calls == 2


# ---------------------------------------------------------------------------
# turn_number assignment
# ---------------------------------------------------------------------------


class TestTurnNumberAssignment:
    def test_first_turn_is_one(self, tmp_path: Path) -> None:
        store = _make_store(tmp_path)
        asyncio.run(store.record_turn(_rec()))
        lines = store._path.read_text(encoding="utf-8").strip().splitlines()
        record = TurnRecord.model_validate_json(lines[0])
        assert record.turn_number == 1
        print(f"turn_number={record.turn_number}")

    def test_turn_number_increments(self, tmp_path: Path) -> None:
        store = _make_store(tmp_path)

        async def _run() -> None:
            await store.record_turn(_rec())
            await store.record_turn(_rec())
            await store.record_turn(_rec())

        asyncio.run(_run())
        lines = store._path.read_text(encoding="utf-8").strip().splitlines()
        turn_numbers = [TurnRecord.model_validate_json(l).turn_number for l in lines]
        assert turn_numbers == [1, 2, 3]
        print(f"turn_numbers={turn_numbers}")

    def test_turn_numbers_independent_per_session(self, tmp_path: Path) -> None:
        store = _make_store(tmp_path)
        session_a = "agent:main:slack:aaa"
        session_b = "agent:main:email:bbb"

        async def _run() -> None:
            await store.record_turn(_rec(session_key=session_a))
            await store.record_turn(_rec(session_key=session_b))
            await store.record_turn(_rec(session_key=session_a))

        asyncio.run(_run())
        lines = store._path.read_text(encoding="utf-8").strip().splitlines()
        records = [TurnRecord.model_validate_json(l) for l in lines]
        a_turns = [r.turn_number for r in records if r.session_key == session_a]
        b_turns = [r.turn_number for r in records if r.session_key == session_b]
        assert a_turns == [1, 2]
        assert b_turns == [1]
        print(f"session_a turns={a_turns}, session_b turns={b_turns}")


# ---------------------------------------------------------------------------
# load_since
# ---------------------------------------------------------------------------


class TestLoadSince:
    def _write_record(self, store: UsageStore, delta_seconds: int) -> None:
        """Write a record and immediately patch its recorded_at to a known time."""
        asyncio.run(store.record_turn(_rec()))
        # Patch the last written record's timestamp by rewriting the file.
        # This is test-only manipulation to control recorded_at precisely.
        lines = store._path.read_text(encoding="utf-8").strip().splitlines()
        import json

        records = [json.loads(l) for l in lines]
        now = datetime.now(timezone.utc)
        records[-1]["recorded_at"] = (now + timedelta(seconds=delta_seconds)).isoformat()
        store._path.write_text(
            "\n".join(json.dumps(r) for r in records) + "\n",
            encoding="utf-8",
        )

    def test_filters_records_by_since(self, tmp_path: Path) -> None:
        store = _make_store(tmp_path)
        self._write_record(store, -120)  # 2 min ago
        self._write_record(store, -60)  # 1 min ago
        self._write_record(store, 0)  # now

        since = datetime.now(timezone.utc) - timedelta(seconds=90)
        results = asyncio.run(store.load_since(since))
        assert len(results) == 2
        print(f"load_since returned {len(results)} records")

    def test_excludes_older_records(self, tmp_path: Path) -> None:
        store = _make_store(tmp_path)
        self._write_record(store, -200)
        self._write_record(store, -100)

        since = datetime.now(timezone.utc) - timedelta(seconds=50)
        results = asyncio.run(store.load_since(since))
        assert len(results) == 0

    def test_includes_record_at_exact_cutoff(self, tmp_path: Path) -> None:
        store = _make_store(tmp_path)
        import json

        asyncio.run(store.record_turn(_rec()))
        # Patch recorded_at to exactly the cutoff we'll use.
        cutoff = datetime(2026, 1, 1, 12, 0, 0, tzinfo=timezone.utc)
        lines = store._path.read_text(encoding="utf-8").strip().splitlines()
        records = [json.loads(l) for l in lines]
        records[0]["recorded_at"] = cutoff.isoformat()
        store._path.write_text("\n".join(json.dumps(r) for r in records) + "\n", encoding="utf-8")
        results = asyncio.run(store.load_since(cutoff))
        assert len(results) == 1

    def test_caps_to_max_records(self, tmp_path: Path) -> None:
        store = _make_store(tmp_path)
        for _ in range(5):
            self._write_record(store, 0)

        since = datetime.now(timezone.utc) - timedelta(hours=1)
        results = asyncio.run(store.load_since(since, max_records=3))
        assert len(results) == 3

    def test_nonexistent_file_returns_empty(self, tmp_path: Path) -> None:
        store = _make_store(tmp_path)
        since = datetime.now(timezone.utc) - timedelta(hours=24)
        results = asyncio.run(store.load_since(since))
        assert results == []
        print("load_since on missing file returned []")

    def test_naive_since_treated_as_utc(self, tmp_path: Path) -> None:
        store = _make_store(tmp_path)
        self._write_record(store, 0)  # now
        since_naive = datetime.now()  # no tzinfo
        results = asyncio.run(store.load_since(since_naive))
        # Should not raise; whether it returns the record depends on timing — just verify no crash.
        assert isinstance(results, list)


# ---------------------------------------------------------------------------
# count_for_session
# ---------------------------------------------------------------------------


class TestCountForSession:
    def test_zero_for_new_session(self, tmp_path: Path) -> None:
        store = _make_store(tmp_path)
        count = asyncio.run(store.count_for_session("agent:main:slack:new"))
        assert count == 0

    def test_counts_correctly(self, tmp_path: Path) -> None:
        store = _make_store(tmp_path)
        key = "agent:main:slack:abc123"

        async def _run() -> None:
            await store.record_turn(_rec(session_key=key))
            await store.record_turn(_rec(session_key=key))

        asyncio.run(_run())
        count = asyncio.run(store.count_for_session(key))
        assert count == 2

    def test_nonexistent_file_returns_zero(self, tmp_path: Path) -> None:
        store = _make_store(tmp_path)
        count = asyncio.run(store.count_for_session("agent:main:slack:xyz"))
        assert count == 0
