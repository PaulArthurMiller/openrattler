"""Tests for TranscriptStore — JSONL session transcript storage."""

from __future__ import annotations

import asyncio
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from openrattler.models.messages import UniversalMessage, create_message
from openrattler.storage.transcripts import TranscriptStore, _key_to_path, _path_to_key

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_SESSION = "agent:main:main"
_GROUP_SESSION = "agent:main:telegram:group:123"


def _msg(operation: str = "user_message", text: str = "hello") -> UniversalMessage:
    return create_message(
        from_agent="channel:cli",
        to_agent="agent:main:main",
        session_key=_SESSION,
        type="request",
        operation=operation,
        trust_level="main",
        params={"text": text},
    )


# ---------------------------------------------------------------------------
# Path helpers (pure unit tests — no I/O)
# ---------------------------------------------------------------------------


class TestPathHelpers:
    def test_simple_key_to_path(self, tmp_path: Path) -> None:
        p = _key_to_path(tmp_path, "agent:main:main")
        assert p == tmp_path / "agent" / "main" / "main.jsonl"

    def test_long_key_to_path(self, tmp_path: Path) -> None:
        p = _key_to_path(tmp_path, "agent:main:telegram:group:123")
        assert p == tmp_path / "agent" / "main" / "telegram" / "group" / "123.jsonl"

    def test_round_trip_simple(self, tmp_path: Path) -> None:
        key = "agent:main:main"
        p = _key_to_path(tmp_path, key)
        assert _path_to_key(tmp_path, p) == key

    def test_round_trip_long(self, tmp_path: Path) -> None:
        key = "agent:main:telegram:group:123"
        p = _key_to_path(tmp_path, key)
        assert _path_to_key(tmp_path, p) == key


# ---------------------------------------------------------------------------
# Append + Load round-trip
# ---------------------------------------------------------------------------


class TestAppendLoad:
    async def test_append_creates_file(self, tmp_path: Path) -> None:
        store = TranscriptStore(tmp_path)
        await store.append(_SESSION, _msg())
        path = _key_to_path(tmp_path, _SESSION)
        assert path.exists()

    async def test_append_load_single_message(self, tmp_path: Path) -> None:
        store = TranscriptStore(tmp_path)
        msg = _msg(text="hi there")
        await store.append(_SESSION, msg)
        loaded = await store.load(_SESSION)
        assert len(loaded) == 1
        assert loaded[0].message_id == msg.message_id
        assert loaded[0].params["text"] == "hi there"

    async def test_append_load_three_messages(self, tmp_path: Path) -> None:
        store = TranscriptStore(tmp_path)
        msgs = [_msg(text=f"msg {i}") for i in range(3)]
        for m in msgs:
            await store.append(_SESSION, m)
        loaded = await store.load(_SESSION)
        assert len(loaded) == 3
        for original, restored in zip(msgs, loaded):
            assert restored.message_id == original.message_id
            assert restored.params == original.params

    async def test_order_preserved(self, tmp_path: Path) -> None:
        store = TranscriptStore(tmp_path)
        msgs = [_msg(text=str(i)) for i in range(5)]
        for m in msgs:
            await store.append(_SESSION, m)
        loaded = await store.load(_SESSION)
        for i, (orig, restored) in enumerate(zip(msgs, loaded)):
            assert restored.message_id == orig.message_id, f"Order wrong at index {i}"

    async def test_full_message_fields_preserved(self, tmp_path: Path) -> None:
        store = TranscriptStore(tmp_path)
        msg = create_message(
            from_agent="agent:main:main",
            to_agent="mcp:weather",
            session_key=_SESSION,
            type="request",
            operation="get_forecast",
            trust_level="main",
            channel="cli",
            params={"location": "Asheville"},
            metadata={"user_intent": "planning"},
            requires_approval=False,
            trace_id="trace-test-001",
        )
        await store.append(_SESSION, msg)
        loaded = await store.load(_SESSION)
        r = loaded[0]
        assert r.from_agent == msg.from_agent
        assert r.to_agent == msg.to_agent
        assert r.channel == msg.channel
        assert r.params == msg.params
        assert r.metadata == msg.metadata
        assert r.trace_id == msg.trace_id
        assert r.timestamp == msg.timestamp

    async def test_load_nonexistent_returns_empty(self, tmp_path: Path) -> None:
        store = TranscriptStore(tmp_path)
        result = await store.load("agent:main:main")
        assert result == []

    async def test_nested_session_key_creates_dirs(self, tmp_path: Path) -> None:
        store = TranscriptStore(tmp_path)
        await store.append(_GROUP_SESSION, _msg())
        expected = tmp_path / "agent" / "main" / "telegram" / "group" / "123.jsonl"
        assert expected.exists()


# ---------------------------------------------------------------------------
# load_recent
# ---------------------------------------------------------------------------


class TestLoadRecent:
    async def test_load_recent_returns_last_n(self, tmp_path: Path) -> None:
        store = TranscriptStore(tmp_path)
        msgs = [_msg(text=str(i)) for i in range(10)]
        for m in msgs:
            await store.append(_SESSION, m)
        recent = await store.load_recent(_SESSION, 3)
        assert len(recent) == 3
        # Should be the last 3 messages
        for orig, restored in zip(msgs[-3:], recent):
            assert restored.message_id == orig.message_id

    async def test_load_recent_more_than_available(self, tmp_path: Path) -> None:
        store = TranscriptStore(tmp_path)
        msgs = [_msg(text=str(i)) for i in range(3)]
        for m in msgs:
            await store.append(_SESSION, m)
        recent = await store.load_recent(_SESSION, 10)
        assert len(recent) == 3

    async def test_load_recent_zero_returns_empty(self, tmp_path: Path) -> None:
        store = TranscriptStore(tmp_path)
        await store.append(_SESSION, _msg())
        recent = await store.load_recent(_SESSION, 0)
        assert recent == []

    async def test_load_recent_nonexistent_returns_empty(self, tmp_path: Path) -> None:
        store = TranscriptStore(tmp_path)
        recent = await store.load_recent("agent:main:main", 5)
        assert recent == []

    async def test_load_recent_one(self, tmp_path: Path) -> None:
        store = TranscriptStore(tmp_path)
        msgs = [_msg(text=str(i)) for i in range(5)]
        for m in msgs:
            await store.append(_SESSION, m)
        recent = await store.load_recent(_SESSION, 1)
        assert len(recent) == 1
        assert recent[0].message_id == msgs[-1].message_id


# ---------------------------------------------------------------------------
# exists
# ---------------------------------------------------------------------------


class TestExists:
    async def test_exists_false_before_write(self, tmp_path: Path) -> None:
        store = TranscriptStore(tmp_path)
        assert not await store.exists(_SESSION)

    async def test_exists_true_after_write(self, tmp_path: Path) -> None:
        store = TranscriptStore(tmp_path)
        await store.append(_SESSION, _msg())
        assert await store.exists(_SESSION)

    async def test_exists_false_for_different_session(self, tmp_path: Path) -> None:
        store = TranscriptStore(tmp_path)
        await store.append(_SESSION, _msg())
        assert not await store.exists("agent:main:other")


# ---------------------------------------------------------------------------
# list_sessions
# ---------------------------------------------------------------------------


class TestListSessions:
    async def test_list_sessions_empty_base(self, tmp_path: Path) -> None:
        store = TranscriptStore(tmp_path)
        sessions = await store.list_sessions()
        assert sessions == []

    async def test_list_sessions_nonexistent_base(self, tmp_path: Path) -> None:
        store = TranscriptStore(tmp_path / "nonexistent")
        sessions = await store.list_sessions()
        assert sessions == []

    async def test_list_sessions_finds_all(self, tmp_path: Path) -> None:
        store = TranscriptStore(tmp_path)
        keys = ["agent:main:main", "agent:main:other", _GROUP_SESSION]
        for key in keys:
            msg = create_message(
                from_agent="channel:cli",
                to_agent=key.split(":")[1],
                session_key=key,
                type="request",
                operation="ping",
                trust_level="main",
            )
            await store.append(key, msg)
        sessions = await store.list_sessions()
        assert sorted(sessions) == sorted(keys)

    async def test_list_sessions_returns_sorted(self, tmp_path: Path) -> None:
        store = TranscriptStore(tmp_path)
        keys = ["agent:z:session", "agent:a:session", "agent:m:session"]
        for key in keys:
            msg = create_message(
                from_agent="channel:cli",
                to_agent="agent:main:main",
                session_key=key,
                type="event",
                operation="ping",
                trust_level="main",
            )
            await store.append(key, msg)
        sessions = await store.list_sessions()
        assert sessions == sorted(sessions)


# ---------------------------------------------------------------------------
# Path sanitization
# ---------------------------------------------------------------------------


class TestPathSanitization:
    async def _assert_rejected(self, store: TranscriptStore, key: str) -> None:
        with pytest.raises(ValueError):
            await store.append(key, _msg())

    async def test_path_traversal_rejected(self, tmp_path: Path) -> None:
        store = TranscriptStore(tmp_path)
        await self._assert_rejected(store, "agent:../../etc:passwd")

    async def test_double_dot_in_component_rejected(self, tmp_path: Path) -> None:
        store = TranscriptStore(tmp_path)
        await self._assert_rejected(store, "agent:main:..evil")

    async def test_absolute_path_slash_rejected(self, tmp_path: Path) -> None:
        store = TranscriptStore(tmp_path)
        await self._assert_rejected(store, "/agent:main:main")

    async def test_absolute_path_backslash_rejected(self, tmp_path: Path) -> None:
        store = TranscriptStore(tmp_path)
        await self._assert_rejected(store, "\\agent:main:main")

    async def test_missing_agent_prefix_rejected(self, tmp_path: Path) -> None:
        store = TranscriptStore(tmp_path)
        await self._assert_rejected(store, "user:main:main")

    async def test_special_chars_rejected(self, tmp_path: Path) -> None:
        store = TranscriptStore(tmp_path)
        await self._assert_rejected(store, "agent:main:m@in!")

    async def test_space_rejected(self, tmp_path: Path) -> None:
        store = TranscriptStore(tmp_path)
        await self._assert_rejected(store, "agent:main:my session")

    async def test_too_few_parts_rejected(self, tmp_path: Path) -> None:
        store = TranscriptStore(tmp_path)
        await self._assert_rejected(store, "agent:main")

    async def test_valid_key_with_hyphens_accepted(self, tmp_path: Path) -> None:
        store = TranscriptStore(tmp_path)
        key = "agent:main:subagent-abc-123"
        await store.append(key, _msg())
        assert await store.exists(key)

    async def test_valid_key_with_underscores_accepted(self, tmp_path: Path) -> None:
        store = TranscriptStore(tmp_path)
        key = "agent:work_agent:main"
        await store.append(key, _msg())
        assert await store.exists(key)

    async def test_sanitization_applies_to_load(self, tmp_path: Path) -> None:
        store = TranscriptStore(tmp_path)
        with pytest.raises(ValueError):
            await store.load("agent:../../etc:passwd")

    async def test_sanitization_applies_to_load_recent(self, tmp_path: Path) -> None:
        store = TranscriptStore(tmp_path)
        with pytest.raises(ValueError):
            await store.load_recent("agent:main:evil/../path", 5)

    async def test_sanitization_applies_to_exists(self, tmp_path: Path) -> None:
        store = TranscriptStore(tmp_path)
        with pytest.raises(ValueError):
            await store.exists("agent:main:evil/../path")


# ---------------------------------------------------------------------------
# Concurrent appends
# ---------------------------------------------------------------------------


# ---------------------------------------------------------------------------
# load_since
# ---------------------------------------------------------------------------


class TestLoadSince:
    """load_since(session_key, since_iso, max_turns) time-range filter."""

    def _msg_at(self, dt: datetime, text: str = "x") -> UniversalMessage:
        """Build a message with a specific timestamp (bypassing auto-timestamp)."""
        m = create_message(
            from_agent="channel:cli",
            to_agent="agent:main:main",
            session_key=_SESSION,
            type="request",
            operation="user_message",
            trust_level="main",
            params={"text": text},
        )
        # Override auto-generated timestamp
        return m.model_copy(update={"timestamp": dt})

    async def _store_messages_at(
        self,
        store: TranscriptStore,
        times: list[datetime],
        session: str = _SESSION,
    ) -> list[UniversalMessage]:
        """Append one message per timestamp; return the created messages."""
        msgs = [self._msg_at(t, text=t.isoformat()) for t in times]
        for m in msgs:
            # Bypass the store.append validation/lock to write the pre-stamped message.
            path = _key_to_path(store._base, session)
            path.parent.mkdir(parents=True, exist_ok=True)
            with open(path, "a", encoding="utf-8") as fh:
                fh.write(m.model_dump_json() + "\n")
        return msgs

    async def test_load_since_filters_old_messages(self, tmp_path: Path) -> None:
        """Messages before since_dt are excluded."""
        store = TranscriptStore(tmp_path)
        now = datetime.now(timezone.utc)
        times = [
            now - timedelta(hours=3),
            now - timedelta(hours=1),
            now,
        ]
        msgs = await self._store_messages_at(store, times)
        cutoff = (now - timedelta(hours=2)).isoformat()

        result = await store.load_since(_SESSION, cutoff)

        print(f"[load_since] got {len(result)} messages; expected 2")
        assert len(result) == 2
        assert result[0].message_id == msgs[1].message_id
        assert result[1].message_id == msgs[2].message_id

    async def test_load_since_applies_max_turns_cap(self, tmp_path: Path) -> None:
        """max_turns caps the result to the most recent N messages oldest-first."""
        store = TranscriptStore(tmp_path)
        now = datetime.now(timezone.utc)
        times = [now - timedelta(minutes=i) for i in reversed(range(10))]
        msgs = await self._store_messages_at(store, times)
        past = (now - timedelta(hours=1)).isoformat()

        result = await store.load_since(_SESSION, past, max_turns=3)

        print(f"[load_since] capped to {len(result)} of 10 messages")
        assert len(result) == 3
        # Should be the 3 most recent, oldest-first
        assert result[0].message_id == msgs[-3].message_id
        assert result[-1].message_id == msgs[-1].message_id

    async def test_load_since_future_cutoff_returns_empty(self, tmp_path: Path) -> None:
        """A since_iso in the future returns an empty list."""
        store = TranscriptStore(tmp_path)
        now = datetime.now(timezone.utc)
        await self._store_messages_at(store, [now - timedelta(minutes=5)])
        future = (now + timedelta(hours=1)).isoformat()

        result = await store.load_since(_SESSION, future)

        print(f"[load_since] future cutoff → {len(result)} messages")
        assert result == []

    async def test_load_since_nonexistent_session_returns_empty(self, tmp_path: Path) -> None:
        """Non-existent session → empty list, no exception."""
        store = TranscriptStore(tmp_path)
        cutoff = datetime.now(timezone.utc).isoformat()
        result = await store.load_since("agent:main:ghost", cutoff)
        assert result == []
        print("[load_since] non-existent session returned []")

    async def test_load_since_invalid_iso_raises_value_error(self, tmp_path: Path) -> None:
        """An unparseable since_iso raises ValueError."""
        store = TranscriptStore(tmp_path)
        with pytest.raises(ValueError, match="ISO 8601"):
            await store.load_since(_SESSION, "not-a-date")

    async def test_load_since_result_is_oldest_first(self, tmp_path: Path) -> None:
        """Returned messages are in ascending timestamp order (oldest first)."""
        store = TranscriptStore(tmp_path)
        now = datetime.now(timezone.utc)
        times = [now - timedelta(minutes=2), now - timedelta(minutes=1), now]
        msgs = await self._store_messages_at(store, times)
        cutoff = (now - timedelta(hours=1)).isoformat()

        result = await store.load_since(_SESSION, cutoff)

        timestamps = [m.timestamp for m in result]
        print(f"[load_since] timestamps: {timestamps}")
        assert timestamps == sorted(timestamps)
        assert result[0].message_id == msgs[0].message_id
        assert result[-1].message_id == msgs[-1].message_id

    async def test_load_since_naive_since_iso_treated_as_utc(self, tmp_path: Path) -> None:
        """Naive since_iso (no timezone) is treated as UTC, not rejected."""
        store = TranscriptStore(tmp_path)
        now = datetime.now(timezone.utc)
        await self._store_messages_at(store, [now])
        # Naive ISO string — no tz info
        naive_cutoff = (now - timedelta(minutes=1)).strftime("%Y-%m-%dT%H:%M:%S")

        result = await store.load_since(_SESSION, naive_cutoff)

        print(f"[load_since] naive cutoff: {naive_cutoff} → {len(result)} messages")
        assert len(result) == 1

    async def test_load_since_invalid_session_key_raises(self, tmp_path: Path) -> None:
        """Invalid session_key raises ValueError before any file I/O."""
        store = TranscriptStore(tmp_path)
        cutoff = datetime.now(timezone.utc).isoformat()
        with pytest.raises(ValueError):
            await store.load_since("agent:main:evil/../path", cutoff)


class TestConcurrentAppends:
    async def test_concurrent_appends_no_corruption(self, tmp_path: Path) -> None:
        """asyncio.gather fires all appends concurrently; the per-session lock
        serialises them so every message is written as a complete JSON line."""
        store = TranscriptStore(tmp_path)
        n = 20
        msgs = [_msg(text=f"concurrent-{i}") for i in range(n)]

        await asyncio.gather(*[store.append(_SESSION, m) for m in msgs])

        loaded = await store.load(_SESSION)
        assert len(loaded) == n, f"Expected {n} messages, got {len(loaded)}"

        # Every message ID must appear exactly once (no duplication or loss)
        loaded_ids = {m.message_id for m in loaded}
        expected_ids = {m.message_id for m in msgs}
        assert loaded_ids == expected_ids

    async def test_concurrent_appends_to_different_sessions(self, tmp_path: Path) -> None:
        """Different session keys use independent locks — no cross-session interference."""
        store = TranscriptStore(tmp_path)
        sessions = [f"agent:main:session-{i}" for i in range(5)]
        msgs_per_session = 10

        tasks = [
            store.append(sk, _msg(text=f"{sk}-msg-{j}"))
            for sk in sessions
            for j in range(msgs_per_session)
        ]
        await asyncio.gather(*tasks)

        for sk in sessions:
            loaded = await store.load(sk)
            assert (
                len(loaded) == msgs_per_session
            ), f"Session {sk}: expected {msgs_per_session} messages, got {len(loaded)}"
