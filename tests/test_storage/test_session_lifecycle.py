"""Tests for SessionLifecycleStore."""

from __future__ import annotations

import asyncio
from pathlib import Path

import pytest

from openrattler.storage.session_lifecycle import SessionLifecycleStore


@pytest.fixture
def store(tmp_path: Path) -> SessionLifecycleStore:
    return SessionLifecycleStore(tmp_path / "usage" / "session_lifecycle.jsonl")


class TestEmitOpen:
    async def test_creates_file_on_first_write(self, store: SessionLifecycleStore) -> None:
        await store.emit_open("agent:main:main", "interactive")
        assert store._path.exists()

    async def test_open_event_readable_back(self, store: SessionLifecycleStore) -> None:
        await store.emit_open("agent:main:main", "interactive")
        evt = await store.get_open_event("agent:main:main")
        assert evt is not None
        assert evt.event_type == "open"
        assert evt.session_type == "interactive"

    async def test_infers_session_type_when_not_provided(
        self, store: SessionLifecycleStore
    ) -> None:
        await store.emit_open("agent:main:heartbeat:hb_x")
        evt = await store.get_open_event("agent:main:heartbeat:hb_x")
        assert evt is not None
        assert evt.session_type == "heartbeat"

    async def test_parent_session_key_stored(self, store: SessionLifecycleStore) -> None:
        await store.emit_open(
            "agent:research:abc",
            "subagent_research",
            parent_session_key="agent:main:heartbeat:hb_x",
        )
        evt = await store.get_open_event("agent:research:abc")
        assert evt is not None
        assert evt.parent_session_key == "agent:main:heartbeat:hb_x"


class TestEmitClose:
    async def test_close_event_with_tokens(self, store: SessionLifecycleStore) -> None:
        await store.emit_open("agent:main:main", "interactive")
        await store.emit_close(
            "agent:main:main",
            "disconnect",
            total_prompt_tokens=500,
            total_completion_tokens=100,
        )
        evt = await store.get_close_event("agent:main:main")
        assert evt is not None
        assert evt.event_type == "close"
        assert evt.close_reason == "disconnect"
        assert evt.total_prompt_tokens == 500
        assert evt.total_completion_tokens == 100

    async def test_duration_computed_from_open(self, store: SessionLifecycleStore) -> None:
        await store.emit_open("agent:main:main", "interactive")
        # A tiny sleep so duration > 0 (even microseconds).
        await asyncio.sleep(0.001)
        await store.emit_close("agent:main:main", "completed")
        evt = await store.get_close_event("agent:main:main")
        assert evt is not None
        assert evt.duration_seconds is not None
        assert evt.duration_seconds >= 0.0

    async def test_close_without_prior_open_still_writes(
        self, store: SessionLifecycleStore
    ) -> None:
        await store.emit_close("orphan:session:key", "error")
        evt = await store.get_close_event("orphan:session:key")
        assert evt is not None
        assert evt.duration_seconds is None  # no open event to compute from

    async def test_close_inherits_session_type_from_open(
        self, store: SessionLifecycleStore
    ) -> None:
        await store.emit_open("agent:research:x", "subagent_research")
        await store.emit_close("agent:research:x", "completed")
        evt = await store.get_close_event("agent:research:x")
        assert evt is not None
        assert evt.session_type == "subagent_research"


class TestGetEvents:
    async def test_get_open_returns_none_for_missing_session(
        self, store: SessionLifecycleStore
    ) -> None:
        result = await store.get_open_event("no:such:session")
        assert result is None

    async def test_get_close_returns_none_for_missing_session(
        self, store: SessionLifecycleStore
    ) -> None:
        result = await store.get_close_event("no:such:session")
        assert result is None

    async def test_multiple_sessions_isolated(self, store: SessionLifecycleStore) -> None:
        await store.emit_open("session:a", "interactive")
        await store.emit_open("session:b", "heartbeat")
        await store.emit_close("session:a", "disconnect")

        evt_a = await store.get_close_event("session:a")
        evt_b = await store.get_close_event("session:b")
        assert evt_a is not None
        assert evt_b is None

    async def test_returns_most_recent_open(self, store: SessionLifecycleStore) -> None:
        # Two opens for the same key (e.g. a reused key across restarts).
        await store.emit_open("agent:main:main", "interactive")
        await asyncio.sleep(0.001)
        await store.emit_open("agent:main:main", "interactive")
        evt = await store.get_open_event("agent:main:main")
        assert evt is not None
        # get_open_event should return the last (most recent) open.
        events_raw = await store._load_events_for_session("agent:main:main")
        opens = [e for e in events_raw if e.event_type == "open"]
        assert evt.timestamp == opens[-1].timestamp

    async def test_file_missing_returns_no_events(self, store: SessionLifecycleStore) -> None:
        result = await store.get_open_event("agent:main:main")
        assert result is None

    async def test_idempotent_directory_creation(self, store: SessionLifecycleStore) -> None:
        await store.emit_open("session:a", "interactive")
        await store.emit_open("session:b", "interactive")
        assert store._path.exists()
