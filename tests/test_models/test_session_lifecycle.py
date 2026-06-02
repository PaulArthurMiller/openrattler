"""Tests for SessionLifecycleEvent model and infer_session_type helper."""

from __future__ import annotations

from datetime import datetime, timezone

import pytest

from openrattler.models.session_lifecycle import SessionLifecycleEvent, infer_session_type


class TestInferSessionType:
    def test_heartbeat_session_key(self) -> None:
        sk = "agent:main:heartbeat:hb_2026-01-01T00:00:00Z"
        assert infer_session_type(sk) == "heartbeat"

    def test_interactive_session_key(self) -> None:
        assert infer_session_type("agent:main:main") == "interactive"

    def test_research_session_key(self) -> None:
        assert infer_session_type("agent:research:abc123") == "subagent_research"

    def test_summarizer_session_key(self) -> None:
        assert infer_session_type("agent:summarizer:def456") == "subagent_research"

    def test_unknown_session_key(self) -> None:
        assert infer_session_type("agent:custom:whatever") == "subagent_other"

    def test_short_key_returns_other(self) -> None:
        assert infer_session_type("agent") == "subagent_other"

    def test_slack_session_key_returns_other(self) -> None:
        # Slack/email sessions are not subagents — but they also aren't the
        # other named types; they fall through to subagent_other.
        assert infer_session_type("agent:main:slack:xyz") == "subagent_other"

    def test_heartbeat_key_with_underscores(self) -> None:
        # Heartbeat keys replace dots with underscores for session-key safety.
        sk = "agent:main:heartbeat:hb_2026-01-01T00_00_00_000000Z"
        assert infer_session_type(sk) == "heartbeat"


class TestSessionLifecycleEvent:
    def _make_open(self, session_key: str = "agent:main:main") -> SessionLifecycleEvent:
        return SessionLifecycleEvent(
            event_type="open",
            session_key=session_key,
            session_type="interactive",
            timestamp=datetime.now(timezone.utc),
        )

    def _make_close(self, session_key: str = "agent:main:main") -> SessionLifecycleEvent:
        return SessionLifecycleEvent(
            event_type="close",
            session_key=session_key,
            session_type="interactive",
            timestamp=datetime.now(timezone.utc),
            close_reason="disconnect",
            duration_seconds=42.5,
            total_prompt_tokens=1000,
            total_completion_tokens=200,
        )

    def test_open_event_roundtrips(self) -> None:
        evt = self._make_open()
        data = evt.model_dump_json()
        restored = SessionLifecycleEvent.model_validate_json(data)
        assert restored.event_type == "open"
        assert restored.session_key == "agent:main:main"

    def test_close_event_carries_token_totals(self) -> None:
        evt = self._make_close()
        assert evt.total_prompt_tokens == 1000
        assert evt.total_completion_tokens == 200
        assert evt.duration_seconds == pytest.approx(42.5)

    def test_open_event_has_no_close_fields(self) -> None:
        evt = self._make_open()
        assert evt.close_reason is None
        assert evt.total_prompt_tokens is None
        assert evt.duration_seconds is None

    def test_parent_session_key_optional(self) -> None:
        evt = SessionLifecycleEvent(
            event_type="open",
            session_key="agent:research:abc",
            session_type="subagent_research",
            parent_session_key="agent:main:heartbeat:hb_x",
            timestamp=datetime.now(timezone.utc),
        )
        assert evt.parent_session_key == "agent:main:heartbeat:hb_x"

    def test_timestamp_is_datetime(self) -> None:
        evt = self._make_open()
        assert isinstance(evt.timestamp, datetime)

    def test_session_type_stored_as_given(self) -> None:
        evt = SessionLifecycleEvent(
            event_type="open",
            session_key="agent:main:heartbeat:hb_x",
            session_type="heartbeat",
            timestamp=datetime.now(timezone.utc),
        )
        assert evt.session_type == "heartbeat"
