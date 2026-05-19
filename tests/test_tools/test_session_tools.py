"""Tests for the built-in session tools: sessions_history, session_read_self, session_lookup."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from openrattler.models.agents import AgentConfig, TrustLevel
from openrattler.models.audit import AuditEvent
from openrattler.models.messages import create_message
from openrattler.storage.audit import AuditLog
from openrattler.storage.transcripts import TranscriptStore
from openrattler.tools.builtin.session_tools import (
    configure_audit_log,
    configure_summarizer_agent,
    configure_transcript_store,
    session_lookup,
    session_read_self,
    sessions_history,
)

# ---------------------------------------------------------------------------
# Fixtures and helpers
# ---------------------------------------------------------------------------

_SESSION = "agent:main:main"
_HEARTBEAT_SESSION = "agent:main:heartbeat:abc123"


def _msg(content: str, session_key: str = _SESSION) -> object:
    return create_message(
        from_agent="main",
        to_agent="main",
        session_key=session_key,
        type="request",
        operation="chat",
        trust_level="main",
        params={"content": content},
    )


def _make_agent_config(session_key: str = _SESSION) -> AgentConfig:
    return AgentConfig(
        agent_id=session_key,
        name="test-agent",
        description="test",
        model="anthropic/claude-haiku-4-5",
        trust_level=TrustLevel.main,
        session_key=session_key,
    )


def _recent_iso() -> str:
    """Return an ISO timestamp from 1 hour ago."""
    return (datetime.now(timezone.utc) - timedelta(hours=1)).isoformat()


def _old_iso() -> str:
    """Return an ISO timestamp from 80 hours ago (beyond the 72h CalibrationAgent window)."""
    return (datetime.now(timezone.utc) - timedelta(hours=80)).isoformat()


@pytest.fixture(autouse=True)
def reset_session_store() -> object:
    """Reset all module-level session tool state after each test."""
    yield
    configure_transcript_store(None)
    configure_summarizer_agent(None)
    configure_audit_log(None)


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


class TestSessionsHistory:
    async def test_returns_messages_as_list_of_dicts(self, tmp_path: Path) -> None:
        store = TranscriptStore(tmp_path)
        configure_transcript_store(store)
        await store.append(_SESSION, _msg("hello"))  # type: ignore[arg-type]
        result = await sessions_history(_SESSION)
        assert isinstance(result, list)
        assert len(result) == 1
        assert isinstance(result[0], dict)

    async def test_message_dict_has_expected_fields(self, tmp_path: Path) -> None:
        store = TranscriptStore(tmp_path)
        configure_transcript_store(store)
        await store.append(_SESSION, _msg("ping"))  # type: ignore[arg-type]
        result = await sessions_history(_SESSION)
        entry = result[0]
        assert "message_id" in entry
        assert "session_key" in entry
        assert entry["session_key"] == _SESSION

    async def test_respects_n_limit(self, tmp_path: Path) -> None:
        store = TranscriptStore(tmp_path)
        configure_transcript_store(store)
        for i in range(5):
            await store.append(_SESSION, _msg(f"msg{i}"))  # type: ignore[arg-type]
        result = await sessions_history(_SESSION, n=3)
        assert len(result) == 3

    async def test_default_n_is_ten(self, tmp_path: Path) -> None:
        store = TranscriptStore(tmp_path)
        configure_transcript_store(store)
        for i in range(15):
            await store.append(_SESSION, _msg(f"msg{i}"))  # type: ignore[arg-type]
        result = await sessions_history(_SESSION)
        assert len(result) == 10

    async def test_returns_most_recent_messages(self, tmp_path: Path) -> None:
        store = TranscriptStore(tmp_path)
        configure_transcript_store(store)
        for i in range(5):
            await store.append(_SESSION, _msg(f"msg{i}"))  # type: ignore[arg-type]
        result = await sessions_history(_SESSION, n=2)
        # load_recent returns the last n, so we should get msg3 and msg4
        params_list = [entry["params"]["content"] for entry in result]
        assert "msg3" in params_list
        assert "msg4" in params_list

    async def test_raises_when_store_not_configured(self) -> None:
        # No configure_transcript_store call — default is None.
        with pytest.raises(RuntimeError, match="TranscriptStore not configured"):
            await sessions_history(_SESSION)

    async def test_empty_session_returns_empty_list(self, tmp_path: Path) -> None:
        store = TranscriptStore(tmp_path)
        configure_transcript_store(store)
        result = await sessions_history(_SESSION)
        assert result == []

    async def test_invalid_session_key_raises(self, tmp_path: Path) -> None:
        store = TranscriptStore(tmp_path)
        configure_transcript_store(store)
        with pytest.raises(ValueError):
            await sessions_history("not-a-valid-key")

    def test_tool_definition_attached(self) -> None:
        assert hasattr(sessions_history, "_tool_definition")
        assert sessions_history._tool_definition.name == "sessions_history"  # type: ignore[attr-defined]

    def test_tool_requires_approval(self) -> None:
        assert sessions_history._tool_definition.requires_approval is True  # type: ignore[attr-defined]


# ---------------------------------------------------------------------------
# TestSessionReadSelf
# ---------------------------------------------------------------------------


class TestSessionReadSelf:
    """Tests for the session_read_self tool (Piece 42.3)."""

    async def test_uses_agent_config_session_key_not_caller_supplied(self, tmp_path: Path) -> None:
        """session_read_self reads the caller's own session, not an LLM-supplied key."""
        store = TranscriptStore(tmp_path)
        configure_transcript_store(store)
        agent_cfg = _make_agent_config(_SESSION)
        await store.append(_SESSION, _msg("hello"))  # type: ignore[arg-type]
        result = await session_read_self(
            since_iso=_recent_iso(),
            summarize=False,
            agent_config=agent_cfg,
        )
        assert result["session_key"] == _SESSION
        assert result["turn_count"] == 1
        print(f"[OK] session_key from agent_config: {result['session_key']}")

    async def test_summarize_false_returns_raw_messages(self, tmp_path: Path) -> None:
        """summarize=False returns the raw messages list, not a summary."""
        store = TranscriptStore(tmp_path)
        configure_transcript_store(store)
        agent_cfg = _make_agent_config(_SESSION)
        await store.append(_SESSION, _msg("alpha"))  # type: ignore[arg-type]
        await store.append(_SESSION, _msg("beta"))  # type: ignore[arg-type]
        result = await session_read_self(
            since_iso=_recent_iso(),
            summarize=False,
            agent_config=agent_cfg,
        )
        assert result["summarized"] is False
        assert "messages" in result
        assert isinstance(result["messages"], list)
        assert result["turn_count"] == 2
        print(f"[OK] raw messages returned: {len(result['messages'])} items")

    async def test_summarize_true_returns_summary_via_summarizer_agent(
        self, tmp_path: Path
    ) -> None:
        """summarize=True invokes SummarizerAgent and returns summary dict."""
        from openrattler.agents.summarizer.agent import SummarizerAgent
        from openrattler.agents.summarizer.config import SummarizerAgentConfig
        from openrattler.storage.audit import AuditLog

        store = TranscriptStore(tmp_path)
        audit = AuditLog(tmp_path / "audit.jsonl")
        configure_transcript_store(store)
        configure_audit_log(audit)

        # No provider → stub fallback (first 1000 chars of input)
        summarizer = SummarizerAgent(config=SummarizerAgentConfig(), audit=audit)
        configure_summarizer_agent(summarizer)

        agent_cfg = _make_agent_config(_SESSION)
        await store.append(_SESSION, _msg("summarize me"))  # type: ignore[arg-type]

        result = await session_read_self(
            since_iso=_recent_iso(),
            summarize=True,
            agent_config=agent_cfg,
        )
        assert result["summarized"] is True
        assert "summary" in result
        assert isinstance(result["summary"], str)
        print(f"[OK] summary returned, length={len(result['summary'])}")

    async def test_empty_session_returns_turn_count_zero_not_error(self, tmp_path: Path) -> None:
        """Empty transcript window returns turn_count=0, not an error."""
        store = TranscriptStore(tmp_path)
        configure_transcript_store(store)
        agent_cfg = _make_agent_config(_SESSION)
        result = await session_read_self(
            since_iso=_recent_iso(),
            summarize=False,
            agent_config=agent_cfg,
        )
        assert result["turn_count"] == 0
        assert "error" not in result
        print("[OK] empty session returns turn_count=0, no error")

    async def test_session_read_self_writes_audit_event(self, tmp_path: Path) -> None:
        """session_read_self writes a session_read_own audit event."""
        store = TranscriptStore(tmp_path)
        audit = AuditLog(tmp_path / "audit.jsonl")
        configure_transcript_store(store)
        configure_audit_log(audit)
        agent_cfg = _make_agent_config(_SESSION)
        await store.append(_SESSION, _msg("audited"))  # type: ignore[arg-type]

        await session_read_self(
            since_iso=_recent_iso(),
            summarize=False,
            agent_config=agent_cfg,
        )
        events = await audit.query(limit=20)
        event_names = [e.event for e in events]
        assert "session_read_own" in event_names
        own_event = next(e for e in events if e.event == "session_read_own")
        assert own_event.details is not None
        assert "turn_count" in own_event.details
        print(f"[OK] audit event written: {own_event.event}, details={own_event.details}")


# ---------------------------------------------------------------------------
# TestSessionLookup
# ---------------------------------------------------------------------------


class TestSessionLookup:
    """Tests for the session_lookup tool (Piece 42.3)."""

    async def test_calibration_agent_can_read_main_session(self, tmp_path: Path) -> None:
        """CalibrationAgent caller + session_key=agent:main:main → succeeds."""
        store = TranscriptStore(tmp_path)
        configure_transcript_store(store)
        await store.append(_SESSION, _msg("main msg"))  # type: ignore[arg-type]
        calibration_cfg = _make_agent_config(_HEARTBEAT_SESSION)
        result = await session_lookup(
            session_key=_SESSION,
            since_iso=_recent_iso(),
            summarize=False,
            agent_config=calibration_cfg,
        )
        assert "error" not in result
        assert result["session_key"] == _SESSION
        print(f"[OK] CalibrationAgent read main session: turn_count={result['turn_count']}")

    async def test_calibration_agent_blocked_from_other_session(self, tmp_path: Path) -> None:
        """CalibrationAgent caller + non-main session_key → scope violation error."""
        other_session = "agent:main:other"
        store = TranscriptStore(tmp_path)
        configure_transcript_store(store)
        calibration_cfg = _make_agent_config(_HEARTBEAT_SESSION)
        result = await session_lookup(
            session_key=other_session,
            since_iso=_recent_iso(),
            summarize=False,
            agent_config=calibration_cfg,
        )
        assert "error" in result
        assert "agent:main:main" in result["error"]
        print(f"[OK] CalibrationAgent blocked from {other_session}: {result['error']}")

    async def test_calibration_agent_blocked_by_72h_window(self, tmp_path: Path) -> None:
        """CalibrationAgent caller + since_iso older than 72h → time window error."""
        store = TranscriptStore(tmp_path)
        configure_transcript_store(store)
        calibration_cfg = _make_agent_config(_HEARTBEAT_SESSION)
        result = await session_lookup(
            session_key=_SESSION,
            since_iso=_old_iso(),
            summarize=False,
            agent_config=calibration_cfg,
        )
        assert "error" in result
        assert "72h" in result["error"]
        print(f"[OK] CalibrationAgent blocked by 72h window: {result['error']}")

    async def test_audit_entry_contains_required_fields(self, tmp_path: Path) -> None:
        """session_lookup audit entry contains requester, target, since_iso, turn_count."""
        store = TranscriptStore(tmp_path)
        audit = AuditLog(tmp_path / "audit.jsonl")
        configure_transcript_store(store)
        configure_audit_log(audit)
        await store.append(_SESSION, _msg("lookup msg"))  # type: ignore[arg-type]
        agent_cfg = _make_agent_config("agent:main:worker")
        iso = _recent_iso()

        await session_lookup(
            session_key=_SESSION,
            since_iso=iso,
            summarize=False,
            agent_config=agent_cfg,
        )
        events = await audit.query(limit=20)
        lookup_events = [e for e in events if e.event == "session_lookup_read"]
        assert lookup_events, "Expected a session_lookup_read audit event"
        ev = lookup_events[0]
        assert ev.details is not None
        assert "requester_session_key" in ev.details
        assert "target_session_key" in ev.details
        assert "since_iso" in ev.details
        assert "turn_count" in ev.details
        assert ev.details["target_session_key"] == _SESSION
        print(f"[OK] audit entry fields: {list(ev.details.keys())}")

    async def test_scope_violation_writes_audit_event(self, tmp_path: Path) -> None:
        """Scope violations are always written to the audit log."""
        store = TranscriptStore(tmp_path)
        audit = AuditLog(tmp_path / "audit.jsonl")
        configure_transcript_store(store)
        configure_audit_log(audit)
        calibration_cfg = _make_agent_config(_HEARTBEAT_SESSION)

        await session_lookup(
            session_key="agent:main:other",
            since_iso=_recent_iso(),
            summarize=False,
            agent_config=calibration_cfg,
        )
        events = await audit.query(limit=20)
        violation_events = [e for e in events if e.event == "session_lookup_scope_violation"]
        assert violation_events, "Expected a session_lookup_scope_violation audit event"
        print(f"[OK] scope violation audit event written: {violation_events[0].details}")

    async def test_summarize_true_returns_summary(self, tmp_path: Path) -> None:
        """session_lookup with summarize=True returns summary from SummarizerAgent."""
        from openrattler.agents.summarizer.agent import SummarizerAgent
        from openrattler.agents.summarizer.config import SummarizerAgentConfig

        store = TranscriptStore(tmp_path)
        audit = AuditLog(tmp_path / "audit.jsonl")
        configure_transcript_store(store)
        configure_audit_log(audit)
        summarizer = SummarizerAgent(config=SummarizerAgentConfig(), audit=audit)
        configure_summarizer_agent(summarizer)

        await store.append(_SESSION, _msg("lookup summary"))  # type: ignore[arg-type]
        agent_cfg = _make_agent_config("agent:main:worker")

        result = await session_lookup(
            session_key=_SESSION,
            since_iso=_recent_iso(),
            summarize=True,
            agent_config=agent_cfg,
        )
        assert result["summarized"] is True
        assert "summary" in result
        print(f"[OK] session_lookup summary returned, len={len(result['summary'])}")

    async def test_sessions_history_still_works_regression(self, tmp_path: Path) -> None:
        """Regression: sessions_history continues to function after 42.3 changes."""
        store = TranscriptStore(tmp_path)
        configure_transcript_store(store)
        await store.append(_SESSION, _msg("legacy"))  # type: ignore[arg-type]
        result = await sessions_history(_SESSION, n=5)
        assert isinstance(result, list)
        assert len(result) == 1
        assert result[0]["params"]["content"] == "legacy"
        print("[OK] sessions_history regression: still returns correct data")
