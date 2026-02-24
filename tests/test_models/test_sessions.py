"""Tests for SessionKey, Session, and Peer models."""

from __future__ import annotations

from datetime import datetime, timezone

import pytest
from pydantic import ValidationError

from openrattler.models.messages import UniversalMessage, create_message
from openrattler.models.sessions import Peer, Session, SessionKey

# ---------------------------------------------------------------------------
# SessionKey validation
# ---------------------------------------------------------------------------


class TestSessionKeyValid:
    def test_standard_dm_key(self) -> None:
        key: SessionKey = "agent:main:main"
        assert key == "agent:main:main"

    def test_group_key(self) -> None:
        key: SessionKey = "agent:main:telegram:group:123"
        assert "group" in key

    def test_thread_key(self) -> None:
        key: SessionKey = "agent:main:main:thread:abc"
        assert "thread" in key

    def test_subagent_key(self) -> None:
        key: SessionKey = "agent:main:subagent:abc-123"
        assert "subagent" in key

    def test_hyphen_and_underscore_allowed(self) -> None:
        key: SessionKey = "agent:work_main:group-1"
        assert key == "agent:work_main:group-1"


class TestSessionKeyInvalid:
    def _bad_key(self, key: str) -> None:
        """Helper: assert a key fails validation inside a Pydantic model."""

        class _M(Session.__bases__[0]):  # type: ignore[name-defined]
            pass

        with pytest.raises((ValueError, ValidationError)):
            from pydantic import TypeAdapter

            ta: TypeAdapter[SessionKey] = TypeAdapter(SessionKey)
            ta.validate_python(key)

    def _validate(self, key: str) -> None:
        from pydantic import TypeAdapter

        ta: TypeAdapter[SessionKey] = TypeAdapter(SessionKey)
        ta.validate_python(key)

    def test_path_traversal_rejected(self) -> None:
        with pytest.raises((ValueError, ValidationError)):
            self._validate("agent:main:../../etc/passwd")

    def test_absolute_path_rejected(self) -> None:
        with pytest.raises((ValueError, ValidationError)):
            self._validate("/agent:main:main")

    def test_missing_agent_prefix_rejected(self) -> None:
        with pytest.raises((ValueError, ValidationError)):
            self._validate("user:main:main")

    def test_too_few_parts_rejected(self) -> None:
        with pytest.raises((ValueError, ValidationError)):
            self._validate("agent:main")

    def test_special_characters_rejected(self) -> None:
        with pytest.raises((ValueError, ValidationError)):
            self._validate("agent:main:m@in!")

    def test_space_rejected(self) -> None:
        with pytest.raises((ValueError, ValidationError)):
            self._validate("agent:main:my session")

    def test_non_string_rejected(self) -> None:
        with pytest.raises((ValueError, ValidationError)):
            from pydantic import TypeAdapter

            ta: TypeAdapter[SessionKey] = TypeAdapter(SessionKey)
            ta.validate_python(123)  # type: ignore[arg-type]


class TestSessionKeyInSession:
    """Validate that Session.key enforces SessionKey rules."""

    def test_session_accepts_valid_key(self) -> None:
        s = Session(key="agent:main:main", agent_id="main")
        assert s.key == "agent:main:main"

    def test_session_rejects_bad_key(self) -> None:
        with pytest.raises(ValidationError):
            Session(key="../../evil", agent_id="main")

    def test_session_rejects_missing_prefix(self) -> None:
        with pytest.raises(ValidationError):
            Session(key="user:main:ctx", agent_id="main")


# ---------------------------------------------------------------------------
# Session model
# ---------------------------------------------------------------------------


class TestSession:
    def _msg(self) -> UniversalMessage:
        return create_message(
            from_agent="agent:main:main",
            to_agent="mcp:weather",
            session_key="agent:main:main",
            type="request",
            operation="get_forecast",
            trust_level="main",
        )

    def test_session_defaults(self) -> None:
        s = Session(key="agent:main:main", agent_id="main")
        assert s.history == []
        assert isinstance(s.created_at, datetime)
        assert isinstance(s.updated_at, datetime)

    def test_session_timestamps_are_utc(self) -> None:
        s = Session(key="agent:main:main", agent_id="main")
        assert s.created_at.tzinfo == timezone.utc
        assert s.updated_at.tzinfo == timezone.utc

    def test_session_history_stores_messages(self) -> None:
        msg = self._msg()
        s = Session(key="agent:main:main", agent_id="main", history=[msg])
        assert len(s.history) == 1
        assert s.history[0].message_id == msg.message_id

    def test_session_round_trip(self) -> None:
        msg = self._msg()
        s = Session(key="agent:main:main", agent_id="main", history=[msg])
        data = s.model_dump()
        restored = Session.model_validate(data)
        assert restored.key == s.key
        assert len(restored.history) == 1


# ---------------------------------------------------------------------------
# Peer model
# ---------------------------------------------------------------------------


class TestPeer:
    def test_dm_peer(self) -> None:
        p = Peer(kind="dm", id="user-42")
        assert p.kind == "dm"
        assert p.id == "user-42"
        assert p.parent is None

    def test_group_peer(self) -> None:
        p = Peer(kind="group", id="channel-123")
        assert p.kind == "group"

    def test_thread_peer_with_parent(self) -> None:
        parent = Peer(kind="group", id="channel-123")
        thread = Peer(kind="thread", id="thread-456", parent=parent)
        assert thread.parent is not None
        assert thread.parent.id == "channel-123"

    def test_invalid_kind_rejected(self) -> None:
        with pytest.raises(ValidationError):
            Peer(kind="unknown", id="x")  # type: ignore[arg-type]

    def test_all_kinds_valid(self) -> None:
        for kind in ("dm", "group", "thread"):
            p = Peer(kind=kind, id="test-id")  # type: ignore[arg-type]
            assert p.kind == kind

    def test_nested_peer_round_trip(self) -> None:
        grandparent = Peer(kind="group", id="g-1")
        parent = Peer(kind="thread", id="t-1", parent=grandparent)
        child = Peer(kind="thread", id="t-2", parent=parent)
        data = child.model_dump()
        restored = Peer.model_validate(data)
        assert restored.parent is not None
        assert restored.parent.parent is not None
        assert restored.parent.parent.id == "g-1"
