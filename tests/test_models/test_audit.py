"""Tests for AuditEvent model."""

from __future__ import annotations

from datetime import datetime, timezone

import pytest
from pydantic import ValidationError

from openrattler.models.audit import AuditEvent


class TestAuditEvent:
    def test_minimal_event(self) -> None:
        ev = AuditEvent(event="tool_call")
        assert ev.event == "tool_call"
        assert ev.session_key is None
        assert ev.agent_id is None
        assert ev.details == {}
        assert ev.trace_id is None

    def test_timestamp_is_utc_aware(self) -> None:
        ev = AuditEvent(event="permission_check")
        assert ev.timestamp.tzinfo is not None
        assert ev.timestamp.tzinfo == timezone.utc

    def test_full_event(self) -> None:
        ev = AuditEvent(
            event="tool_call",
            session_key="agent:main:main",
            agent_id="agent:main:main",
            details={"tool": "file_read", "path": "notes.txt", "result": "allowed"},
            trace_id="trace-abc-123",
        )
        assert ev.session_key == "agent:main:main"
        assert ev.details["tool"] == "file_read"
        assert ev.trace_id == "trace-abc-123"

    def test_missing_event_raises(self) -> None:
        with pytest.raises(ValidationError):
            AuditEvent()  # type: ignore[call-arg]

    def test_explicit_timestamp(self) -> None:
        ts = datetime(2026, 1, 15, 12, 0, 0, tzinfo=timezone.utc)
        ev = AuditEvent(event="approval_requested", timestamp=ts)
        assert ev.timestamp == ts

    def test_details_can_hold_nested_data(self) -> None:
        ev = AuditEvent(
            event="memory_update",
            details={
                "diff": {"added": {"user_name": "Paul"}, "removed": {}, "modified": {}},
                "approved_by": "security_agent",
            },
        )
        assert ev.details["diff"]["added"]["user_name"] == "Paul"

    def test_round_trip(self) -> None:
        ev = AuditEvent(
            event="tool_call",
            session_key="agent:main:main",
            agent_id="agent:main:main",
            details={"tool": "web_search"},
            trace_id="trace-rt-001",
        )
        data = ev.model_dump()
        restored = AuditEvent.model_validate(data)
        assert restored == ev

    def test_json_round_trip(self) -> None:
        ev = AuditEvent(
            event="agent_spawned",
            trace_id="trace-json-001",
            details={"template": "research", "depth": 1},
        )
        restored = AuditEvent.model_validate_json(ev.model_dump_json())
        assert restored.event == "agent_spawned"
        assert restored.trace_id == "trace-json-001"
        assert restored.timestamp == ev.timestamp

    def test_various_event_names(self) -> None:
        event_names = [
            "tool_call",
            "permission_denied",
            "approval_requested",
            "approval_resolved",
            "memory_update",
            "agent_spawned",
            "agent_killed",
            "session_accessed",
            "rate_limit_exceeded",
        ]
        for name in event_names:
            ev = AuditEvent(event=name)
            assert ev.event == name
