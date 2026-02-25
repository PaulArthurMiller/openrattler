"""Tests for AuditLog — append-only JSONL audit log with HMAC tamper detection."""

from __future__ import annotations

import asyncio
import json
from datetime import datetime, timezone
from pathlib import Path

import pytest

import openrattler.storage.audit as audit_module
from openrattler.models.audit import AuditEvent
from openrattler.storage.audit import AuditLog, audit_log, configure_default_log

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_HMAC_KEY = "test-secret-key"


def _event(name: str = "test_event", **kwargs: object) -> AuditEvent:
    return AuditEvent(event=name, **kwargs)  # type: ignore[arg-type]


# ---------------------------------------------------------------------------
# Log (basic append)
# ---------------------------------------------------------------------------


class TestLog:
    async def test_log_creates_file(self, tmp_path: Path) -> None:
        log = AuditLog(tmp_path / "audit.jsonl")
        await log.log(_event())
        assert (tmp_path / "audit.jsonl").exists()

    async def test_log_creates_parent_dirs(self, tmp_path: Path) -> None:
        log = AuditLog(tmp_path / "deep" / "nested" / "audit.jsonl")
        await log.log(_event())
        assert (tmp_path / "deep" / "nested" / "audit.jsonl").exists()

    async def test_log_single_event_writes_one_line(self, tmp_path: Path) -> None:
        log = AuditLog(tmp_path / "audit.jsonl")
        await log.log(_event("session_start"))
        lines = (tmp_path / "audit.jsonl").read_text(encoding="utf-8").splitlines()
        assert len(lines) == 1

    async def test_log_multiple_events_appends(self, tmp_path: Path) -> None:
        log = AuditLog(tmp_path / "audit.jsonl")
        for name in ("a", "b", "c"):
            await log.log(_event(name))
        lines = (tmp_path / "audit.jsonl").read_text(encoding="utf-8").splitlines()
        assert len(lines) == 3


# ---------------------------------------------------------------------------
# Query
# ---------------------------------------------------------------------------


class TestQuery:
    async def test_query_empty_log_returns_empty(self, tmp_path: Path) -> None:
        log = AuditLog(tmp_path / "audit.jsonl")
        await log.log(_event())
        # Clear and re-open (empty)
        (tmp_path / "audit.jsonl").write_text("")
        assert await log.query() == []

    async def test_query_nonexistent_log_returns_empty(self, tmp_path: Path) -> None:
        log = AuditLog(tmp_path / "nonexistent.jsonl")
        assert await log.query() == []

    async def test_query_no_filters_returns_all(self, tmp_path: Path) -> None:
        log = AuditLog(tmp_path / "audit.jsonl")
        for name in ("a", "b", "c"):
            await log.log(_event(name))
        results = await log.query(limit=100)
        assert len(results) == 3

    async def test_query_filter_event_type_matches(self, tmp_path: Path) -> None:
        log = AuditLog(tmp_path / "audit.jsonl")
        await log.log(_event("tool_call"))
        await log.log(_event("session_start"))
        await log.log(_event("tool_call"))
        results = await log.query(event_type="tool_call")
        assert len(results) == 2
        assert all(e.event == "tool_call" for e in results)

    async def test_query_filter_event_type_no_match_returns_empty(self, tmp_path: Path) -> None:
        log = AuditLog(tmp_path / "audit.jsonl")
        await log.log(_event("session_start"))
        assert await log.query(event_type="nonexistent") == []

    async def test_query_filter_session_key(self, tmp_path: Path) -> None:
        log = AuditLog(tmp_path / "audit.jsonl")
        await log.log(_event(session_key="agent:main:main"))
        await log.log(_event(session_key="agent:main:other"))
        results = await log.query(session_key="agent:main:main")
        assert len(results) == 1
        assert results[0].session_key == "agent:main:main"

    async def test_query_filter_trace_id(self, tmp_path: Path) -> None:
        log = AuditLog(tmp_path / "audit.jsonl")
        await log.log(_event(trace_id="trace-001"))
        await log.log(_event(trace_id="trace-002"))
        results = await log.query(trace_id="trace-001")
        assert len(results) == 1
        assert results[0].trace_id == "trace-001"

    async def test_query_filter_since(self, tmp_path: Path) -> None:
        log = AuditLog(tmp_path / "audit.jsonl")
        early = AuditEvent(
            event="early",
            timestamp=datetime(2020, 1, 1, tzinfo=timezone.utc),
        )
        late = AuditEvent(
            event="late",
            timestamp=datetime(2025, 1, 1, tzinfo=timezone.utc),
        )
        await log.log(early)
        await log.log(late)
        cutoff = datetime(2023, 1, 1, tzinfo=timezone.utc)
        results = await log.query(since=cutoff)
        assert len(results) == 1
        assert results[0].event == "late"

    async def test_query_limit_caps_results(self, tmp_path: Path) -> None:
        log = AuditLog(tmp_path / "audit.jsonl")
        for i in range(10):
            await log.log(_event(f"event_{i}"))
        results = await log.query(limit=3)
        assert len(results) == 3

    async def test_query_limit_returns_most_recent(self, tmp_path: Path) -> None:
        log = AuditLog(tmp_path / "audit.jsonl")
        for i in range(5):
            await log.log(_event(f"event_{i}"))
        results = await log.query(limit=2)
        assert results[0].event == "event_3"
        assert results[1].event == "event_4"

    async def test_query_combined_filters(self, tmp_path: Path) -> None:
        log = AuditLog(tmp_path / "audit.jsonl")
        await log.log(_event("tool_call", session_key="agent:main:main", trace_id="t1"))
        await log.log(_event("tool_call", session_key="agent:main:other", trace_id="t2"))
        await log.log(_event("session_start", session_key="agent:main:main", trace_id="t3"))
        results = await log.query(event_type="tool_call", session_key="agent:main:main")
        assert len(results) == 1
        assert results[0].trace_id == "t1"


# ---------------------------------------------------------------------------
# HMAC — unsigned log
# ---------------------------------------------------------------------------


class TestUnsignedLog:
    async def test_unsigned_log_line_has_no_hmac_field(self, tmp_path: Path) -> None:
        log = AuditLog(tmp_path / "audit.jsonl")
        await log.log(_event("test"))
        line = (tmp_path / "audit.jsonl").read_text(encoding="utf-8").strip()
        d = json.loads(line)
        assert "_hmac" not in d

    async def test_unsigned_verify_integrity_returns_true(self, tmp_path: Path) -> None:
        log = AuditLog(tmp_path / "audit.jsonl")
        for i in range(3):
            await log.log(_event(f"e{i}"))
        ok, bad = await log.verify_integrity()
        assert ok is True
        assert bad == []


# ---------------------------------------------------------------------------
# HMAC — signed log
# ---------------------------------------------------------------------------


class TestSignedLog:
    async def test_signed_log_line_has_hmac_field(self, tmp_path: Path) -> None:
        log = AuditLog(tmp_path / "audit.jsonl", hmac_key=_HMAC_KEY)
        await log.log(_event("test"))
        line = (tmp_path / "audit.jsonl").read_text(encoding="utf-8").strip()
        d = json.loads(line)
        assert "_hmac" in d
        assert isinstance(d["_hmac"], str) and len(d["_hmac"]) == 64

    async def test_signed_verify_integrity_passes_unmodified(self, tmp_path: Path) -> None:
        log = AuditLog(tmp_path / "audit.jsonl", hmac_key=_HMAC_KEY)
        for i in range(5):
            await log.log(_event(f"e{i}"))
        ok, bad = await log.verify_integrity()
        assert ok is True
        assert bad == []

    async def test_signed_verify_fails_on_tampered_line(self, tmp_path: Path) -> None:
        log_path = tmp_path / "audit.jsonl"
        log = AuditLog(log_path, hmac_key=_HMAC_KEY)
        await log.log(_event("original_event"))
        await log.log(_event("another_event"))

        # Tamper: change the event name in line 1
        text = log_path.read_text(encoding="utf-8")
        tampered = text.replace('"original_event"', '"tampered_event"', 1)
        log_path.write_text(tampered, encoding="utf-8")

        ok, bad = await log.verify_integrity()
        assert ok is False
        assert 1 in bad

    async def test_signed_verify_returns_correct_bad_line_numbers(self, tmp_path: Path) -> None:
        log_path = tmp_path / "audit.jsonl"
        log = AuditLog(log_path, hmac_key=_HMAC_KEY)
        for i in range(4):
            await log.log(_event(f"event_{i}"))

        # Tamper lines 1 and 3 (1-indexed)
        lines = log_path.read_text(encoding="utf-8").splitlines()
        d1 = json.loads(lines[0])
        d1["details"] = {"injected": True}
        lines[0] = json.dumps(d1, ensure_ascii=False)
        d3 = json.loads(lines[2])
        d3["agent_id"] = "attacker"
        lines[2] = json.dumps(d3, ensure_ascii=False)
        log_path.write_text("\n".join(lines) + "\n", encoding="utf-8")

        ok, bad = await log.verify_integrity()
        assert ok is False
        assert bad == [1, 3]

    async def test_query_strips_hmac_field(self, tmp_path: Path) -> None:
        log = AuditLog(tmp_path / "audit.jsonl", hmac_key=_HMAC_KEY)
        await log.log(_event("test_event"))
        results = await log.query()
        assert len(results) == 1
        # AuditEvent should not have _hmac as a field
        assert not hasattr(results[0], "_hmac")

    async def test_unsigned_line_in_signed_log_is_bad(self, tmp_path: Path) -> None:
        """A line without _hmac in a signed log is flagged as bad."""
        log_path = tmp_path / "audit.jsonl"
        log = AuditLog(log_path, hmac_key=_HMAC_KEY)
        await log.log(_event("signed_event"))

        # Inject an unsigned line directly
        with open(log_path, "a", encoding="utf-8") as fh:
            fh.write(AuditEvent(event="injected").model_dump_json() + "\n")

        ok, bad = await log.verify_integrity()
        assert ok is False
        assert 2 in bad


# ---------------------------------------------------------------------------
# Append-only guarantee
# ---------------------------------------------------------------------------


class TestAppendOnly:
    def test_no_delete_method(self) -> None:
        assert not hasattr(AuditLog, "delete")

    def test_no_clear_method(self) -> None:
        assert not hasattr(AuditLog, "clear")

    def test_no_modify_method(self) -> None:
        assert not hasattr(AuditLog, "modify")

    def test_no_truncate_method(self) -> None:
        assert not hasattr(AuditLog, "truncate")


# ---------------------------------------------------------------------------
# Convenience function: audit_log()
# ---------------------------------------------------------------------------


class TestAuditLogConvenienceFunction:
    async def test_no_op_if_no_log_configured(self) -> None:
        """audit_log() silently does nothing when no log is provided."""
        # Should not raise even with no default configured
        await audit_log("test_event")

    async def test_explicit_log_receives_event(self, tmp_path: Path) -> None:
        log = AuditLog(tmp_path / "audit.jsonl")
        await audit_log("tool_call", log=log)
        results = await log.query()
        assert len(results) == 1
        assert results[0].event == "tool_call"

    async def test_kwargs_become_details(self, tmp_path: Path) -> None:
        log = AuditLog(tmp_path / "audit.jsonl")
        await audit_log("tool_call", log=log, tool="file_read", result="ok")
        results = await log.query()
        assert results[0].details == {"tool": "file_read", "result": "ok"}

    async def test_optional_fields_passed_through(self, tmp_path: Path) -> None:
        log = AuditLog(tmp_path / "audit.jsonl")
        await audit_log(
            "session_start",
            log=log,
            session_key="agent:main:main",
            agent_id="main",
            trace_id="trace-xyz",
        )
        ev = (await log.query())[0]
        assert ev.session_key == "agent:main:main"
        assert ev.agent_id == "main"
        assert ev.trace_id == "trace-xyz"

    async def test_default_log_receives_event(self, tmp_path: Path) -> None:
        log = AuditLog(tmp_path / "audit.jsonl")
        original = audit_module._default_log
        try:
            configure_default_log(log)
            await audit_log("default_test")
            results = await log.query()
            assert len(results) == 1
            assert results[0].event == "default_test"
        finally:
            audit_module._default_log = original


# ---------------------------------------------------------------------------
# Concurrent appends
# ---------------------------------------------------------------------------


class TestConcurrentAppends:
    async def test_concurrent_appends_no_corruption(self, tmp_path: Path) -> None:
        """asyncio.gather fires all appends concurrently; the Lock serialises
        them so every event is written as a complete JSON line."""
        log = AuditLog(tmp_path / "audit.jsonl")
        n = 20
        events = [_event(f"concurrent_{i}") for i in range(n)]

        await asyncio.gather(*[log.log(e) for e in events])

        results = await log.query(limit=n)
        assert len(results) == n

        logged_names = {e.event for e in results}
        expected_names = {f"concurrent_{i}" for i in range(n)}
        assert logged_names == expected_names

    async def test_concurrent_signed_appends_all_valid(self, tmp_path: Path) -> None:
        """Concurrent signed writes must all verify cleanly."""
        log = AuditLog(tmp_path / "audit.jsonl", hmac_key=_HMAC_KEY)
        await asyncio.gather(*[log.log(_event(f"e{i}")) for i in range(10)])
        ok, bad = await log.verify_integrity()
        assert ok is True
        assert bad == []
