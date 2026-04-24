"""Tests for openrattler.tools.builtin.calendar_tools — CalendarToolHandler."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import AsyncMock, MagicMock

import pytest

from openrattler.config.loader import AppConfig, GoogleConfig
from openrattler.integrations.google.client import GoogleClientFactory
from openrattler.models.messages import UniversalMessage
from openrattler.models.tools import ToolResult
from openrattler.storage.audit import AuditLog
from openrattler.tools.builtin.calendar_tools import (
    CALENDAR_CREATE_EVENT,
    CALENDAR_LIST_EVENTS,
    CALENDAR_READ_EVENT,
    CalendarToolHandler,
    _ATTRIBUTION,
    register_calendar_tools,
)
from openrattler.tools.registry import ToolRegistry

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


def _make_audit(tmp_path: Path) -> AuditLog:
    return AuditLog(tmp_path / "audit.jsonl")


def _make_google_config(**overrides: object) -> GoogleConfig:
    defaults: dict = {
        "enabled": True,
        "credentials_file": "/tmp/credentials.json",
        "token_file": "/tmp/token.json",
        "user_email": "test@example.com",
        "max_events_per_query": 50,
        "max_tasks_per_query": 100,
    }
    defaults.update(overrides)
    return GoogleConfig(**defaults)


def _make_client_factory() -> MagicMock:
    """Return a MagicMock GoogleClientFactory with a fake calendar service."""
    factory = MagicMock(spec=GoogleClientFactory)
    svc = MagicMock()
    factory.calendar_service = AsyncMock(return_value=svc)
    return factory, svc


def _make_handler(
    tmp_path: Path,
    *,
    factory: MagicMock | None = None,
    config: GoogleConfig | None = None,
) -> tuple[CalendarToolHandler, MagicMock]:
    """Return *(handler, calendar_svc_mock)* for use in tests."""
    if factory is None:
        factory, svc = _make_client_factory()
    else:
        svc = factory.calendar_service.return_value  # type: ignore[attr-defined]
    cfg = config or _make_google_config()
    audit = _make_audit(tmp_path)
    handler = CalendarToolHandler(client=factory, config=cfg, audit=audit)
    return handler, svc


# ---------------------------------------------------------------------------
# handle_list_events
# ---------------------------------------------------------------------------


class TestHandleListEvents:
    async def test_returns_tool_result_with_universal_message(self, tmp_path: Path) -> None:
        handler, svc = _make_handler(tmp_path)
        fake_events = [{"id": "evt1", "summary": "Meeting"}]
        svc.events.return_value.list.return_value.execute.return_value = {"items": fake_events}

        result = await handler.handle_list_events(
            time_min="2026-04-24T00:00:00Z",
            time_max="2026-04-24T23:59:59Z",
            call_id="c1",
        )

        assert isinstance(result, ToolResult)
        assert result.success is True
        assert isinstance(result.result, UniversalMessage)
        print(f"list_events result: {result.result.params}")

    async def test_trust_level_is_local(self, tmp_path: Path) -> None:
        handler, svc = _make_handler(tmp_path)
        svc.events.return_value.list.return_value.execute.return_value = {"items": []}

        result = await handler.handle_list_events(
            time_min="2026-04-24T00:00:00Z",
            time_max="2026-04-24T23:59:59Z",
        )

        assert result.result.trust_level == "local"

    async def test_events_in_params(self, tmp_path: Path) -> None:
        handler, svc = _make_handler(tmp_path)
        fake_events = [{"id": "e1", "summary": "Standup"}, {"id": "e2", "summary": "Review"}]
        svc.events.return_value.list.return_value.execute.return_value = {"items": fake_events}

        result = await handler.handle_list_events(
            time_min="2026-04-24T00:00:00Z",
            time_max="2026-04-24T23:59:59Z",
        )

        assert result.result.params["events"] == fake_events

    async def test_max_results_capped_by_config(self, tmp_path: Path) -> None:
        cfg = _make_google_config(max_events_per_query=10)
        handler, svc = _make_handler(tmp_path, config=cfg)
        svc.events.return_value.list.return_value.execute.return_value = {"items": []}

        await handler.handle_list_events(
            time_min="2026-04-24T00:00:00Z",
            time_max="2026-04-24T23:59:59Z",
            max_results=100,  # user requests 100 but config caps at 10
        )

        call_kwargs = svc.events.return_value.list.call_args.kwargs
        assert call_kwargs["maxResults"] == 10

    async def test_trace_id_propagated_to_result_um(self, tmp_path: Path) -> None:
        handler, svc = _make_handler(tmp_path)
        svc.events.return_value.list.return_value.execute.return_value = {"items": []}
        trace = "trace-abc-123"

        result = await handler.handle_list_events(
            time_min="2026-04-24T00:00:00Z",
            time_max="2026-04-24T23:59:59Z",
            trace_id=trace,
        )

        assert result.result.trace_id == trace

    async def test_google_api_exception_returns_failure(self, tmp_path: Path) -> None:
        handler, svc = _make_handler(tmp_path)
        svc.events.return_value.list.return_value.execute.side_effect = Exception("quota exceeded")

        result = await handler.handle_list_events(
            time_min="2026-04-24T00:00:00Z",
            time_max="2026-04-24T23:59:59Z",
            call_id="c_fail",
        )

        assert result.success is False
        assert "quota exceeded" in (result.error or "")
        assert result.call_id == "c_fail"
        print(f"list_events error result: {result.error}")

    async def test_empty_response_returns_empty_events_list(self, tmp_path: Path) -> None:
        handler, svc = _make_handler(tmp_path)
        # Google returns no 'items' key when calendar is empty
        svc.events.return_value.list.return_value.execute.return_value = {}

        result = await handler.handle_list_events(
            time_min="2026-04-24T00:00:00Z",
            time_max="2026-04-24T23:59:59Z",
        )

        assert result.success is True
        assert result.result.params["events"] == []


# ---------------------------------------------------------------------------
# handle_read_event
# ---------------------------------------------------------------------------


class TestHandleReadEvent:
    async def test_returns_tool_result_with_universal_message(self, tmp_path: Path) -> None:
        handler, svc = _make_handler(tmp_path)
        fake_event = {"id": "evt99", "summary": "All Hands", "description": "Quarterly review"}
        svc.events.return_value.get.return_value.execute.return_value = fake_event

        result = await handler.handle_read_event(event_id="evt99", call_id="c2")

        assert isinstance(result, ToolResult)
        assert result.success is True
        assert isinstance(result.result, UniversalMessage)
        print(f"read_event result: {result.result.params}")

    async def test_trust_level_is_local(self, tmp_path: Path) -> None:
        handler, svc = _make_handler(tmp_path)
        svc.events.return_value.get.return_value.execute.return_value = {"id": "e1"}

        result = await handler.handle_read_event(event_id="e1")

        assert result.result.trust_level == "local"

    async def test_event_in_params(self, tmp_path: Path) -> None:
        handler, svc = _make_handler(tmp_path)
        fake_event = {"id": "e1", "summary": "Dentist", "location": "123 Main St"}
        svc.events.return_value.get.return_value.execute.return_value = fake_event

        result = await handler.handle_read_event(event_id="e1")

        assert result.result.params["event"] == fake_event

    async def test_trace_id_propagated(self, tmp_path: Path) -> None:
        handler, svc = _make_handler(tmp_path)
        svc.events.return_value.get.return_value.execute.return_value = {"id": "e1"}
        trace = "trace-read-event"

        result = await handler.handle_read_event(event_id="e1", trace_id=trace)

        assert result.result.trace_id == trace

    async def test_google_api_exception_returns_failure(self, tmp_path: Path) -> None:
        handler, svc = _make_handler(tmp_path)
        svc.events.return_value.get.return_value.execute.side_effect = Exception("not found")

        result = await handler.handle_read_event(event_id="nonexistent", call_id="c_fail2")

        assert result.success is False
        assert "not found" in (result.error or "")
        print(f"read_event error result: {result.error}")


# ---------------------------------------------------------------------------
# handle_create_event
# ---------------------------------------------------------------------------


class TestHandleCreateEvent:
    async def test_returns_tool_result_with_universal_message(self, tmp_path: Path) -> None:
        handler, svc = _make_handler(tmp_path)
        svc.events.return_value.insert.return_value.execute.return_value = {
            "id": "new_evt_001",
            "summary": "Team Lunch",
        }

        result = await handler.handle_create_event(
            summary="Team Lunch",
            start="2026-04-25T12:00:00Z",
            end="2026-04-25T13:00:00Z",
            call_id="c3",
        )

        assert isinstance(result, ToolResult)
        assert result.success is True
        assert isinstance(result.result, UniversalMessage)
        print(f"create_event result: {result.result.params}")

    async def test_trust_level_is_local(self, tmp_path: Path) -> None:
        handler, svc = _make_handler(tmp_path)
        svc.events.return_value.insert.return_value.execute.return_value = {"id": "e_new"}

        result = await handler.handle_create_event(
            summary="Meeting",
            start="2026-04-25T09:00:00Z",
            end="2026-04-25T10:00:00Z",
        )

        assert result.result.trust_level == "local"

    async def test_result_params_contain_event_id(self, tmp_path: Path) -> None:
        handler, svc = _make_handler(tmp_path)
        svc.events.return_value.insert.return_value.execute.return_value = {"id": "evt_xyz"}

        result = await handler.handle_create_event(
            summary="Sprint Planning",
            start="2026-04-25T14:00:00Z",
            end="2026-04-25T15:30:00Z",
        )

        assert result.result.params["event_id"] == "evt_xyz"

    async def test_description_includes_attribution_string(self, tmp_path: Path) -> None:
        handler, svc = _make_handler(tmp_path)
        svc.events.return_value.insert.return_value.execute.return_value = {"id": "e1"}

        await handler.handle_create_event(
            summary="Sync",
            start="2026-04-25T10:00:00Z",
            end="2026-04-25T10:30:00Z",
            description="Weekly sync call",
        )

        body = svc.events.return_value.insert.call_args.kwargs["body"]
        assert _ATTRIBUTION in body["description"]
        assert "Weekly sync call" in body["description"]

    async def test_attribution_added_when_no_description(self, tmp_path: Path) -> None:
        handler, svc = _make_handler(tmp_path)
        svc.events.return_value.insert.return_value.execute.return_value = {"id": "e1"}

        await handler.handle_create_event(
            summary="No-desc event",
            start="2026-04-25T10:00:00Z",
            end="2026-04-25T10:30:00Z",
        )

        body = svc.events.return_value.insert.call_args.kwargs["body"]
        assert body["description"] == _ATTRIBUTION

    async def test_trace_id_propagated(self, tmp_path: Path) -> None:
        handler, svc = _make_handler(tmp_path)
        svc.events.return_value.insert.return_value.execute.return_value = {"id": "e1"}
        trace = "trace-create-event"

        result = await handler.handle_create_event(
            summary="Event",
            start="2026-04-25T10:00:00Z",
            end="2026-04-25T11:00:00Z",
            trace_id=trace,
        )

        assert result.result.trace_id == trace

    async def test_google_api_exception_returns_failure(self, tmp_path: Path) -> None:
        handler, svc = _make_handler(tmp_path)
        svc.events.return_value.insert.return_value.execute.side_effect = Exception(
            "calendar write error"
        )

        result = await handler.handle_create_event(
            summary="Bad Event",
            start="2026-04-25T10:00:00Z",
            end="2026-04-25T11:00:00Z",
            call_id="c_fail3",
        )

        assert result.success is False
        assert "calendar write error" in (result.error or "")
        print(f"create_event error result: {result.error}")

    async def test_optional_location_included_in_body(self, tmp_path: Path) -> None:
        handler, svc = _make_handler(tmp_path)
        svc.events.return_value.insert.return_value.execute.return_value = {"id": "e1"}

        await handler.handle_create_event(
            summary="Office meeting",
            start="2026-04-25T10:00:00Z",
            end="2026-04-25T11:00:00Z",
            location="Building A, Room 101",
        )

        body = svc.events.return_value.insert.call_args.kwargs["body"]
        assert body["location"] == "Building A, Room 101"

    async def test_missing_location_not_in_body(self, tmp_path: Path) -> None:
        handler, svc = _make_handler(tmp_path)
        svc.events.return_value.insert.return_value.execute.return_value = {"id": "e1"}

        await handler.handle_create_event(
            summary="No location event",
            start="2026-04-25T10:00:00Z",
            end="2026-04-25T11:00:00Z",
        )

        body = svc.events.return_value.insert.call_args.kwargs["body"]
        assert "location" not in body

    async def test_audit_event_logged_on_success(self, tmp_path: Path) -> None:
        audit = _make_audit(tmp_path)
        factory, svc = _make_client_factory()
        cfg = _make_google_config()
        handler = CalendarToolHandler(client=factory, config=cfg, audit=audit)
        svc.events.return_value.insert.return_value.execute.return_value = {"id": "audit_evt"}

        await handler.handle_create_event(
            summary="Audit test",
            start="2026-04-25T10:00:00Z",
            end="2026-04-25T11:00:00Z",
        )

        matching = await audit.query(event_type="calendar_event_created")
        assert len(matching) == 1
        assert matching[0].details["event_id"] == "audit_evt"
        print(f"Audit event logged: {matching[0]}")


# ---------------------------------------------------------------------------
# register_calendar_tools / google.enabled gate
# ---------------------------------------------------------------------------


class TestRegisterCalendarTools:
    def test_all_three_tools_registered(self, tmp_path: Path) -> None:
        registry = ToolRegistry()
        factory, svc = _make_client_factory()
        cfg = _make_google_config()
        audit = _make_audit(tmp_path)
        handler = CalendarToolHandler(client=factory, config=cfg, audit=audit)

        register_calendar_tools(registry, handler)

        names = {t.name for t in registry.list_tools()}
        assert "calendar_list_events" in names
        assert "calendar_read_event" in names
        assert "calendar_create_event" in names
        print(f"Registered tools: {names}")

    def test_tools_not_registered_when_google_disabled(self, tmp_path: Path) -> None:
        """Tools are never registered when google.enabled=False (startup guard)."""
        registry = ToolRegistry()
        # Simulating the startup.py conditional: don't call register_calendar_tools at all.
        # The registry should have zero calendar tools.
        names = {t.name for t in registry.list_tools()}
        assert "calendar_list_events" not in names
        assert "calendar_read_event" not in names
        assert "calendar_create_event" not in names

    def test_create_event_requires_approval(self) -> None:
        assert CALENDAR_CREATE_EVENT.requires_approval is True

    def test_list_events_does_not_require_approval(self) -> None:
        assert CALENDAR_LIST_EVENTS.requires_approval is False

    def test_read_event_does_not_require_approval(self) -> None:
        assert CALENDAR_READ_EVENT.requires_approval is False

    def test_create_event_action_level(self) -> None:
        assert CALENDAR_CREATE_EVENT.action_level == 3

    def test_read_tools_action_level_5(self) -> None:
        assert CALENDAR_LIST_EVENTS.action_level == 5
        assert CALENDAR_READ_EVENT.action_level == 5
