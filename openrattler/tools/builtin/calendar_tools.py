"""Google Calendar tools for the 41.x integration layer.

Three tool handlers let the main agent read and write the user's Google Calendar:

  - ``calendar_list_events``  — list events in a time window
  - ``calendar_read_event``   — fetch a single event by ID
  - ``calendar_create_event`` — create a new event (with attribution string)

All read results carry ``trust_level="local"`` (own calendar data).
All results are wrapped in a ``ToolResult`` with the structured payload in
``result`` (a ``UniversalMessage``).

SECURITY NOTES
--------------
- ``calendar_create_event`` appends a ``[Created by OpenRattler]`` attribution
  to every description before the API call so created events are identifiable.
- Google API exceptions are caught and surfaced as ``ToolResult(success=False)``
  — they never propagate raw to the LLM.
- ``trace_id`` from the originating ``ToolCall`` is propagated to every result
  ``UniversalMessage`` for end-to-end audit correlation.
"""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING, Any, Optional

from openrattler.models.agents import TrustLevel
from openrattler.models.audit import AuditEvent
from openrattler.models.messages import create_message
from openrattler.models.tools import ToolDefinition, ToolResult

if TYPE_CHECKING:
    from openrattler.config.loader import GoogleConfig
    from openrattler.integrations.google.client import GoogleClientFactory
    from openrattler.models.tools import ToolCall
    from openrattler.storage.audit import AuditLog
    from openrattler.tools.registry import ToolRegistry

logger = logging.getLogger(__name__)

_TOOLS_SESSION_KEY = "agent:main:main"
_ATTRIBUTION = "[Created by OpenRattler]"


# ---------------------------------------------------------------------------
# Tool definitions
# ---------------------------------------------------------------------------

CALENDAR_LIST_EVENTS = ToolDefinition(
    name="calendar_list_events",
    description=(
        "List Google Calendar events within a time window. "
        "Returns event summaries, start/end times, and event IDs."
    ),
    parameters={
        "type": "object",
        "properties": {
            "time_min": {
                "type": "string",
                "description": "Start of the time window (ISO 8601, e.g. 2026-04-24T00:00:00Z)",
            },
            "time_max": {
                "type": "string",
                "description": "End of the time window (ISO 8601, e.g. 2026-04-24T23:59:59Z)",
            },
            "calendar_id": {
                "type": "string",
                "description": "Calendar ID to query (default: 'primary')",
                "default": "primary",
            },
            "max_results": {
                "type": "integer",
                "description": "Maximum number of events to return (default: 50)",
                "default": 50,
            },
        },
        "required": ["time_min", "time_max"],
    },
    requires_approval=False,
    action_level=5,
    trust_level_required=TrustLevel.main,
    security_notes=(
        "Read-only. Returns own calendar data — trust_level='local'. "
        "max_results capped by GoogleConfig.max_events_per_query."
    ),
)

CALENDAR_READ_EVENT = ToolDefinition(
    name="calendar_read_event",
    description=(
        "Fetch a single Google Calendar event by its event ID. "
        "Returns full event details including attendees and description."
    ),
    parameters={
        "type": "object",
        "properties": {
            "event_id": {
                "type": "string",
                "description": "Google Calendar event ID",
            },
            "calendar_id": {
                "type": "string",
                "description": "Calendar ID that owns this event (default: 'primary')",
                "default": "primary",
            },
        },
        "required": ["event_id"],
    },
    requires_approval=False,
    action_level=5,
    trust_level_required=TrustLevel.main,
    security_notes="Read-only. Returns own calendar data — trust_level='local'.",
)

CALENDAR_CREATE_EVENT = ToolDefinition(
    name="calendar_create_event",
    description=(
        "Create a new event on Google Calendar. "
        "Requires explicit approval before execution. "
        "An attribution string is appended to the description automatically."
    ),
    parameters={
        "type": "object",
        "properties": {
            "summary": {
                "type": "string",
                "description": "Event title / summary",
            },
            "start": {
                "type": "string",
                "description": "Event start time (ISO 8601, e.g. 2026-04-25T14:00:00Z)",
            },
            "end": {
                "type": "string",
                "description": "Event end time (ISO 8601, e.g. 2026-04-25T15:00:00Z)",
            },
            "description": {
                "type": "string",
                "description": "Optional event description / notes",
            },
            "location": {
                "type": "string",
                "description": "Optional event location",
            },
            "calendar_id": {
                "type": "string",
                "description": "Calendar ID to create the event on (default: 'primary')",
                "default": "primary",
            },
        },
        "required": ["summary", "start", "end"],
    },
    requires_approval=True,
    action_level=3,
    trust_level_required=TrustLevel.main,
    security_notes=(
        "Write operation — requires human approval. "
        "Attribution string appended to every description before API call. "
        "Returns event_id in result UM params on success."
    ),
)


# ---------------------------------------------------------------------------
# Handler
# ---------------------------------------------------------------------------


class CalendarToolHandler:
    """Handles execution of the three calendar tool definitions.

    Args:
        client: ``GoogleClientFactory`` providing the Calendar API service.
        config: ``GoogleConfig`` carrying limits (max_events_per_query, calendar_id).
        audit:  Shared audit log.
    """

    def __init__(
        self,
        client: "GoogleClientFactory",
        config: "GoogleConfig",
        audit: "AuditLog",
    ) -> None:
        self._client = client
        self._config = config
        self._audit = audit

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    async def _handle_auth_expired(self, tool_name: str, call_id: str) -> ToolResult:
        """Clear stale credentials and return an actionable error for invalid_grant."""
        logger.warning("%s: Google OAuth invalid_grant detected — clearing credentials.", tool_name)
        self._client.clear_auth()
        await self._audit.log(
            AuditEvent(
                event="google_auth_expired",
                agent_id="calendar_tools",
                session_key=_TOOLS_SESSION_KEY,
                details={"tool": tool_name, "error": "invalid_grant"},
            )
        )
        return ToolResult(
            call_id=call_id,
            success=False,
            error=(
                "Google OAuth token has expired (invalid_grant). "
                "Run 'openrattler auth google' to re-authorize. "
                "Calendar tools will be unavailable until re-authorized."
            ),
        )

    # ------------------------------------------------------------------
    # Tool handlers
    # ------------------------------------------------------------------

    async def handle_list_events(
        self,
        time_min: str,
        time_max: str,
        calendar_id: str = "primary",
        max_results: int = 50,
        *,
        call_id: str = "",
        trace_id: Optional[str] = None,
    ) -> ToolResult:
        """List events within the given time window.

        Args:
            time_min:    ISO 8601 window start.
            time_max:    ISO 8601 window end.
            calendar_id: Target calendar (default ``"primary"``).
            max_results: Upper bound on returned events.
            call_id:     Passed through to ``ToolResult``.
            trace_id:    Propagated to result ``UniversalMessage``.

        Returns:
            ``ToolResult`` whose ``result`` is a ``UniversalMessage`` with
            ``params["events"]`` on success, or ``ToolResult(success=False)``
            on API error.
        """
        effective_max = min(max_results, self._config.max_events_per_query)
        try:
            svc = await self._client.calendar_service()
            response: dict[str, Any] = (
                svc.events()
                .list(
                    calendarId=calendar_id,
                    timeMin=time_min,
                    timeMax=time_max,
                    maxResults=effective_max,
                    singleEvents=True,
                    orderBy="startTime",
                )
                .execute()
            )
            events = response.get("items", [])
            logger.debug(
                "calendar_list_events: returned %d events for calendar=%s", len(events), calendar_id
            )
        except Exception as exc:
            if "invalid_grant" in str(exc):
                return await self._handle_auth_expired("calendar_list_events", call_id)
            logger.exception("calendar_list_events failed: calendar_id=%s", calendar_id)
            return ToolResult(call_id=call_id, success=False, error=str(exc))

        result_msg = create_message(
            from_agent="calendar_tools",
            to_agent="agent:main",
            session_key=_TOOLS_SESSION_KEY,
            type="response",
            operation="calendar_list_events",
            trust_level="local",
            params={"events": events, "calendar_id": calendar_id},
            trace_id=trace_id,
        )
        return ToolResult(call_id=call_id, success=True, result=result_msg)

    async def handle_read_event(
        self,
        event_id: str,
        calendar_id: str = "primary",
        *,
        call_id: str = "",
        trace_id: Optional[str] = None,
    ) -> ToolResult:
        """Fetch a single event by ID.

        Args:
            event_id:    Google Calendar event ID.
            calendar_id: Calendar that owns the event (default ``"primary"``).
            call_id:     Passed through to ``ToolResult``.
            trace_id:    Propagated to result ``UniversalMessage``.

        Returns:
            ``ToolResult`` with the full event dict in ``params["event"]``, or
            ``ToolResult(success=False)`` on API error.
        """
        try:
            svc = await self._client.calendar_service()
            event: dict[str, Any] = (
                svc.events().get(calendarId=calendar_id, eventId=event_id).execute()
            )
            logger.debug("calendar_read_event: fetched event_id=%s", event_id)
        except Exception as exc:
            if "invalid_grant" in str(exc):
                return await self._handle_auth_expired("calendar_read_event", call_id)
            logger.exception(
                "calendar_read_event failed: event_id=%s calendar_id=%s", event_id, calendar_id
            )
            return ToolResult(call_id=call_id, success=False, error=str(exc))

        result_msg = create_message(
            from_agent="calendar_tools",
            to_agent="agent:main",
            session_key=_TOOLS_SESSION_KEY,
            type="response",
            operation="calendar_read_event",
            trust_level="local",
            params={"event": event, "calendar_id": calendar_id},
            trace_id=trace_id,
        )
        return ToolResult(call_id=call_id, success=True, result=result_msg)

    async def handle_create_event(
        self,
        summary: str,
        start: str,
        end: str,
        description: Optional[str] = None,
        location: Optional[str] = None,
        calendar_id: str = "primary",
        *,
        call_id: str = "",
        trace_id: Optional[str] = None,
    ) -> ToolResult:
        """Create a new calendar event with attribution.

        An ``_ATTRIBUTION`` string is appended to *description* before the API
        call so events created by the assistant are identifiable in the calendar.

        Args:
            summary:     Event title.
            start:       ISO 8601 start time.
            end:         ISO 8601 end time.
            description: Optional event notes.
            location:    Optional event location.
            calendar_id: Target calendar (default ``"primary"``).
            call_id:     Passed through to ``ToolResult``.
            trace_id:    Propagated to result ``UniversalMessage``.

        Returns:
            ``ToolResult`` with ``params["event_id"]`` on success, or
            ``ToolResult(success=False)`` on API error.
        """
        attributed_description = f"{description}\n\n{_ATTRIBUTION}" if description else _ATTRIBUTION

        body: dict[str, Any] = {
            "summary": summary,
            "description": attributed_description,
            "start": {"dateTime": start, "timeZone": "UTC"},
            "end": {"dateTime": end, "timeZone": "UTC"},
        }
        if location:
            body["location"] = location

        try:
            svc = await self._client.calendar_service()
            created: dict[str, Any] = (
                svc.events().insert(calendarId=calendar_id, body=body).execute()
            )
            event_id: str = created.get("id", "")
            logger.info(
                "calendar_create_event: created event_id=%s calendar_id=%s", event_id, calendar_id
            )
        except Exception as exc:
            if "invalid_grant" in str(exc):
                return await self._handle_auth_expired("calendar_create_event", call_id)
            logger.exception(
                "calendar_create_event failed: summary=%r calendar_id=%s", summary, calendar_id
            )
            return ToolResult(call_id=call_id, success=False, error=str(exc))

        await self._audit.log(
            AuditEvent(
                event="calendar_event_created",
                agent_id="calendar_tools",
                session_key=_TOOLS_SESSION_KEY,
                details={"event_id": event_id, "calendar_id": calendar_id, "summary": summary},
            )
        )

        result_msg = create_message(
            from_agent="calendar_tools",
            to_agent="agent:main",
            session_key=_TOOLS_SESSION_KEY,
            type="response",
            operation="calendar_create_event",
            trust_level="local",
            params={"event_id": event_id, "calendar_id": calendar_id, "summary": summary},
            trace_id=trace_id,
        )
        return ToolResult(call_id=call_id, success=True, result=result_msg)


# ---------------------------------------------------------------------------
# Registration
# ---------------------------------------------------------------------------


def register_calendar_tools(
    registry: "ToolRegistry",
    handler: CalendarToolHandler,
) -> None:
    """Register all three calendar tools with *registry*.

    Called from ``startup.py`` when ``config.google.enabled`` is True.

    Args:
        registry: The ``ToolRegistry`` to register tools into.
        handler:  The ``CalendarToolHandler`` whose methods serve as callbacks.
    """
    registry.register(CALENDAR_LIST_EVENTS, handler.handle_list_events)
    registry.register(CALENDAR_READ_EVENT, handler.handle_read_event)
    registry.register(CALENDAR_CREATE_EVENT, handler.handle_create_event)
    logger.info("Calendar tools registered: list_events, read_event, create_event")
