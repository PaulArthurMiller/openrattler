"""Google Tasks tools for the 41.x integration layer.

Five tool handlers let the main agent list, read, and manage Google Tasks:

  - ``tasks_list_tasklists`` — list all task lists
  - ``tasks_list_tasks``     — list tasks in a task list
  - ``tasks_read_task``      — full details of a specific task
  - ``tasks_create_task``    — create a new task
  - ``tasks_complete_task``  — mark a task complete or incomplete

All results carry ``trust_level="local"`` since tasks live in the user's
own Google account.  Task ``notes`` fields are passed through
``GoogleContentSanitizer`` because they may contain externally pasted text.

All results are wrapped in a ``ToolResult`` with the structured payload in
``result`` (a ``UniversalMessage``).

SECURITY NOTES
--------------
- Task ``notes`` fields pass through ``GoogleContentSanitizer`` before
  being included in results.  A ``None`` notes field is handled gracefully
  (returns empty ``SanitizedContent``).
- Write operations (create, complete) are logged to the audit log on success.
- Google API exceptions are caught and surfaced as ``ToolResult(success=False)``
  — they never propagate raw to the LLM.
- ``trace_id`` from the originating ``ToolCall`` is propagated to every result
  ``UniversalMessage`` for end-to-end audit correlation.
- Assistant-created tasks include a ``" [OpenRattler]"`` suffix in the title
  so they are identifiable in the user's task list.
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
    from openrattler.integrations.google.sanitizer import GoogleContentSanitizer
    from openrattler.models.tools import ToolCall
    from openrattler.storage.audit import AuditLog
    from openrattler.tools.registry import ToolRegistry

logger = logging.getLogger(__name__)

_TOOLS_SESSION_KEY = "agent:main:main"

# ---------------------------------------------------------------------------
# Tool definitions
# ---------------------------------------------------------------------------

TASKS_LIST_TASKLISTS = ToolDefinition(
    name="tasks_list_tasklists",
    description=(
        "List all Google Task lists in the user's account. "
        "Returns task list IDs and titles. "
        "Use the returned IDs with tasks_list_tasks to query tasks in a specific list."
    ),
    parameters={
        "type": "object",
        "properties": {},
        "required": [],
    },
    requires_approval=False,
    action_level=5,
    trust_level_required=TrustLevel.main,
    security_notes="Read-only listing. Returns own task list metadata — trust_level='local'.",
)

TASKS_LIST_TASKS = ToolDefinition(
    name="tasks_list_tasks",
    description=(
        "List tasks in a Google Tasks task list. "
        "Returns task IDs, titles, status, and due dates. "
        "Note: subtasks are not included by default — fetch a parent task's children separately. "
        "Use tasks_read_task for full task details including notes."
    ),
    parameters={
        "type": "object",
        "properties": {
            "tasklist_id": {
                "type": "string",
                "description": (
                    "Task list ID. '@default' resolves to the primary task list (default: '@default')"
                ),
                "default": "@default",
            },
            "show_completed": {
                "type": "boolean",
                "description": "Include completed tasks in results (default: False)",
                "default": False,
            },
            "show_hidden": {
                "type": "boolean",
                "description": "Include hidden tasks in results (default: False)",
                "default": False,
            },
            "max_results": {
                "type": "integer",
                "description": "Maximum number of tasks to return (default: 100)",
                "default": 100,
            },
        },
        "required": [],
    },
    requires_approval=False,
    action_level=5,
    trust_level_required=TrustLevel.main,
    security_notes=(
        "Read-only listing. Task notes are sanitized before being returned. " "trust_level='local'."
    ),
)

TASKS_READ_TASK = ToolDefinition(
    name="tasks_read_task",
    description=(
        "Read the full details of a specific Google Task by ID. "
        "Returns title, notes, due date, status, and parent task ID (if a subtask)."
    ),
    parameters={
        "type": "object",
        "properties": {
            "task_id": {
                "type": "string",
                "description": "Google Tasks task ID",
            },
            "tasklist_id": {
                "type": "string",
                "description": (
                    "Task list ID containing the task. '@default' resolves to the primary "
                    "task list (default: '@default')"
                ),
                "default": "@default",
            },
        },
        "required": ["task_id"],
    },
    requires_approval=False,
    action_level=5,
    trust_level_required=TrustLevel.main,
    security_notes=(
        "Read-only. Task notes are sanitized before being returned. trust_level='local'."
    ),
)

TASKS_CREATE_TASK = ToolDefinition(
    name="tasks_create_task",
    description=(
        "Create a new task in a Google Tasks task list. "
        "The task title will include a '[OpenRattler]' suffix for identification. "
        "Supports optional notes, due date (ISO 8601), and parent task ID for subtasks."
    ),
    parameters={
        "type": "object",
        "properties": {
            "title": {
                "type": "string",
                "description": "Task title",
            },
            "notes": {
                "type": "string",
                "description": "Optional task notes or description",
            },
            "due": {
                "type": "string",
                "description": (
                    "Optional due date in ISO 8601 format (e.g. '2026-04-30T00:00:00.000Z')"
                ),
            },
            "tasklist_id": {
                "type": "string",
                "description": (
                    "Task list ID to create the task in. '@default' resolves to the primary "
                    "task list (default: '@default')"
                ),
                "default": "@default",
            },
            "parent": {
                "type": "string",
                "description": "Optional parent task ID for creating a subtask",
            },
        },
        "required": ["title"],
    },
    requires_approval=True,
    action_level=3,
    trust_level_required=TrustLevel.main,
    security_notes="Creates a new task. Audit logged on success. trust_level='local' on result.",
)

TASKS_COMPLETE_TASK = ToolDefinition(
    name="tasks_complete_task",
    description=(
        "Mark a Google Task as complete or incomplete. "
        "Set completed=True to mark done; completed=False to un-complete (restore to 'needsAction')."
    ),
    parameters={
        "type": "object",
        "properties": {
            "task_id": {
                "type": "string",
                "description": "Google Tasks task ID",
            },
            "tasklist_id": {
                "type": "string",
                "description": (
                    "Task list ID containing the task. '@default' resolves to the primary "
                    "task list (default: '@default')"
                ),
                "default": "@default",
            },
            "completed": {
                "type": "boolean",
                "description": "True to mark complete; False to mark incomplete (default: True)",
                "default": True,
            },
        },
        "required": ["task_id"],
    },
    requires_approval=False,
    action_level=4,
    trust_level_required=TrustLevel.main,
    security_notes=(
        "Toggles completion state — reversible. Audit logged on success. trust_level='local'."
    ),
)

# ---------------------------------------------------------------------------
# Handler
# ---------------------------------------------------------------------------

_ASSISTANT_SUFFIX = " [OpenRattler]"


class TasksToolHandler:
    """Handles execution of the five Google Tasks tool definitions.

    Args:
        client:    ``GoogleClientFactory`` providing the Tasks API service.
        sanitizer: ``GoogleContentSanitizer`` — applied to task notes fields.
        config:    ``GoogleConfig`` carrying limits (max_tasks_per_query).
        audit:     Shared audit log.
    """

    def __init__(
        self,
        client: "GoogleClientFactory",
        sanitizer: "GoogleContentSanitizer",
        config: "GoogleConfig",
        audit: "AuditLog",
    ) -> None:
        self._client = client
        self._sanitizer = sanitizer
        self._config = config
        self._audit = audit

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    async def _sanitize_notes(self, notes: Optional[str]) -> str:
        """Sanitize task notes, returning empty string for None input."""
        if not notes:
            return ""
        sanitized = await self._sanitizer.sanitize_file_content(notes, "text/plain")
        return self._sanitizer.wrap_for_agent(sanitized, "TASK NOTES")

    # ------------------------------------------------------------------
    # Tool handlers
    # ------------------------------------------------------------------

    async def handle_list_tasklists(
        self,
        *,
        call_id: str = "",
        trace_id: Optional[str] = None,
    ) -> ToolResult:
        """List all Google Task lists.

        Args:
            call_id:  Passed through to ``ToolResult``.
            trace_id: Propagated to result ``UniversalMessage``.

        Returns:
            ``ToolResult`` with ``params["tasklists"]`` on success.
        """
        try:
            svc = await self._client.tasks_service()
            response: dict[str, Any] = svc.tasklists().list().execute()
            tasklists = response.get("items", [])
            logger.debug("tasks_list_tasklists: returned %d task lists", len(tasklists))
        except Exception as exc:
            logger.exception("tasks_list_tasklists failed")
            return ToolResult(call_id=call_id, success=False, error=str(exc))

        result_msg = create_message(
            from_agent="tasks_tools",
            to_agent="agent:main",
            session_key=_TOOLS_SESSION_KEY,
            type="response",
            operation="tasks_list_tasklists",
            trust_level="local",
            params={"tasklists": tasklists},
            trace_id=trace_id,
        )
        return ToolResult(call_id=call_id, success=True, result=result_msg)

    async def handle_list_tasks(
        self,
        tasklist_id: str = "@default",
        show_completed: bool = False,
        show_hidden: bool = False,
        max_results: int = 100,
        *,
        call_id: str = "",
        trace_id: Optional[str] = None,
    ) -> ToolResult:
        """List tasks in a task list.

        Task notes are sanitized before being returned.

        Args:
            tasklist_id:    Task list ID (``"@default"`` for primary list).
            show_completed: Include completed tasks.
            show_hidden:    Include hidden tasks.
            max_results:    Upper bound on returned tasks.
            call_id:        Passed through to ``ToolResult``.
            trace_id:       Propagated to result ``UniversalMessage``.

        Returns:
            ``ToolResult`` with ``params["tasks"]`` on success.
        """
        try:
            svc = await self._client.tasks_service()
            capped = min(max_results, self._config.max_tasks_per_query)
            response: dict[str, Any] = (
                svc.tasks()
                .list(
                    tasklist=tasklist_id,
                    showCompleted=show_completed,
                    showHidden=show_hidden,
                    maxResults=capped,
                )
                .execute()
            )
            raw_tasks: list[dict[str, Any]] = response.get("items", [])
            logger.debug(
                "tasks_list_tasks: returned %d tasks from tasklist=%s",
                len(raw_tasks),
                tasklist_id,
            )
        except Exception as exc:
            logger.exception("tasks_list_tasks failed: tasklist_id=%s", tasklist_id)
            return ToolResult(call_id=call_id, success=False, error=str(exc))

        # Sanitize notes for each task.
        tasks: list[dict[str, Any]] = []
        for task in raw_tasks:
            sanitized_notes = await self._sanitize_notes(task.get("notes"))
            tasks.append(
                {
                    "id": task.get("id", ""),
                    "title": task.get("title", ""),
                    "status": task.get("status", ""),
                    "due": task.get("due"),
                    "notes": sanitized_notes,
                    "parent": task.get("parent"),
                }
            )

        result_msg = create_message(
            from_agent="tasks_tools",
            to_agent="agent:main",
            session_key=_TOOLS_SESSION_KEY,
            type="response",
            operation="tasks_list_tasks",
            trust_level="local",
            params={"tasks": tasks, "tasklist_id": tasklist_id},
            trace_id=trace_id,
        )
        return ToolResult(call_id=call_id, success=True, result=result_msg)

    async def handle_read_task(
        self,
        task_id: str,
        tasklist_id: str = "@default",
        *,
        call_id: str = "",
        trace_id: Optional[str] = None,
    ) -> ToolResult:
        """Read full details of a single task.

        Task notes are sanitized before being returned.

        Args:
            task_id:     Google Tasks task ID.
            tasklist_id: Task list containing the task.
            call_id:     Passed through to ``ToolResult``.
            trace_id:    Propagated to result ``UniversalMessage``.

        Returns:
            ``ToolResult`` with ``params["task"]`` on success.
        """
        try:
            svc = await self._client.tasks_service()
            task: dict[str, Any] = svc.tasks().get(tasklist=tasklist_id, task=task_id).execute()
            logger.debug(
                "tasks_read_task: fetched task_id=%s from tasklist=%s", task_id, tasklist_id
            )
        except Exception as exc:
            logger.exception("tasks_read_task failed: task_id=%s", task_id)
            return ToolResult(call_id=call_id, success=False, error=str(exc))

        sanitized_notes = await self._sanitize_notes(task.get("notes"))

        result_msg = create_message(
            from_agent="tasks_tools",
            to_agent="agent:main",
            session_key=_TOOLS_SESSION_KEY,
            type="response",
            operation="tasks_read_task",
            trust_level="local",
            params={
                "task": {
                    "id": task.get("id", ""),
                    "title": task.get("title", ""),
                    "status": task.get("status", ""),
                    "due": task.get("due"),
                    "notes": sanitized_notes,
                    "parent": task.get("parent"),
                    "completed": task.get("completed"),
                }
            },
            trace_id=trace_id,
        )
        return ToolResult(call_id=call_id, success=True, result=result_msg)

    async def handle_create_task(
        self,
        title: str,
        notes: Optional[str] = None,
        due: Optional[str] = None,
        tasklist_id: str = "@default",
        parent: Optional[str] = None,
        *,
        call_id: str = "",
        trace_id: Optional[str] = None,
    ) -> ToolResult:
        """Create a new task in a task list.

        Appends ``" [OpenRattler]"`` to the title so assistant-created tasks
        are identifiable.  Audit-logged on success.

        Args:
            title:       Task title (suffix will be appended).
            notes:       Optional task notes.
            due:         Optional due date in ISO 8601 format.
            tasklist_id: Task list to create the task in.
            parent:      Optional parent task ID for subtasks.
            call_id:     Passed through to ``ToolResult``.
            trace_id:    Propagated to result ``UniversalMessage``.

        Returns:
            ``ToolResult`` with ``params["task_id"]`` and ``params["title"]``
            on success.
        """
        full_title = f"{title}{_ASSISTANT_SUFFIX}"
        body: dict[str, Any] = {"title": full_title}
        if notes is not None:
            body["notes"] = notes
        if due is not None:
            body["due"] = due

        kwargs: dict[str, Any] = {"tasklist": tasklist_id, "body": body}
        if parent is not None:
            kwargs["parent"] = parent

        try:
            svc = await self._client.tasks_service()
            created: dict[str, Any] = svc.tasks().insert(**kwargs).execute()
            task_id: str = created.get("id", "")
            logger.info(
                "tasks_create_task: created task_id=%s title=%r in tasklist=%s",
                task_id,
                full_title,
                tasklist_id,
            )
        except Exception as exc:
            logger.exception("tasks_create_task failed: title=%r", title)
            return ToolResult(call_id=call_id, success=False, error=str(exc))

        await self._audit.log(
            AuditEvent(
                event="tasks_task_created",
                agent_id="tasks_tools",
                session_key=_TOOLS_SESSION_KEY,
                details={"task_id": task_id, "title": full_title, "tasklist_id": tasklist_id},
            )
        )

        result_msg = create_message(
            from_agent="tasks_tools",
            to_agent="agent:main",
            session_key=_TOOLS_SESSION_KEY,
            type="response",
            operation="tasks_create_task",
            trust_level="local",
            params={"task_id": task_id, "title": full_title, "tasklist_id": tasklist_id},
            trace_id=trace_id,
        )
        return ToolResult(call_id=call_id, success=True, result=result_msg)

    async def handle_complete_task(
        self,
        task_id: str,
        tasklist_id: str = "@default",
        completed: bool = True,
        *,
        call_id: str = "",
        trace_id: Optional[str] = None,
    ) -> ToolResult:
        """Mark a task complete or incomplete.

        Uses ``tasks.patch()`` to update only the status field.  When
        un-completing, the ``completed`` timestamp is also cleared per the
        Google Tasks API requirement.  Audit-logged on success.

        Args:
            task_id:     Google Tasks task ID.
            tasklist_id: Task list containing the task.
            completed:   True → ``status="completed"``; False → ``status="needsAction"``.
            call_id:     Passed through to ``ToolResult``.
            trace_id:    Propagated to result ``UniversalMessage``.

        Returns:
            ``ToolResult`` with ``params["task_id"]`` and ``params["status"]``
            on success.
        """
        if completed:
            patch_body: dict[str, Any] = {"status": "completed"}
            status_label = "completed"
        else:
            # The API requires clearing the `completed` timestamp when un-completing.
            patch_body = {"status": "needsAction", "completed": None}
            status_label = "needsAction"

        try:
            svc = await self._client.tasks_service()
            svc.tasks().patch(
                tasklist=tasklist_id,
                task=task_id,
                body=patch_body,
            ).execute()
            logger.info(
                "tasks_complete_task: task_id=%s → status=%s in tasklist=%s",
                task_id,
                status_label,
                tasklist_id,
            )
        except Exception as exc:
            logger.exception("tasks_complete_task failed: task_id=%s", task_id)
            return ToolResult(call_id=call_id, success=False, error=str(exc))

        await self._audit.log(
            AuditEvent(
                event="tasks_task_completed",
                agent_id="tasks_tools",
                session_key=_TOOLS_SESSION_KEY,
                details={
                    "task_id": task_id,
                    "tasklist_id": tasklist_id,
                    "status": status_label,
                },
            )
        )

        result_msg = create_message(
            from_agent="tasks_tools",
            to_agent="agent:main",
            session_key=_TOOLS_SESSION_KEY,
            type="response",
            operation="tasks_complete_task",
            trust_level="local",
            params={"task_id": task_id, "status": status_label, "tasklist_id": tasklist_id},
            trace_id=trace_id,
        )
        return ToolResult(call_id=call_id, success=True, result=result_msg)


# ---------------------------------------------------------------------------
# Registration
# ---------------------------------------------------------------------------


def register_tasks_tools(
    registry: "ToolRegistry",
    handler: TasksToolHandler,
) -> None:
    """Register all five Google Tasks tools with *registry*.

    Called from ``startup.py`` when ``config.google.enabled`` is True.

    Args:
        registry: The ``ToolRegistry`` to register tools into.
        handler:  The ``TasksToolHandler`` whose methods serve as callbacks.
    """
    registry.register(TASKS_LIST_TASKLISTS, handler.handle_list_tasklists)
    registry.register(TASKS_LIST_TASKS, handler.handle_list_tasks)
    registry.register(TASKS_READ_TASK, handler.handle_read_task)
    registry.register(TASKS_CREATE_TASK, handler.handle_create_task)
    registry.register(TASKS_COMPLETE_TASK, handler.handle_complete_task)
    logger.info(
        "Tasks tools registered: list_tasklists, list_tasks, read_task, create_task, complete_task"
    )
