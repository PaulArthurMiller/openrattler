"""Tests for openrattler.tools.builtin.tasks_tools — TasksToolHandler."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import AsyncMock, MagicMock

import pytest

from openrattler.config.loader import GoogleConfig
from openrattler.integrations.google.client import GoogleClientFactory
from openrattler.integrations.google.sanitizer import GoogleContentSanitizer
from openrattler.models.messages import UniversalMessage
from openrattler.models.tools import ToolResult
from openrattler.storage.audit import AuditLog
from openrattler.tools.builtin.tasks_tools import (
    TASKS_COMPLETE_TASK,
    TASKS_CREATE_TASK,
    TASKS_LIST_TASKLISTS,
    TASKS_LIST_TASKS,
    TASKS_READ_TASK,
    TasksToolHandler,
    _ASSISTANT_SUFFIX,
    register_tasks_tools,
)
from openrattler.tools.registry import ToolRegistry

# ---------------------------------------------------------------------------
# Fixtures / helpers
# ---------------------------------------------------------------------------


def _make_audit(tmp_path: Path) -> AuditLog:
    return AuditLog(tmp_path / "audit.jsonl")


def _make_google_config(**overrides: object) -> GoogleConfig:
    defaults: dict = {
        "enabled": True,
        "credentials_file": "/tmp/credentials.json",
        "token_file": "/tmp/token.json",
        "user_email": "test@example.com",
        "max_file_bytes": 5_000_000,
        "max_file_chars": 20000,
        "max_email_chars": 10000,
        "max_tasks_per_query": 100,
    }
    defaults.update(overrides)
    return GoogleConfig(**defaults)


def _make_client_factory() -> tuple[MagicMock, MagicMock]:
    """Return (factory mock, tasks_svc mock)."""
    factory = MagicMock(spec=GoogleClientFactory)
    svc = MagicMock()
    factory.tasks_service = AsyncMock(return_value=svc)
    return factory, svc


def _make_sanitizer(tmp_path: Path, config: GoogleConfig | None = None) -> GoogleContentSanitizer:
    cfg = config or _make_google_config()
    return GoogleContentSanitizer(config=cfg, audit=_make_audit(tmp_path))


def _make_handler(
    tmp_path: Path,
    *,
    factory: MagicMock | None = None,
    config: GoogleConfig | None = None,
    sanitizer: GoogleContentSanitizer | None = None,
) -> tuple[TasksToolHandler, MagicMock]:
    """Return *(handler, tasks_svc_mock)*."""
    cfg = config or _make_google_config()
    if factory is None:
        factory, svc = _make_client_factory()
    else:
        svc = factory.tasks_service.return_value
    san = sanitizer or _make_sanitizer(tmp_path, config=cfg)
    audit = _make_audit(tmp_path)
    handler = TasksToolHandler(client=factory, sanitizer=san, config=cfg, audit=audit)
    return handler, svc


# ---------------------------------------------------------------------------
# Tool definitions — structural tests
# ---------------------------------------------------------------------------


class TestTasksToolDefinitions:
    def test_all_five_definitions_have_valid_action_levels(self) -> None:
        for tool_def in [
            TASKS_LIST_TASKLISTS,
            TASKS_LIST_TASKS,
            TASKS_READ_TASK,
            TASKS_CREATE_TASK,
            TASKS_COMPLETE_TASK,
        ]:
            assert (
                1 <= tool_def.action_level <= 5
            ), f"{tool_def.name} has action_level {tool_def.action_level} outside 1-5"

    def test_read_tools_are_level_5(self) -> None:
        assert TASKS_LIST_TASKLISTS.action_level == 5
        assert TASKS_LIST_TASKS.action_level == 5
        assert TASKS_READ_TASK.action_level == 5

    def test_create_task_is_level_3(self) -> None:
        assert TASKS_CREATE_TASK.action_level == 3

    def test_complete_task_is_level_4(self) -> None:
        assert TASKS_COMPLETE_TASK.action_level == 4

    def test_create_task_requires_approval(self) -> None:
        assert TASKS_CREATE_TASK.requires_approval is True

    def test_complete_task_does_not_require_approval(self) -> None:
        assert TASKS_COMPLETE_TASK.requires_approval is False

    def test_assistant_suffix_value(self) -> None:
        assert _ASSISTANT_SUFFIX == " [OpenRattler]"


# ---------------------------------------------------------------------------
# handle_list_tasklists
# ---------------------------------------------------------------------------


class TestHandleListTasklists:
    async def test_returns_tool_result_with_universal_message(self, tmp_path: Path) -> None:
        handler, svc = _make_handler(tmp_path)
        svc.tasklists.return_value.list.return_value.execute.return_value = {
            "items": [{"id": "tl1", "title": "My Tasks"}]
        }

        result = await handler.handle_list_tasklists(call_id="c1", trace_id="t1")

        assert isinstance(result, ToolResult)
        assert result.success is True
        assert isinstance(result.result, UniversalMessage)

    async def test_trust_level_is_local(self, tmp_path: Path) -> None:
        handler, svc = _make_handler(tmp_path)
        svc.tasklists.return_value.list.return_value.execute.return_value = {"items": []}

        result = await handler.handle_list_tasklists()

        assert result.result.trust_level == "local"

    async def test_params_contains_tasklists(self, tmp_path: Path) -> None:
        handler, svc = _make_handler(tmp_path)
        expected = [{"id": "tl1", "title": "My Tasks"}, {"id": "tl2", "title": "Work"}]
        svc.tasklists.return_value.list.return_value.execute.return_value = {"items": expected}

        result = await handler.handle_list_tasklists()

        assert result.result.params["tasklists"] == expected

    async def test_empty_items_key_returns_empty_list(self, tmp_path: Path) -> None:
        handler, svc = _make_handler(tmp_path)
        svc.tasklists.return_value.list.return_value.execute.return_value = {}

        result = await handler.handle_list_tasklists()

        assert result.success is True
        assert result.result.params["tasklists"] == []

    async def test_api_error_returns_failure(self, tmp_path: Path) -> None:
        handler, svc = _make_handler(tmp_path)
        svc.tasklists.return_value.list.return_value.execute.side_effect = RuntimeError("API fail")

        result = await handler.handle_list_tasklists()

        assert result.success is False
        assert "API fail" in result.error

    async def test_trace_id_propagated(self, tmp_path: Path) -> None:
        handler, svc = _make_handler(tmp_path)
        svc.tasklists.return_value.list.return_value.execute.return_value = {"items": []}

        result = await handler.handle_list_tasklists(trace_id="trace-xyz")

        assert result.result.trace_id == "trace-xyz"

    async def test_operation_name_in_result(self, tmp_path: Path) -> None:
        handler, svc = _make_handler(tmp_path)
        svc.tasklists.return_value.list.return_value.execute.return_value = {"items": []}

        result = await handler.handle_list_tasklists()

        assert result.result.operation == "tasks_list_tasklists"


# ---------------------------------------------------------------------------
# handle_list_tasks
# ---------------------------------------------------------------------------


class TestHandleListTasks:
    def _make_raw_task(
        self, task_id: str = "t1", title: str = "Buy milk", notes: str | None = None
    ) -> dict:
        task: dict = {"id": task_id, "title": title, "status": "needsAction"}
        if notes is not None:
            task["notes"] = notes
        return task

    async def test_returns_tool_result_with_universal_message(self, tmp_path: Path) -> None:
        handler, svc = _make_handler(tmp_path)
        svc.tasks.return_value.list.return_value.execute.return_value = {
            "items": [self._make_raw_task()]
        }

        result = await handler.handle_list_tasks()

        assert isinstance(result, ToolResult)
        assert result.success is True
        assert isinstance(result.result, UniversalMessage)

    async def test_trust_level_is_local(self, tmp_path: Path) -> None:
        handler, svc = _make_handler(tmp_path)
        svc.tasks.return_value.list.return_value.execute.return_value = {"items": []}

        result = await handler.handle_list_tasks()

        assert result.result.trust_level == "local"

    async def test_params_contains_tasks_and_tasklist_id(self, tmp_path: Path) -> None:
        handler, svc = _make_handler(tmp_path)
        svc.tasks.return_value.list.return_value.execute.return_value = {
            "items": [self._make_raw_task("t1", "Buy milk")]
        }

        result = await handler.handle_list_tasks(tasklist_id="@default")

        params = result.result.params
        assert "tasks" in params
        assert params["tasklist_id"] == "@default"
        assert len(params["tasks"]) == 1
        assert params["tasks"][0]["id"] == "t1"

    async def test_notes_passed_through_sanitizer(self, tmp_path: Path) -> None:
        handler, svc = _make_handler(tmp_path)
        svc.tasks.return_value.list.return_value.execute.return_value = {
            "items": [self._make_raw_task(notes="some task notes")]
        }

        result = await handler.handle_list_tasks()

        # Sanitizer wraps the content in [TASK NOTES]...[/TASK NOTES]
        notes_val = result.result.params["tasks"][0]["notes"]
        assert "[TASK NOTES]" in notes_val
        assert "some task notes" in notes_val

    async def test_none_notes_returns_empty_string(self, tmp_path: Path) -> None:
        handler, svc = _make_handler(tmp_path)
        svc.tasks.return_value.list.return_value.execute.return_value = {
            "items": [self._make_raw_task(notes=None)]
        }

        result = await handler.handle_list_tasks()

        assert result.result.params["tasks"][0]["notes"] == ""

    async def test_max_results_capped_by_config(self, tmp_path: Path) -> None:
        cfg = _make_google_config(max_tasks_per_query=50)
        handler, svc = _make_handler(tmp_path, config=cfg)
        svc.tasks.return_value.list.return_value.execute.return_value = {"items": []}

        await handler.handle_list_tasks(max_results=200)

        call_kwargs = svc.tasks.return_value.list.call_args.kwargs
        assert call_kwargs["maxResults"] == 50

    async def test_api_error_returns_failure(self, tmp_path: Path) -> None:
        handler, svc = _make_handler(tmp_path)
        svc.tasks.return_value.list.return_value.execute.side_effect = RuntimeError(
            "quota exceeded"
        )

        result = await handler.handle_list_tasks()

        assert result.success is False
        assert "quota exceeded" in result.error

    async def test_show_completed_and_hidden_passed_to_api(self, tmp_path: Path) -> None:
        handler, svc = _make_handler(tmp_path)
        svc.tasks.return_value.list.return_value.execute.return_value = {"items": []}

        await handler.handle_list_tasks(show_completed=True, show_hidden=True)

        call_kwargs = svc.tasks.return_value.list.call_args.kwargs
        assert call_kwargs["showCompleted"] is True
        assert call_kwargs["showHidden"] is True

    async def test_trace_id_propagated(self, tmp_path: Path) -> None:
        handler, svc = _make_handler(tmp_path)
        svc.tasks.return_value.list.return_value.execute.return_value = {"items": []}

        result = await handler.handle_list_tasks(trace_id="trace-abc")

        assert result.result.trace_id == "trace-abc"


# ---------------------------------------------------------------------------
# handle_read_task
# ---------------------------------------------------------------------------


class TestHandleReadTask:
    def _make_raw_task(self, **overrides: object) -> dict:
        task: dict = {
            "id": "t99",
            "title": "Write tests",
            "status": "needsAction",
            "due": None,
            "notes": None,
            "parent": None,
            "completed": None,
        }
        task.update(overrides)
        return task

    async def test_returns_tool_result_with_universal_message(self, tmp_path: Path) -> None:
        handler, svc = _make_handler(tmp_path)
        svc.tasks.return_value.get.return_value.execute.return_value = self._make_raw_task()

        result = await handler.handle_read_task("t99")

        assert isinstance(result, ToolResult)
        assert result.success is True
        assert isinstance(result.result, UniversalMessage)

    async def test_trust_level_is_local(self, tmp_path: Path) -> None:
        handler, svc = _make_handler(tmp_path)
        svc.tasks.return_value.get.return_value.execute.return_value = self._make_raw_task()

        result = await handler.handle_read_task("t99")

        assert result.result.trust_level == "local"

    async def test_params_contain_task_dict(self, tmp_path: Path) -> None:
        handler, svc = _make_handler(tmp_path)
        svc.tasks.return_value.get.return_value.execute.return_value = self._make_raw_task(
            title="Write tests"
        )

        result = await handler.handle_read_task("t99")

        task = result.result.params["task"]
        assert task["id"] == "t99"
        assert task["title"] == "Write tests"

    async def test_notes_sanitized(self, tmp_path: Path) -> None:
        handler, svc = _make_handler(tmp_path)
        svc.tasks.return_value.get.return_value.execute.return_value = self._make_raw_task(
            notes="Detailed notes here"
        )

        result = await handler.handle_read_task("t99")

        notes_val = result.result.params["task"]["notes"]
        assert "[TASK NOTES]" in notes_val
        assert "Detailed notes here" in notes_val

    async def test_none_notes_returns_empty_string(self, tmp_path: Path) -> None:
        handler, svc = _make_handler(tmp_path)
        svc.tasks.return_value.get.return_value.execute.return_value = self._make_raw_task(
            notes=None
        )

        result = await handler.handle_read_task("t99")

        assert result.result.params["task"]["notes"] == ""

    async def test_api_error_returns_failure(self, tmp_path: Path) -> None:
        handler, svc = _make_handler(tmp_path)
        svc.tasks.return_value.get.return_value.execute.side_effect = RuntimeError("not found")

        result = await handler.handle_read_task("bad-id")

        assert result.success is False
        assert "not found" in result.error

    async def test_tasklist_id_passed_to_api(self, tmp_path: Path) -> None:
        handler, svc = _make_handler(tmp_path)
        svc.tasks.return_value.get.return_value.execute.return_value = self._make_raw_task()

        await handler.handle_read_task("t99", "my-list-id")

        call_kwargs = svc.tasks.return_value.get.call_args.kwargs
        assert call_kwargs["tasklist"] == "my-list-id"
        assert call_kwargs["task"] == "t99"

    async def test_trace_id_propagated(self, tmp_path: Path) -> None:
        handler, svc = _make_handler(tmp_path)
        svc.tasks.return_value.get.return_value.execute.return_value = self._make_raw_task()

        result = await handler.handle_read_task("t99", trace_id="trace-read")

        assert result.result.trace_id == "trace-read"


# ---------------------------------------------------------------------------
# handle_create_task
# ---------------------------------------------------------------------------


class TestHandleCreateTask:
    async def test_returns_tool_result_with_universal_message(self, tmp_path: Path) -> None:
        handler, svc = _make_handler(tmp_path)
        svc.tasks.return_value.insert.return_value.execute.return_value = {
            "id": "new-task-1",
            "title": f"Buy groceries{_ASSISTANT_SUFFIX}",
        }

        result = await handler.handle_create_task("Buy groceries")

        assert isinstance(result, ToolResult)
        assert result.success is True
        assert isinstance(result.result, UniversalMessage)

    async def test_trust_level_is_local(self, tmp_path: Path) -> None:
        handler, svc = _make_handler(tmp_path)
        svc.tasks.return_value.insert.return_value.execute.return_value = {
            "id": "t1",
            "title": f"Task{_ASSISTANT_SUFFIX}",
        }

        result = await handler.handle_create_task("Task")

        assert result.result.trust_level == "local"

    async def test_title_includes_assistant_suffix(self, tmp_path: Path) -> None:
        handler, svc = _make_handler(tmp_path)
        svc.tasks.return_value.insert.return_value.execute.return_value = {
            "id": "t1",
            "title": f"Buy groceries{_ASSISTANT_SUFFIX}",
        }

        result = await handler.handle_create_task("Buy groceries")

        # Verify suffix sent to API
        call_kwargs = svc.tasks.return_value.insert.call_args.kwargs
        assert call_kwargs["body"]["title"] == f"Buy groceries{_ASSISTANT_SUFFIX}"
        # Verify suffix in result params
        assert result.result.params["title"] == f"Buy groceries{_ASSISTANT_SUFFIX}"

    async def test_params_contain_task_id_and_title(self, tmp_path: Path) -> None:
        handler, svc = _make_handler(tmp_path)
        svc.tasks.return_value.insert.return_value.execute.return_value = {
            "id": "new-task-99",
            "title": f"My task{_ASSISTANT_SUFFIX}",
        }

        result = await handler.handle_create_task("My task")

        params = result.result.params
        assert params["task_id"] == "new-task-99"
        assert params["tasklist_id"] == "@default"

    async def test_notes_included_when_provided(self, tmp_path: Path) -> None:
        handler, svc = _make_handler(tmp_path)
        svc.tasks.return_value.insert.return_value.execute.return_value = {"id": "t1"}

        await handler.handle_create_task("Task", notes="Do this carefully")

        body = svc.tasks.return_value.insert.call_args.kwargs["body"]
        assert body["notes"] == "Do this carefully"

    async def test_due_date_included_when_provided(self, tmp_path: Path) -> None:
        handler, svc = _make_handler(tmp_path)
        svc.tasks.return_value.insert.return_value.execute.return_value = {"id": "t1"}

        await handler.handle_create_task("Task", due="2026-05-01T00:00:00.000Z")

        body = svc.tasks.return_value.insert.call_args.kwargs["body"]
        assert body["due"] == "2026-05-01T00:00:00.000Z"

    async def test_parent_passed_to_api_when_provided(self, tmp_path: Path) -> None:
        handler, svc = _make_handler(tmp_path)
        svc.tasks.return_value.insert.return_value.execute.return_value = {"id": "t1"}

        await handler.handle_create_task("Subtask", parent="parent-task-id")

        call_kwargs = svc.tasks.return_value.insert.call_args.kwargs
        assert call_kwargs["parent"] == "parent-task-id"

    async def test_parent_not_passed_when_none(self, tmp_path: Path) -> None:
        handler, svc = _make_handler(tmp_path)
        svc.tasks.return_value.insert.return_value.execute.return_value = {"id": "t1"}

        await handler.handle_create_task("Task")

        call_kwargs = svc.tasks.return_value.insert.call_args.kwargs
        assert "parent" not in call_kwargs

    async def test_audit_log_entry_fired_on_success(self, tmp_path: Path) -> None:
        handler, svc = _make_handler(tmp_path)
        svc.tasks.return_value.insert.return_value.execute.return_value = {"id": "t1"}
        audit_path = tmp_path / "audit.jsonl"

        await handler.handle_create_task("Task")

        audit_text = audit_path.read_text()
        assert "tasks_task_created" in audit_text

    async def test_api_error_returns_failure(self, tmp_path: Path) -> None:
        handler, svc = _make_handler(tmp_path)
        svc.tasks.return_value.insert.return_value.execute.side_effect = RuntimeError("API error")

        result = await handler.handle_create_task("Task")

        assert result.success is False
        assert "API error" in result.error

    async def test_trace_id_propagated(self, tmp_path: Path) -> None:
        handler, svc = _make_handler(tmp_path)
        svc.tasks.return_value.insert.return_value.execute.return_value = {"id": "t1"}

        result = await handler.handle_create_task("Task", trace_id="trace-create")

        assert result.result.trace_id == "trace-create"


# ---------------------------------------------------------------------------
# handle_complete_task
# ---------------------------------------------------------------------------


class TestHandleCompleteTask:
    async def test_returns_tool_result_with_universal_message(self, tmp_path: Path) -> None:
        handler, svc = _make_handler(tmp_path)
        svc.tasks.return_value.patch.return_value.execute.return_value = {}

        result = await handler.handle_complete_task("t1")

        assert isinstance(result, ToolResult)
        assert result.success is True
        assert isinstance(result.result, UniversalMessage)

    async def test_trust_level_is_local(self, tmp_path: Path) -> None:
        handler, svc = _make_handler(tmp_path)
        svc.tasks.return_value.patch.return_value.execute.return_value = {}

        result = await handler.handle_complete_task("t1")

        assert result.result.trust_level == "local"

    async def test_completed_true_sends_completed_status(self, tmp_path: Path) -> None:
        handler, svc = _make_handler(tmp_path)
        svc.tasks.return_value.patch.return_value.execute.return_value = {}

        result = await handler.handle_complete_task("t1", completed=True)

        call_kwargs = svc.tasks.return_value.patch.call_args.kwargs
        assert call_kwargs["body"]["status"] == "completed"
        assert result.result.params["status"] == "completed"

    async def test_completed_false_sends_needs_action_status(self, tmp_path: Path) -> None:
        handler, svc = _make_handler(tmp_path)
        svc.tasks.return_value.patch.return_value.execute.return_value = {}

        result = await handler.handle_complete_task("t1", completed=False)

        call_kwargs = svc.tasks.return_value.patch.call_args.kwargs
        assert call_kwargs["body"]["status"] == "needsAction"
        assert result.result.params["status"] == "needsAction"

    async def test_completed_false_clears_completed_timestamp(self, tmp_path: Path) -> None:
        handler, svc = _make_handler(tmp_path)
        svc.tasks.return_value.patch.return_value.execute.return_value = {}

        await handler.handle_complete_task("t1", completed=False)

        call_kwargs = svc.tasks.return_value.patch.call_args.kwargs
        assert call_kwargs["body"].get("completed") is None

    async def test_tasklist_id_passed_to_api(self, tmp_path: Path) -> None:
        handler, svc = _make_handler(tmp_path)
        svc.tasks.return_value.patch.return_value.execute.return_value = {}

        await handler.handle_complete_task("t1", tasklist_id="my-list")

        call_kwargs = svc.tasks.return_value.patch.call_args.kwargs
        assert call_kwargs["tasklist"] == "my-list"
        assert call_kwargs["task"] == "t1"

    async def test_audit_log_entry_fired_on_success(self, tmp_path: Path) -> None:
        handler, svc = _make_handler(tmp_path)
        svc.tasks.return_value.patch.return_value.execute.return_value = {}
        audit_path = tmp_path / "audit.jsonl"

        await handler.handle_complete_task("t1")

        audit_text = audit_path.read_text()
        assert "tasks_task_completed" in audit_text

    async def test_audit_log_entry_fired_on_un_complete(self, tmp_path: Path) -> None:
        handler, svc = _make_handler(tmp_path)
        svc.tasks.return_value.patch.return_value.execute.return_value = {}
        audit_path = tmp_path / "audit.jsonl"

        await handler.handle_complete_task("t1", completed=False)

        audit_text = audit_path.read_text()
        assert "tasks_task_completed" in audit_text

    async def test_api_error_returns_failure(self, tmp_path: Path) -> None:
        handler, svc = _make_handler(tmp_path)
        svc.tasks.return_value.patch.return_value.execute.side_effect = RuntimeError("patch failed")

        result = await handler.handle_complete_task("t1")

        assert result.success is False
        assert "patch failed" in result.error

    async def test_trace_id_propagated(self, tmp_path: Path) -> None:
        handler, svc = _make_handler(tmp_path)
        svc.tasks.return_value.patch.return_value.execute.return_value = {}

        result = await handler.handle_complete_task("t1", trace_id="trace-complete")

        assert result.result.trace_id == "trace-complete"

    async def test_params_contain_task_id_and_tasklist_id(self, tmp_path: Path) -> None:
        handler, svc = _make_handler(tmp_path)
        svc.tasks.return_value.patch.return_value.execute.return_value = {}

        result = await handler.handle_complete_task("t99", tasklist_id="work-list")

        params = result.result.params
        assert params["task_id"] == "t99"
        assert params["tasklist_id"] == "work-list"


# ---------------------------------------------------------------------------
# Registration
# ---------------------------------------------------------------------------


class TestRegisterTasksTools:
    def test_all_five_tools_registered_when_enabled(self, tmp_path: Path) -> None:
        factory, _svc = _make_client_factory()
        cfg = _make_google_config(enabled=True)
        handler = TasksToolHandler(
            client=factory,
            sanitizer=_make_sanitizer(tmp_path, config=cfg),
            config=cfg,
            audit=_make_audit(tmp_path),
        )
        registry = ToolRegistry()
        register_tasks_tools(registry, handler)

        registered_names = {name for name in registry._tools}
        assert "tasks_list_tasklists" in registered_names
        assert "tasks_list_tasks" in registered_names
        assert "tasks_read_task" in registered_names
        assert "tasks_create_task" in registered_names
        assert "tasks_complete_task" in registered_names

    def test_tools_not_registered_when_not_called(self, tmp_path: Path) -> None:
        registry = ToolRegistry()

        registered_names = {name for name in registry._tools}
        assert "tasks_list_tasklists" not in registered_names
        assert "tasks_list_tasks" not in registered_names
        assert "tasks_read_task" not in registered_names
        assert "tasks_create_task" not in registered_names
        assert "tasks_complete_task" not in registered_names
