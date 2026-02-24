"""Tests for ToolDefinition, ToolCall, and ToolResult models."""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from openrattler.models.agents import TrustLevel
from openrattler.models.tools import ToolCall, ToolDefinition, ToolResult

# ---------------------------------------------------------------------------
# ToolDefinition
# ---------------------------------------------------------------------------


_FILE_READ_DEF = dict(
    name="file_read",
    description="Read a file from the agent workspace",
    parameters={
        "type": "object",
        "properties": {"path": {"type": "string"}},
        "required": ["path"],
    },
    requires_approval=False,
    trust_level_required=TrustLevel.main,
    security_notes="Validates path is within workspace; rejects traversal attempts.",
)


class TestToolDefinition:
    def test_minimal_definition(self) -> None:
        td = ToolDefinition(**_FILE_READ_DEF)
        assert td.name == "file_read"
        assert td.trust_level_required == TrustLevel.main
        assert td.requires_approval is False

    def test_requires_approval_true(self) -> None:
        td = ToolDefinition(**{**_FILE_READ_DEF, "requires_approval": True})
        assert td.requires_approval is True

    def test_security_notes_default_empty(self) -> None:
        td = ToolDefinition(
            name="web_search",
            description="Search the web",
            parameters={},
            requires_approval=False,
            trust_level_required=TrustLevel.public,
        )
        assert td.security_notes == ""

    def test_all_trust_levels_valid(self) -> None:
        for level in TrustLevel:
            td = ToolDefinition(**{**_FILE_READ_DEF, "trust_level_required": level})
            assert td.trust_level_required == level

    def test_invalid_trust_level_rejected(self) -> None:
        with pytest.raises(ValidationError):
            ToolDefinition(**{**_FILE_READ_DEF, "trust_level_required": "admin"})  # type: ignore[arg-type]

    def test_missing_required_field_raises(self) -> None:
        with pytest.raises(ValidationError):
            ToolDefinition(
                # name missing
                description="desc",
                parameters={},
                requires_approval=False,
                trust_level_required=TrustLevel.main,
            )

    def test_round_trip(self) -> None:
        td = ToolDefinition(**_FILE_READ_DEF)
        data = td.model_dump()
        restored = ToolDefinition.model_validate(data)
        assert restored == td

    def test_json_round_trip(self) -> None:
        td = ToolDefinition(**_FILE_READ_DEF)
        restored = ToolDefinition.model_validate_json(td.model_dump_json())
        assert restored.name == td.name
        assert restored.trust_level_required == td.trust_level_required


# ---------------------------------------------------------------------------
# ToolCall
# ---------------------------------------------------------------------------


class TestToolCall:
    def test_basic_call(self) -> None:
        tc = ToolCall(
            tool_name="file_read",
            arguments={"path": "notes.txt"},
            call_id="call-abc-123",
        )
        assert tc.tool_name == "file_read"
        assert tc.arguments["path"] == "notes.txt"
        assert tc.call_id == "call-abc-123"

    def test_empty_arguments_default(self) -> None:
        tc = ToolCall(tool_name="list_sessions", call_id="call-001")
        assert tc.arguments == {}

    def test_missing_tool_name_raises(self) -> None:
        with pytest.raises(ValidationError):
            ToolCall(arguments={}, call_id="call-001")  # type: ignore[call-arg]

    def test_missing_call_id_raises(self) -> None:
        with pytest.raises(ValidationError):
            ToolCall(tool_name="file_read", arguments={})  # type: ignore[call-arg]

    def test_nested_arguments(self) -> None:
        tc = ToolCall(
            tool_name="api_call",
            arguments={"url": "https://api.example.com", "headers": {"auth": "token"}},
            call_id="call-nested",
        )
        assert tc.arguments["headers"]["auth"] == "token"

    def test_round_trip(self) -> None:
        tc = ToolCall(
            tool_name="file_read",
            arguments={"path": "data.json"},
            call_id="call-rt-001",
        )
        data = tc.model_dump()
        restored = ToolCall.model_validate(data)
        assert restored == tc


# ---------------------------------------------------------------------------
# ToolResult
# ---------------------------------------------------------------------------


class TestToolResult:
    def test_successful_result(self) -> None:
        tr = ToolResult(
            call_id="call-abc-123",
            success=True,
            result="file contents here",
        )
        assert tr.success is True
        assert tr.result == "file contents here"
        assert tr.error is None

    def test_failed_result(self) -> None:
        tr = ToolResult(
            call_id="call-abc-123",
            success=False,
            result=None,
            error="Permission denied: path outside workspace",
        )
        assert tr.success is False
        assert tr.error == "Permission denied: path outside workspace"
        assert tr.result is None

    def test_result_can_be_dict(self) -> None:
        tr = ToolResult(
            call_id="call-dict",
            success=True,
            result={"forecast": [{"day": "Monday", "high": 68}]},
        )
        assert isinstance(tr.result, dict)

    def test_result_can_be_list(self) -> None:
        tr = ToolResult(
            call_id="call-list",
            success=True,
            result=["file1.txt", "file2.txt"],
        )
        assert isinstance(tr.result, list)

    def test_missing_call_id_raises(self) -> None:
        with pytest.raises(ValidationError):
            ToolResult(success=True, result="ok")  # type: ignore[call-arg]

    def test_missing_success_raises(self) -> None:
        with pytest.raises(ValidationError):
            ToolResult(call_id="call-001", result="ok")  # type: ignore[call-arg]

    def test_round_trip_success(self) -> None:
        tr = ToolResult(call_id="call-rt", success=True, result=42)
        data = tr.model_dump()
        restored = ToolResult.model_validate(data)
        assert restored == tr

    def test_round_trip_failure(self) -> None:
        tr = ToolResult(call_id="call-rt-err", success=False, error="timed out")
        data = tr.model_dump()
        restored = ToolResult.model_validate(data)
        assert restored.success is False
        assert restored.error == "timed out"
