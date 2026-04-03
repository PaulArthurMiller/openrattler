"""Tests for action_levels.py — level registry, dead stop frozenset, DeadStopError.

Covers:
- DEAD_STOP_ACTIONS is immutable (frozenset)
- ACTION_LEVEL_DESCRIPTIONS has exactly keys 1–5
- DeadStopError carries the action name
- All built-in tool ToolDefinitions have action_level in range 1–5
"""

from __future__ import annotations

import pytest

from openrattler.security.action_levels import (
    ACTION_LEVEL_DESCRIPTIONS,
    DEAD_STOP_ACTIONS,
    DeadStopError,
)

# ---------------------------------------------------------------------------
# DEAD_STOP_ACTIONS
# ---------------------------------------------------------------------------


def test_dead_stop_actions_is_frozenset() -> None:
    """DEAD_STOP_ACTIONS must be a frozenset so it is immutable at runtime."""
    print(f"DEAD_STOP_ACTIONS type: {type(DEAD_STOP_ACTIONS)}")
    assert isinstance(DEAD_STOP_ACTIONS, frozenset)


def test_dead_stop_actions_cannot_be_mutated() -> None:
    """Confirm frozenset raises AttributeError on attempted mutation."""
    with pytest.raises(AttributeError):
        DEAD_STOP_ACTIONS.add("new_action")  # type: ignore[attr-defined]


def test_dead_stop_actions_contains_expected_entries() -> None:
    """Verify the initial set of dead-stop action names are present."""
    expected = {"force_push_main", "drop_table", "rm_workspace_recursive"}
    print(f"DEAD_STOP_ACTIONS: {DEAD_STOP_ACTIONS}")
    assert expected.issubset(DEAD_STOP_ACTIONS)


# ---------------------------------------------------------------------------
# ACTION_LEVEL_DESCRIPTIONS
# ---------------------------------------------------------------------------


def test_action_level_descriptions_has_exactly_keys_1_to_5() -> None:
    """Keys must be exactly the integers 1, 2, 3, 4, 5 — no more, no fewer."""
    print(f"ACTION_LEVEL_DESCRIPTIONS keys: {sorted(ACTION_LEVEL_DESCRIPTIONS.keys())}")
    assert set(ACTION_LEVEL_DESCRIPTIONS.keys()) == {1, 2, 3, 4, 5}


def test_action_level_descriptions_values_are_non_empty_strings() -> None:
    """Every level must have a non-empty human-readable description."""
    for level, desc in ACTION_LEVEL_DESCRIPTIONS.items():
        print(f"Level {level}: {desc!r}")
        assert isinstance(desc, str)
        assert len(desc.strip()) > 0, f"Level {level} has an empty description"


# ---------------------------------------------------------------------------
# DeadStopError
# ---------------------------------------------------------------------------


def test_dead_stop_error_carries_action_name() -> None:
    """DeadStopError.action must equal the name passed to the constructor."""
    action = "force_push_main"
    err = DeadStopError(action)
    print(f"DeadStopError: {err}")
    assert err.action == action


def test_dead_stop_error_is_exception_subclass() -> None:
    """DeadStopError must be raisable and catchable as an Exception."""
    with pytest.raises(DeadStopError) as exc_info:
        raise DeadStopError("drop_table")
    assert exc_info.value.action == "drop_table"


def test_dead_stop_error_message_contains_action_name() -> None:
    """The error message must include the action name for audit log readability."""
    action = "rm_workspace_recursive"
    err = DeadStopError(action)
    print(f"Error message: {str(err)!r}")
    assert action in str(err)


# ---------------------------------------------------------------------------
# Built-in tool action_level annotations
# ---------------------------------------------------------------------------


def test_tool_definition_default_action_level_is_5() -> None:
    """ToolDefinition defaults to action_level=5 (safest) when not specified."""
    from openrattler.models.agents import TrustLevel
    from openrattler.models.tools import ToolDefinition

    td = ToolDefinition(
        name="test_tool",
        description="A test tool",
        parameters={"type": "object", "properties": {}, "required": []},
        trust_level_required=TrustLevel.main,
    )
    print(f"Default action_level: {td.action_level}")
    assert td.action_level == 5


def _collect_builtin_tool_definitions() -> list[tuple[str, int]]:
    """Import all built-in tool modules and collect (tool_name, action_level) pairs.

    Returns a list covering all ToolDefinitions produced by:
    - file_ops.py  (via @tool decorator, checked via _tool_definition attribute)
    - session_tools.py (via @tool decorator)
    - channel_tools.py (via ToolDefinition constructor in register_all)
    - memory_tools.py (via ToolDefinition constructor in register_all)
    """
    results: list[tuple[str, int]] = []

    # --- file_ops ---
    from openrattler.tools.builtin import (
        file_ops,
    )  # noqa: F401 (side-effect: attaches _tool_definition)

    for fn_name in ("file_read", "file_write", "file_list"):
        fn = getattr(file_ops, fn_name)
        td = fn._tool_definition
        results.append((td.name, td.action_level))
        print(f"file_ops.{fn_name}: action_level={td.action_level}")

    # --- session_tools ---
    from openrattler.tools.builtin import session_tools  # noqa: F401

    fn = session_tools.sessions_history
    td = fn._tool_definition
    results.append((td.name, td.action_level))
    print(f"session_tools.sessions_history: action_level={td.action_level}")

    # --- channel_tools + memory_tools: need a real registry to capture definitions ---
    from unittest.mock import MagicMock

    from openrattler.config.loader import MemoryConfig, OutboundChannelConfig
    from openrattler.tools.registry import ToolRegistry

    # channel_tools
    from openrattler.tools.builtin.channel_tools import OutboundChannelTools

    mock_audit = MagicMock()
    # Provide mock adapters for all three channels so all three tools are registered.
    mock_sms = MagicMock()
    mock_sms._from_number = "+10000000000"
    mock_sms._sender_allowlist = ["+10000000000"]
    mock_sms._default_to_number = "+10000000000"
    mock_slack = MagicMock()
    mock_slack._channel_id = "#general"
    mock_email = MagicMock()
    mock_email._sender_allowlist = ["test@example.com"]
    mock_email._default_to_address = "test@example.com"

    # OutboundChannelTools uses isinstance checks — patch adapter class names.
    from openrattler.channels import email_adapter, slack_adapter, sms_adapter

    mock_sms.__class__ = sms_adapter.SMSAdapter
    mock_slack.__class__ = slack_adapter.SlackAdapter
    mock_email.__class__ = email_adapter.EmailAdapter

    channel_adapters = {"sms": mock_sms, "slack": mock_slack, "email": mock_email}
    outbound_cfg = OutboundChannelConfig(sms_enabled=True, slack_enabled=True, email_enabled=True)
    channel_tools = OutboundChannelTools(channel_adapters, mock_audit, outbound_cfg)
    channel_registry = ToolRegistry()
    channel_tools.register_all(channel_registry)
    for td in channel_registry.list_tools():
        results.append((td.name, td.action_level))
        print(f"channel_tools.{td.name}: action_level={td.action_level}")

    # memory_tools
    from openrattler.tools.builtin.memory_tools import NarrativeMemoryTools
    from pathlib import Path
    import tempfile

    with tempfile.TemporaryDirectory() as tmpdir:
        mock_security = MagicMock()
        mem_tools = NarrativeMemoryTools(
            identity_dir=Path(tmpdir),
            memory_config=MemoryConfig(),
            security_agent=mock_security,
            audit=mock_audit,
            memory_store=MagicMock(),  # enables memory_read / memory_write
        )
        mem_registry = ToolRegistry()
        mem_tools.register_all(mem_registry)
        for td in mem_registry.list_tools():
            results.append((td.name, td.action_level))
            print(f"memory_tools.{td.name}: action_level={td.action_level}")

    return results


def test_all_builtin_tools_have_action_level_in_range() -> None:
    """Every built-in tool must have action_level in the valid range 1–5."""
    definitions = _collect_builtin_tool_definitions()
    assert len(definitions) > 0, "No tool definitions collected — import or setup failure"
    for name, level in definitions:
        assert (
            1 <= level <= 5
        ), f"Tool '{name}' has action_level={level}, which is outside the valid range 1–5"


def test_specific_tool_action_levels() -> None:
    """Verify the action levels assigned in the build plan are correct."""
    definitions = dict(_collect_builtin_tool_definitions())
    print(f"All tool action levels: {definitions}")

    # channel_tools
    assert definitions["send_email"] == 1, "send_email should be level 1 (has financial cost)"
    assert definitions["send_slack_message"] == 2, "send_slack_message should be level 2"
    assert definitions["send_sms"] == 2, "send_sms should be level 2"

    # file_ops
    assert definitions["file_write"] == 3, "file_write should be level 3 (local state write)"
    assert definitions["file_read"] == 5, "file_read should be level 5 (read-only)"
    assert definitions["file_list"] == 5, "file_list should be level 5 (read-only)"

    # session_tools
    assert (
        definitions["sessions_history"] == 4
    ), "sessions_history should be level 4 (sensitive cross-session read)"

    # memory_tools
    assert definitions["memory_read"] == 5, "memory_read should be level 5 (read-only)"
    assert definitions["memory_write"] == 3, "memory_write should be level 3 (local state write)"
    assert (
        definitions["update_heartbeat"] == 3
    ), "update_heartbeat should be level 3 (local state write)"
