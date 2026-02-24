"""Tests for UniversalMessage model and factory helpers."""

from __future__ import annotations

import uuid
from datetime import datetime, timezone

import pytest
from pydantic import ValidationError

from openrattler.models.errors import ErrorCode
from openrattler.models.messages import (
    UniversalMessage,
    create_error,
    create_message,
    create_response,
)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_BASE_KWARGS: dict = dict(
    from_agent="agent:main:main",
    to_agent="mcp:weather-mcp",
    session_key="agent:main:main",
    type="request",
    operation="get_forecast",
    trust_level="main",
)


def _make_message(**overrides: object) -> UniversalMessage:
    kwargs = {**_BASE_KWARGS, **overrides}
    return create_message(**kwargs)  # type: ignore[arg-type]


# ---------------------------------------------------------------------------
# create_message
# ---------------------------------------------------------------------------


class TestCreateMessage:
    def test_valid_message_created(self) -> None:
        msg = _make_message()
        assert msg.from_agent == "agent:main:main"
        assert msg.to_agent == "mcp:weather-mcp"
        assert msg.session_key == "agent:main:main"
        assert msg.type == "request"
        assert msg.operation == "get_forecast"
        assert msg.trust_level == "main"

    def test_message_id_is_valid_uuid(self) -> None:
        msg = _make_message()
        # Should not raise
        parsed = uuid.UUID(msg.message_id)
        assert str(parsed) == msg.message_id

    def test_trace_id_is_valid_uuid_when_auto_generated(self) -> None:
        msg = _make_message()
        parsed = uuid.UUID(msg.trace_id)
        assert str(parsed) == msg.trace_id

    def test_custom_trace_id_is_preserved(self) -> None:
        custom = "trace-abc-123"
        msg = _make_message(trace_id=custom)
        assert msg.trace_id == custom

    def test_timestamp_is_utc_aware(self) -> None:
        msg = _make_message()
        assert msg.timestamp.tzinfo is not None
        assert msg.timestamp.tzinfo == timezone.utc

    def test_default_params_and_metadata_are_empty_dicts(self) -> None:
        msg = _make_message()
        assert msg.params == {}
        assert msg.metadata == {}

    def test_params_and_metadata_are_set(self) -> None:
        msg = _make_message(
            params={"location": "Asheville", "days": 7},
            metadata={"user_intent": "vacation planning"},
        )
        assert msg.params["location"] == "Asheville"
        assert msg.metadata["user_intent"] == "vacation planning"

    def test_requires_approval_defaults_to_false(self) -> None:
        msg = _make_message()
        assert msg.requires_approval is False

    def test_requires_approval_can_be_set_true(self) -> None:
        msg = _make_message(requires_approval=True)
        assert msg.requires_approval is True

    def test_channel_defaults_to_none(self) -> None:
        msg = _make_message()
        assert msg.channel is None

    def test_channel_can_be_set(self) -> None:
        msg = _make_message(channel="sms")
        assert msg.channel == "sms"

    def test_error_defaults_to_none(self) -> None:
        msg = _make_message()
        assert msg.error is None

    def test_each_message_gets_unique_message_id(self) -> None:
        ids = {_make_message().message_id for _ in range(20)}
        assert len(ids) == 20

    def test_each_auto_trace_id_is_unique(self) -> None:
        ids = {_make_message().trace_id for _ in range(20)}
        assert len(ids) == 20


# ---------------------------------------------------------------------------
# Validation — missing required fields
# ---------------------------------------------------------------------------


class TestValidationErrors:
    def test_missing_from_agent_raises(self) -> None:
        with pytest.raises(ValidationError):
            UniversalMessage(
                message_id=str(uuid.uuid4()),
                # from_agent missing
                to_agent="mcp:weather-mcp",
                session_key="agent:main:main",
                type="request",
                operation="get_forecast",
                trust_level="main",
                timestamp=datetime.now(timezone.utc),
                trace_id=str(uuid.uuid4()),
            )

    def test_missing_session_key_raises(self) -> None:
        with pytest.raises(ValidationError):
            UniversalMessage(
                message_id=str(uuid.uuid4()),
                from_agent="agent:main:main",
                to_agent="mcp:weather-mcp",
                # session_key missing
                type="request",
                operation="get_forecast",
                trust_level="main",
                timestamp=datetime.now(timezone.utc),
                trace_id=str(uuid.uuid4()),
            )

    def test_missing_type_raises(self) -> None:
        with pytest.raises(ValidationError):
            UniversalMessage(
                message_id=str(uuid.uuid4()),
                from_agent="agent:main:main",
                to_agent="mcp:weather-mcp",
                session_key="agent:main:main",
                # type missing
                operation="get_forecast",
                trust_level="main",
                timestamp=datetime.now(timezone.utc),
                trace_id=str(uuid.uuid4()),
            )

    def test_invalid_type_value_raises(self) -> None:
        with pytest.raises(ValidationError):
            create_message(**{**_BASE_KWARGS, "type": "unknown"})  # type: ignore[arg-type]

    def test_invalid_trust_level_raises(self) -> None:
        with pytest.raises(ValidationError):
            create_message(**{**_BASE_KWARGS, "trust_level": "admin"})  # type: ignore[arg-type]

    def test_all_trust_levels_are_valid(self) -> None:
        for level in ("public", "main", "local", "security", "mcp"):
            msg = create_message(**{**_BASE_KWARGS, "trust_level": level})  # type: ignore[arg-type]
            assert msg.trust_level == level

    def test_all_message_types_are_valid(self) -> None:
        for msg_type in ("request", "response", "event", "error"):
            msg = create_message(**{**_BASE_KWARGS, "type": msg_type})  # type: ignore[arg-type]
            assert msg.type == msg_type


# ---------------------------------------------------------------------------
# create_response
# ---------------------------------------------------------------------------


class TestCreateResponse:
    def _original(self) -> UniversalMessage:
        return _make_message(trace_id="trace-original-123")

    def test_response_type_is_response(self) -> None:
        original = self._original()
        resp = create_response(original, from_agent="mcp:weather-mcp", trust_level="mcp")
        assert resp.type == "response"

    def test_response_inherits_trace_id(self) -> None:
        original = self._original()
        resp = create_response(original, from_agent="mcp:weather-mcp", trust_level="mcp")
        assert resp.trace_id == original.trace_id

    def test_response_sets_parent_message_id(self) -> None:
        original = self._original()
        resp = create_response(original, from_agent="mcp:weather-mcp", trust_level="mcp")
        assert resp.parent_message_id == original.message_id

    def test_response_routes_to_original_sender(self) -> None:
        original = self._original()
        resp = create_response(original, from_agent="mcp:weather-mcp", trust_level="mcp")
        assert resp.to_agent == original.from_agent

    def test_response_inherits_session_key(self) -> None:
        original = self._original()
        resp = create_response(original, from_agent="mcp:weather-mcp", trust_level="mcp")
        assert resp.session_key == original.session_key

    def test_response_operation_defaults_to_original(self) -> None:
        original = self._original()
        resp = create_response(original, from_agent="mcp:weather-mcp", trust_level="mcp")
        assert resp.operation == original.operation

    def test_response_operation_can_be_overridden(self) -> None:
        original = self._original()
        resp = create_response(
            original,
            from_agent="mcp:weather-mcp",
            trust_level="mcp",
            operation="custom_op",
        )
        assert resp.operation == "custom_op"

    def test_response_has_new_message_id(self) -> None:
        original = self._original()
        resp = create_response(original, from_agent="mcp:weather-mcp", trust_level="mcp")
        assert resp.message_id != original.message_id

    def test_response_channel_inherits_from_original(self) -> None:
        original = _make_message(channel="sms", trace_id="trace-sms-1")
        resp = create_response(original, from_agent="mcp:weather-mcp", trust_level="mcp")
        assert resp.channel == "sms"

    def test_response_channel_can_be_overridden(self) -> None:
        original = _make_message(channel="sms", trace_id="trace-sms-2")
        resp = create_response(
            original, from_agent="mcp:weather-mcp", trust_level="mcp", channel="email"
        )
        assert resp.channel == "email"

    def test_response_params_are_set(self) -> None:
        original = self._original()
        forecast = [{"day": "Monday", "high": 68}]
        resp = create_response(
            original,
            from_agent="mcp:weather-mcp",
            trust_level="mcp",
            params={"forecast": forecast},
        )
        assert resp.params["forecast"] == forecast


# ---------------------------------------------------------------------------
# create_error
# ---------------------------------------------------------------------------


class TestCreateError:
    def _original(self) -> UniversalMessage:
        return _make_message(trace_id="trace-err-456")

    def test_error_type_is_error(self) -> None:
        original = self._original()
        err = create_error(
            original,
            from_agent="agent:main:main",
            trust_level="main",
            code=ErrorCode.PERMISSION_DENIED,
            message="Not allowed",
        )
        assert err.type == "error"

    def test_error_code_is_correct(self) -> None:
        original = self._original()
        err = create_error(
            original,
            from_agent="agent:main:main",
            trust_level="main",
            code=ErrorCode.PERMISSION_DENIED,
            message="Not allowed",
        )
        assert err.error is not None
        assert err.error["code"] == "PERMISSION_DENIED"

    def test_error_message_is_correct(self) -> None:
        original = self._original()
        err = create_error(
            original,
            from_agent="agent:main:main",
            trust_level="main",
            code=ErrorCode.INVALID_PARAMS,
            message="Missing required param: location",
        )
        assert err.error is not None
        assert err.error["message"] == "Missing required param: location"

    def test_error_details_are_included(self) -> None:
        original = self._original()
        err = create_error(
            original,
            from_agent="agent:main:main",
            trust_level="main",
            code=ErrorCode.PERMISSION_DENIED,
            message="Tool not allowed",
            details={"tool": "exec", "session": "agent:main:discord:123"},
        )
        assert err.error is not None
        assert err.error["details"]["tool"] == "exec"

    def test_error_details_default_to_empty_dict(self) -> None:
        original = self._original()
        err = create_error(
            original,
            from_agent="agent:main:main",
            trust_level="main",
            code=ErrorCode.INTERNAL_ERROR,
            message="Unexpected failure",
        )
        assert err.error is not None
        assert err.error["details"] == {}

    def test_error_inherits_trace_id(self) -> None:
        original = self._original()
        err = create_error(
            original,
            from_agent="agent:main:main",
            trust_level="main",
            code=ErrorCode.TIMEOUT,
            message="Timed out",
        )
        assert err.trace_id == original.trace_id

    def test_error_sets_parent_message_id(self) -> None:
        original = self._original()
        err = create_error(
            original,
            from_agent="agent:main:main",
            trust_level="main",
            code=ErrorCode.NOT_FOUND,
            message="Resource not found",
        )
        assert err.parent_message_id == original.message_id

    def test_error_routes_to_original_sender(self) -> None:
        original = self._original()
        err = create_error(
            original,
            from_agent="mcp:some-mcp",
            trust_level="mcp",
            code=ErrorCode.NETWORK_ERROR,
            message="API unreachable",
        )
        assert err.to_agent == original.from_agent

    def test_all_error_codes_are_usable(self) -> None:
        original = self._original()
        for code in ErrorCode:
            err = create_error(
                original,
                from_agent="agent:main:main",
                trust_level="main",
                code=code,
                message=f"Test {code.value}",
            )
            assert err.error is not None
            assert err.error["code"] == code.value


# ---------------------------------------------------------------------------
# Serialisation round-trip
# ---------------------------------------------------------------------------


class TestRoundTrip:
    def test_model_dump_and_validate(self) -> None:
        original = _make_message(
            channel="telegram",
            params={"text": "hello"},
            metadata={"user_id": "42"},
            requires_approval=True,
            trace_id="trace-rt-001",
        )
        data = original.model_dump()
        restored = UniversalMessage.model_validate(data)
        assert restored == original

    def test_json_round_trip(self) -> None:
        original = _make_message(trace_id="trace-rt-002")
        json_str = original.model_dump_json()
        restored = UniversalMessage.model_validate_json(json_str)
        assert restored.message_id == original.message_id
        assert restored.trace_id == original.trace_id
        assert restored.timestamp == original.timestamp

    def test_error_message_round_trip(self) -> None:
        req = _make_message(trace_id="trace-rt-003")
        err = create_error(
            req,
            from_agent="agent:main:main",
            trust_level="main",
            code=ErrorCode.RATE_LIMIT_EXCEEDED,
            message="Too many requests",
            details={"limit": 10, "window": "1m"},
        )
        data = err.model_dump()
        restored = UniversalMessage.model_validate(data)
        assert restored.type == "error"
        assert restored.error is not None
        assert restored.error["code"] == "RATE_LIMIT_EXCEEDED"
