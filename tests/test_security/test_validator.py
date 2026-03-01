"""Tests for PitchCatchValidator — the trust-boundary enforcement layer."""

from __future__ import annotations

from pathlib import Path

import pytest

from openrattler.models.agents import TrustLevel
from openrattler.models.messages import UniversalMessage, create_message
from openrattler.security.rate_limiter import RateLimiter
from openrattler.security.validator import PitchCatchValidator
from openrattler.storage.audit import AuditLog

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_SESSION = "agent:main:main"


def _make_validator(
    tmp_path: Path,
    *,
    trust_level: TrustLevel = TrustLevel.main,
    allowed_operations: list[str] | None = None,
    required_params: dict[str, list[str]] | None = None,
    optional_params: dict[str, list[str]] | None = None,
    max_per_minute: int = 60,
    max_per_hour: int = 1000,
) -> PitchCatchValidator:
    log = AuditLog(tmp_path / "audit.jsonl")
    rl = RateLimiter(max_per_minute=max_per_minute, max_per_hour=max_per_hour)
    return PitchCatchValidator(
        component_id="test-component",
        trust_level=trust_level,
        allowed_operations=(
            allowed_operations if allowed_operations is not None else ["chat", "query"]
        ),
        required_params=required_params if required_params is not None else {"chat": ["content"]},
        optional_params=optional_params if optional_params is not None else {"chat": ["context"]},
        rate_limiter=rl,
        audit_log=log,
    )


def _msg(
    operation: str = "chat",
    trust_level: str = "main",
    params: dict | None = None,
    from_agent: str = "user",
) -> UniversalMessage:
    return create_message(
        from_agent=from_agent,
        to_agent="test-component",
        session_key=_SESSION,
        type="request",
        operation=operation,
        trust_level=trust_level,  # type: ignore[arg-type]
        params=params if params is not None else {"content": "hello"},
    )


# ---------------------------------------------------------------------------
# validate_incoming — operation check
# ---------------------------------------------------------------------------


class TestOperationCheck:
    async def test_allowed_operation_passes(self, tmp_path: Path) -> None:
        v = _make_validator(tmp_path)
        result = await v.validate_incoming(_msg(operation="chat"))
        assert result.operation == "chat"

    async def test_disallowed_operation_raises_value_error(self, tmp_path: Path) -> None:
        v = _make_validator(tmp_path)
        with pytest.raises(ValueError, match="not allowed"):
            await v.validate_incoming(_msg(operation="delete"))

    async def test_rejected_operation_logged(self, tmp_path: Path) -> None:
        log = AuditLog(tmp_path / "audit.jsonl")
        rl = RateLimiter(max_per_minute=60, max_per_hour=1000)
        v = PitchCatchValidator(
            component_id="c",
            trust_level=TrustLevel.main,
            allowed_operations=["chat"],
            required_params={},
            optional_params={},
            rate_limiter=rl,
            audit_log=log,
        )
        with pytest.raises(ValueError):
            await v.validate_incoming(_msg(operation="nope"))
        events = await log.query(event_type="message_rejected")
        assert len(events) == 1
        assert "operation_not_allowed" in events[0].details["reason"]


# ---------------------------------------------------------------------------
# validate_incoming — trust level check
# ---------------------------------------------------------------------------


class TestTrustLevelCheck:
    async def test_sufficient_trust_passes(self, tmp_path: Path) -> None:
        v = _make_validator(tmp_path, trust_level=TrustLevel.main)
        result = await v.validate_incoming(_msg(trust_level="main"))
        assert result is not None

    async def test_higher_trust_passes(self, tmp_path: Path) -> None:
        # Component requires main (rank 2); local (rank 3) should pass
        v = _make_validator(tmp_path, trust_level=TrustLevel.main)
        result = await v.validate_incoming(_msg(trust_level="local"))
        assert result is not None

    async def test_lower_trust_raises_permission_error(self, tmp_path: Path) -> None:
        # Component requires main (rank 2); public (rank 0) should fail
        v = _make_validator(tmp_path, trust_level=TrustLevel.main)
        with pytest.raises(PermissionError, match="insufficient"):
            await v.validate_incoming(_msg(trust_level="public"))

    async def test_mcp_insufficient_for_main_component(self, tmp_path: Path) -> None:
        v = _make_validator(tmp_path, trust_level=TrustLevel.main)
        with pytest.raises(PermissionError):
            await v.validate_incoming(_msg(trust_level="mcp"))

    async def test_public_component_accepts_any_trust(self, tmp_path: Path) -> None:
        v = _make_validator(tmp_path, trust_level=TrustLevel.public)
        result = await v.validate_incoming(_msg(trust_level="public"))
        assert result is not None

    async def test_security_same_rank_as_main_passes(self, tmp_path: Path) -> None:
        # security and main share rank 2 — security messages should pass a main component
        v = _make_validator(tmp_path, trust_level=TrustLevel.main)
        result = await v.validate_incoming(_msg(trust_level="security"))
        assert result is not None


# ---------------------------------------------------------------------------
# validate_incoming — required params
# ---------------------------------------------------------------------------


class TestRequiredParams:
    async def test_all_required_params_present_passes(self, tmp_path: Path) -> None:
        v = _make_validator(
            tmp_path,
            required_params={"chat": ["content", "user_id"]},
        )
        result = await v.validate_incoming(_msg(params={"content": "hi", "user_id": "u1"}))
        assert result.params["content"] == "hi"

    async def test_missing_required_param_raises_value_error(self, tmp_path: Path) -> None:
        v = _make_validator(
            tmp_path,
            required_params={"chat": ["content", "user_id"]},
        )
        with pytest.raises(ValueError, match="Missing required parameter"):
            await v.validate_incoming(_msg(params={"content": "hi"}))

    async def test_operation_with_no_required_params_passes(self, tmp_path: Path) -> None:
        v = _make_validator(
            tmp_path,
            required_params={},
            allowed_operations=["ping"],
        )
        result = await v.validate_incoming(_msg(operation="ping", params={}))
        assert result is not None


# ---------------------------------------------------------------------------
# validate_incoming — param stripping (need-to-know)
# ---------------------------------------------------------------------------


class TestParamStripping:
    async def test_extraneous_params_stripped(self, tmp_path: Path) -> None:
        v = _make_validator(
            tmp_path,
            required_params={"chat": ["content"]},
            optional_params={"chat": ["context"]},
        )
        msg = _msg(params={"content": "hi", "context": "bg", "secret": "leak"})
        result = await v.validate_incoming(msg)
        assert "content" in result.params
        assert "context" in result.params
        assert "secret" not in result.params

    async def test_required_params_kept(self, tmp_path: Path) -> None:
        v = _make_validator(tmp_path)
        result = await v.validate_incoming(_msg(params={"content": "keep-me"}))
        assert result.params["content"] == "keep-me"

    async def test_optional_params_kept_when_present(self, tmp_path: Path) -> None:
        v = _make_validator(tmp_path)
        result = await v.validate_incoming(_msg(params={"content": "hi", "context": "ctx"}))
        assert result.params["context"] == "ctx"

    async def test_all_params_stripped_when_none_known(self, tmp_path: Path) -> None:
        v = _make_validator(
            tmp_path,
            required_params={},
            optional_params={},
            allowed_operations=["ping"],
        )
        result = await v.validate_incoming(_msg(operation="ping", params={"noise": "value"}))
        assert result.params == {}

    async def test_original_message_params_unmodified(self, tmp_path: Path) -> None:
        """Stripping should not mutate the original message."""
        v = _make_validator(tmp_path)
        msg = _msg(params={"content": "hi", "secret": "leak"})
        original_params = dict(msg.params)
        await v.validate_incoming(msg)
        assert msg.params == original_params


# ---------------------------------------------------------------------------
# validate_incoming — rate limiting
# ---------------------------------------------------------------------------


class TestRateLimiting:
    async def test_request_within_limit_passes(self, tmp_path: Path) -> None:
        v = _make_validator(tmp_path, max_per_minute=5, max_per_hour=100)
        result = await v.validate_incoming(_msg())
        assert result is not None

    async def test_rate_limited_request_raises_permission_error(self, tmp_path: Path) -> None:
        v = _make_validator(tmp_path, max_per_minute=2, max_per_hour=100)
        await v.validate_incoming(_msg())
        await v.validate_incoming(_msg())
        with pytest.raises(PermissionError, match="[Rr]ate limit"):
            await v.validate_incoming(_msg())

    async def test_rate_limit_is_per_sender(self, tmp_path: Path) -> None:
        v = _make_validator(tmp_path, max_per_minute=1, max_per_hour=100)
        await v.validate_incoming(_msg(from_agent="agent-a"))
        # agent-a is at limit; agent-b should still pass
        result = await v.validate_incoming(_msg(from_agent="agent-b"))
        assert result is not None


# ---------------------------------------------------------------------------
# validate_incoming — audit logging
# ---------------------------------------------------------------------------


class TestAuditLogging:
    async def test_successful_validation_logged(self, tmp_path: Path) -> None:
        v = _make_validator(tmp_path)
        await v.validate_incoming(_msg())
        log = AuditLog(tmp_path / "audit.jsonl")
        events = await log.query(event_type="message_validated")
        assert len(events) == 1

    async def test_audit_event_contains_operation(self, tmp_path: Path) -> None:
        v = _make_validator(tmp_path)
        await v.validate_incoming(_msg(operation="chat"))
        log = AuditLog(tmp_path / "audit.jsonl")
        events = await log.query(event_type="message_validated")
        assert events[0].details["operation"] == "chat"

    async def test_rejected_message_logged_as_rejected(self, tmp_path: Path) -> None:
        v = _make_validator(tmp_path)
        with pytest.raises(ValueError):
            await v.validate_incoming(_msg(operation="bad-op"))
        log = AuditLog(tmp_path / "audit.jsonl")
        events = await log.query(event_type="message_rejected")
        assert len(events) == 1


# ---------------------------------------------------------------------------
# structure_outgoing
# ---------------------------------------------------------------------------


class TestStructureOutgoing:
    async def test_returns_universal_message(self, tmp_path: Path) -> None:
        v = _make_validator(tmp_path)
        msg = await v.structure_outgoing(
            operation="chat",
            params={"content": "reply"},
            to_agent="user",
            session_key=_SESSION,
        )
        assert isinstance(msg, UniversalMessage)

    async def test_from_agent_is_component_id(self, tmp_path: Path) -> None:
        v = _make_validator(tmp_path)
        msg = await v.structure_outgoing(
            operation="chat",
            params={},
            to_agent="user",
            session_key=_SESSION,
        )
        assert msg.from_agent == "test-component"

    async def test_trust_level_is_components_level(self, tmp_path: Path) -> None:
        v = _make_validator(tmp_path, trust_level=TrustLevel.main)
        msg = await v.structure_outgoing(
            operation="chat",
            params={},
            to_agent="user",
            session_key=_SESSION,
        )
        assert msg.trust_level == "main"

    async def test_default_type_is_response(self, tmp_path: Path) -> None:
        v = _make_validator(tmp_path)
        msg = await v.structure_outgoing(
            operation="chat",
            params={},
            to_agent="user",
            session_key=_SESSION,
        )
        assert msg.type == "response"

    async def test_custom_type_event(self, tmp_path: Path) -> None:
        v = _make_validator(tmp_path)
        msg = await v.structure_outgoing(
            operation="heartbeat",
            params={},
            to_agent="monitor",
            session_key=_SESSION,
            type="event",
        )
        assert msg.type == "event"

    async def test_trace_id_propagated(self, tmp_path: Path) -> None:
        v = _make_validator(tmp_path)
        msg = await v.structure_outgoing(
            operation="chat",
            params={},
            to_agent="user",
            session_key=_SESSION,
            trace_id="trace-abc",
        )
        assert msg.trace_id == "trace-abc"
