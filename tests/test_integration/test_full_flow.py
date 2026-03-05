"""Integration tests: full message flow from user input to persisted output.

These tests wire every major component together using the ``make_stack``
fixture and a mock LLM provider so no real API calls are made.
"""

from __future__ import annotations

import pytest

from openrattler.models.agents import TrustLevel
from openrattler.models.messages import create_message
from openrattler.models.tools import ToolDefinition
from openrattler.security.rate_limiter import RateLimiter

from tests.conftest import make_mock_provider, make_text_response, make_tool_response

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _user_msg(session_key: str, content: str):
    """Build a minimal request message for integration tests."""
    return create_message(
        from_agent="channel:cli",
        to_agent=session_key,
        session_key=session_key,
        type="request",
        operation="user_message",
        trust_level="main",
        params={"content": content},
    )


# ---------------------------------------------------------------------------
# 1. Text message round-trip
# ---------------------------------------------------------------------------


class TestTextMessageRoundTrip:
    """User sends plain text → runtime processes → response returned."""

    async def test_response_type_and_content(self, make_stack):
        provider = make_mock_provider(make_text_response("Hello!"))
        stack = make_stack(provider)
        session = await stack.runtime.initialize_session("agent:main:main")

        response = await stack.runtime.process_message(session, _user_msg("agent:main:main", "Hi"))

        assert response.type == "response"
        assert response.params["content"] == "Hello!"

    async def test_transcript_has_user_and_assistant_messages(self, make_stack):
        provider = make_mock_provider(make_text_response("Hi back!"))
        stack = make_stack(provider)
        session = await stack.runtime.initialize_session("agent:main:main")

        await stack.runtime.process_message(session, _user_msg("agent:main:main", "Hello"))

        transcript = await stack.transcript_store.load("agent:main:main")
        assert len(transcript) == 2
        assert transcript[0].type == "request"
        assert transcript[1].type == "response"
        assert transcript[1].params["content"] == "Hi back!"

    async def test_agent_turn_audit_event_written(self, make_stack):
        provider = make_mock_provider(make_text_response("Ack"))
        stack = make_stack(provider)
        session = await stack.runtime.initialize_session("agent:main:main")

        await stack.runtime.process_message(session, _user_msg("agent:main:main", "Test"))

        events = await stack.audit_log.query(event_type="agent_turn")
        assert len(events) == 1
        assert events[0].session_key == "agent:main:main"


# ---------------------------------------------------------------------------
# 2. Tool call flow
# ---------------------------------------------------------------------------


class TestToolCallFlow:
    """Provider requests a tool → executor runs it → result fed back → final response."""

    async def test_tool_executed_and_final_response_returned(self, make_stack):
        first_response = make_tool_response("echo", {"text": "ping"}, call_id="call-42")
        second_response = make_text_response("Received: ping")
        provider = make_mock_provider(first_response, second_response)
        stack = make_stack(provider, allowed_tools=["echo"])

        # Register tool after building the stack — the shared registry picks it up.
        tool_def = ToolDefinition(
            name="echo",
            description="Return text unchanged",
            parameters={
                "type": "object",
                "properties": {"text": {"type": "string"}},
                "required": ["text"],
            },
            trust_level_required=TrustLevel.main,
        )

        async def echo_handler(text: str) -> str:
            return text

        stack.tool_registry.register(tool_def, echo_handler)

        session = await stack.runtime.initialize_session("agent:main:main")
        response = await stack.runtime.process_message(
            session, _user_msg("agent:main:main", "Echo ping")
        )

        assert response.type == "response"
        assert response.params["content"] == "Received: ping"

    async def test_successful_tool_execution_audit_logged(self, make_stack):
        first_response = make_tool_response("echo", {"text": "hi"}, call_id="c1")
        second_response = make_text_response("Done")
        provider = make_mock_provider(first_response, second_response)
        stack = make_stack(provider, allowed_tools=["echo"])

        tool_def = ToolDefinition(
            name="echo",
            description="Echo",
            parameters={
                "type": "object",
                "properties": {"text": {"type": "string"}},
                "required": ["text"],
            },
            trust_level_required=TrustLevel.main,
        )
        stack.tool_registry.register(tool_def, lambda text: text)

        session = await stack.runtime.initialize_session("agent:main:main")
        await stack.runtime.process_message(session, _user_msg("agent:main:main", "Echo"))

        events = await stack.audit_log.query(event_type="tool_execution")
        assert len(events) == 1
        assert events[0].details["success"] is True
        assert events[0].details["tool"] == "echo"


# ---------------------------------------------------------------------------
# 3. Tool permission denied → graceful error
# ---------------------------------------------------------------------------


class TestToolPermissionDenied:
    """Executor denies a forbidden tool; runtime continues gracefully."""

    async def test_denied_tool_result_fed_back_to_llm(self, make_stack):
        # Provider first asks for a tool; after receiving the error result it
        # returns a text response — the runtime should not raise.
        first_response = make_tool_response("gated", {}, call_id="cg1")
        second_response = make_text_response("Cannot do that.")
        provider = make_mock_provider(first_response, second_response)
        # allowed_tools is empty → "gated" will be denied
        stack = make_stack(provider, allowed_tools=[])

        tool_def = ToolDefinition(
            name="gated",
            description="Gated tool",
            parameters={"type": "object", "properties": {}, "required": []},
            trust_level_required=TrustLevel.main,
        )
        stack.tool_registry.register(tool_def, lambda: "secret")

        session = await stack.runtime.initialize_session("agent:main:main")
        response = await stack.runtime.process_message(
            session, _user_msg("agent:main:main", "Use gated")
        )

        # Runtime must not raise; it returns the second (text) LLM response.
        assert response.type == "response"
        assert response.params["content"] == "Cannot do that."

    async def test_denied_tool_execution_audit_logged(self, make_stack):
        first_response = make_tool_response("gated", {}, call_id="cg2")
        second_response = make_text_response("Nope")
        provider = make_mock_provider(first_response, second_response)
        stack = make_stack(provider, allowed_tools=[])

        tool_def = ToolDefinition(
            name="gated",
            description="Gated tool",
            parameters={"type": "object", "properties": {}, "required": []},
            trust_level_required=TrustLevel.main,
        )
        stack.tool_registry.register(tool_def, lambda: None)

        session = await stack.runtime.initialize_session("agent:main:main")
        await stack.runtime.process_message(session, _user_msg("agent:main:main", "Use gated"))

        events = await stack.audit_log.query(event_type="tool_execution")
        assert len(events) == 1
        assert events[0].details["success"] is False
        assert "allowed_tools" in events[0].details["error"]


# ---------------------------------------------------------------------------
# 4. Two sessions isolated
# ---------------------------------------------------------------------------


class TestSessionIsolation:
    """Messages and transcripts for different sessions never mix."""

    async def test_transcripts_are_independent(self, make_stack):
        provider = make_mock_provider(
            make_text_response("Reply A"),
            make_text_response("Reply B"),
        )
        stack = make_stack(provider)
        session_a = await stack.runtime.initialize_session("agent:main:sessiona")
        session_b = await stack.runtime.initialize_session("agent:main:sessionb")

        await stack.runtime.process_message(session_a, _user_msg("agent:main:sessiona", "Hello A"))
        await stack.runtime.process_message(session_b, _user_msg("agent:main:sessionb", "Hello B"))

        transcript_a = await stack.transcript_store.load("agent:main:sessiona")
        transcript_b = await stack.transcript_store.load("agent:main:sessionb")

        assert len(transcript_a) == 2
        assert len(transcript_b) == 2
        # Content must not bleed across sessions.
        assert all(m.session_key == "agent:main:sessiona" for m in transcript_a)
        assert all(m.session_key == "agent:main:sessionb" for m in transcript_b)
        assert transcript_a[1].params["content"] == "Reply A"
        assert transcript_b[1].params["content"] == "Reply B"


# ---------------------------------------------------------------------------
# 5. Rate limit triggers
# ---------------------------------------------------------------------------


class TestRateLimitTriggers:
    """RateLimiter blocks requests once the threshold is exceeded."""

    async def test_rate_limit_blocks_after_threshold(self):
        limiter = RateLimiter(max_per_minute=2, max_per_hour=100)
        key = "agent:main:main"

        assert await limiter.check(key) is True
        await limiter.record(key)

        assert await limiter.check(key) is True
        await limiter.record(key)

        # Third check within the same minute must fail.
        assert await limiter.check(key) is False

    async def test_rate_limit_different_keys_independent(self):
        limiter = RateLimiter(max_per_minute=1, max_per_hour=100)

        await limiter.record("agent:main:sessiona")
        # sessiona is exhausted but sessionb is untouched.
        assert await limiter.check("agent:main:sessiona") is False
        assert await limiter.check("agent:main:sessionb") is True
