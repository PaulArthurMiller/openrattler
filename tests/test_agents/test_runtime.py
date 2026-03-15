"""Tests for AgentRuntime — the core agent turn loop."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import AsyncMock, MagicMock

import pytest

from openrattler.agents.providers.base import LLMProvider, LLMResponse, TokenUsage
from openrattler.agents.runtime import AgentRuntime, _MAX_TOOL_LOOPS
from openrattler.models.agents import AgentConfig, TrustLevel
from openrattler.models.messages import UniversalMessage, create_message
from openrattler.models.tools import ToolCall, ToolDefinition
from openrattler.storage.audit import AuditLog
from openrattler.storage.memory import MemoryStore
from openrattler.storage.transcripts import TranscriptStore
from openrattler.tools.executor import ToolExecutor
from openrattler.tools.registry import ToolRegistry

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_SESSION = "agent:main:main"


def _usage() -> TokenUsage:
    return TokenUsage(
        prompt_tokens=10, completion_tokens=5, total_tokens=15, estimated_cost_usd=0.0
    )


def _text_response(content: str) -> LLMResponse:
    return LLMResponse(
        content=content, tool_calls=[], usage=_usage(), model="test-model", finish_reason="stop"
    )


def _tool_response(tool_name: str, args: dict, call_id: str = "c1") -> LLMResponse:
    return LLMResponse(
        content="",
        tool_calls=[ToolCall(tool_name=tool_name, arguments=args, call_id=call_id)],
        usage=_usage(),
        model="test-model",
        finish_reason="tool_calls",
    )


def _user_msg(content: str = "hello") -> UniversalMessage:
    return create_message(
        from_agent="user",
        to_agent=_SESSION,
        session_key=_SESSION,
        type="request",
        operation="chat",
        trust_level="main",
        params={"content": content},
    )


def _mock_provider(*responses: LLMResponse) -> LLMProvider:
    provider = MagicMock(spec=LLMProvider)
    provider.complete = AsyncMock(side_effect=list(responses))
    return provider


# ---------------------------------------------------------------------------
# Fixture: build a complete stack for each test
# ---------------------------------------------------------------------------


def _make_runtime(
    tmp_path: Path,
    provider: LLMProvider,
    *,
    extra_tools: list[tuple[ToolDefinition, object]] | None = None,
    allowed_tools: list[str] | None = None,
) -> AgentRuntime:
    reg = ToolRegistry()
    if extra_tools:
        for td, handler in extra_tools:
            reg.register(td, handler)  # type: ignore[arg-type]

    log = AuditLog(tmp_path / "audit.jsonl")
    executor = ToolExecutor(reg, log)

    config = AgentConfig(
        agent_id=_SESSION,
        name="Test",
        description="Test agent",
        model="test-model",
        trust_level=TrustLevel.main,
        allowed_tools=allowed_tools if allowed_tools is not None else [],
        system_prompt="You are a helpful test agent.",
    )

    return AgentRuntime(
        config=config,
        provider=provider,
        tool_executor=executor,
        transcript_store=TranscriptStore(tmp_path / "transcripts"),
        memory_store=MemoryStore(tmp_path / "memory"),
        audit_log=log,
    )


# ---------------------------------------------------------------------------
# initialize_session
# ---------------------------------------------------------------------------


class TestInitializeSession:
    async def test_returns_session_with_correct_key(self, tmp_path: Path) -> None:
        runtime = _make_runtime(tmp_path, _mock_provider())
        session = await runtime.initialize_session(_SESSION)
        assert session.key == _SESSION

    async def test_empty_transcript_gives_empty_history(self, tmp_path: Path) -> None:
        runtime = _make_runtime(tmp_path, _mock_provider())
        session = await runtime.initialize_session(_SESSION)
        assert session.history == []

    async def test_loads_existing_transcript(self, tmp_path: Path) -> None:
        store = TranscriptStore(tmp_path / "transcripts")
        for i in range(3):
            await store.append(_SESSION, _user_msg(f"msg{i}"))

        runtime = _make_runtime(tmp_path, _mock_provider())
        session = await runtime.initialize_session(_SESSION)
        assert len(session.history) == 3

    async def test_system_prompt_built_from_config(self, tmp_path: Path) -> None:
        runtime = _make_runtime(tmp_path, _mock_provider())
        session = await runtime.initialize_session(_SESSION)
        assert "helpful test agent" in session.system_prompt

    async def test_memory_store_not_injected_into_system_prompt(self, tmp_path: Path) -> None:
        # MemoryStore facts are no longer dumped into the system prompt.
        # They are accessed on demand via the memory_read tool.
        mem_store = MemoryStore(tmp_path / "memory")
        await mem_store.save("main", {"user_name": "Alice"})

        runtime = _make_runtime(tmp_path, _mock_provider())
        runtime._memory_store = mem_store

        session = await runtime.initialize_session(_SESSION)
        # "Alice" should NOT appear in the system prompt.
        assert "Alice" not in session.system_prompt

    async def test_agent_id_set_on_session(self, tmp_path: Path) -> None:
        runtime = _make_runtime(tmp_path, _mock_provider())
        session = await runtime.initialize_session(_SESSION)
        assert session.agent_id == _SESSION


# ---------------------------------------------------------------------------
# process_message — simple response (no tools)
# ---------------------------------------------------------------------------


class TestSimpleResponse:
    async def test_returns_response_message(self, tmp_path: Path) -> None:
        runtime = _make_runtime(tmp_path, _mock_provider(_text_response("Hi there!")))
        session = await runtime.initialize_session(_SESSION)
        result = await runtime.process_message(session, _user_msg())
        assert result.type == "response"
        assert result.params["content"] == "Hi there!"

    async def test_response_from_agent_is_runtime_agent_id(self, tmp_path: Path) -> None:
        runtime = _make_runtime(tmp_path, _mock_provider(_text_response("ok")))
        session = await runtime.initialize_session(_SESSION)
        result = await runtime.process_message(session, _user_msg())
        assert result.from_agent == _SESSION

    async def test_trace_id_preserved(self, tmp_path: Path) -> None:
        runtime = _make_runtime(tmp_path, _mock_provider(_text_response("ok")))
        session = await runtime.initialize_session(_SESSION)
        user_msg = _user_msg()
        original_trace = user_msg.trace_id
        result = await runtime.process_message(session, user_msg)
        assert result.trace_id == original_trace

    async def test_provider_called_once_without_tools(self, tmp_path: Path) -> None:
        provider = _mock_provider(_text_response("done"))
        runtime = _make_runtime(tmp_path, provider)
        session = await runtime.initialize_session(_SESSION)
        await runtime.process_message(session, _user_msg())
        assert provider.complete.call_count == 1

    async def test_system_prompt_included_in_llm_call(self, tmp_path: Path) -> None:
        provider = _mock_provider(_text_response("ok"))
        runtime = _make_runtime(tmp_path, provider)
        session = await runtime.initialize_session(_SESSION)
        await runtime.process_message(session, _user_msg("hi"))
        messages = provider.complete.call_args.kwargs["messages"]
        assert messages[0]["role"] == "system"
        assert "helpful test agent" in messages[0]["content"]


# ---------------------------------------------------------------------------
# process_message — transcript persistence
# ---------------------------------------------------------------------------


class TestTranscriptPersistence:
    async def test_user_and_response_appended_to_transcript(self, tmp_path: Path) -> None:
        runtime = _make_runtime(tmp_path, _mock_provider(_text_response("reply")))
        session = await runtime.initialize_session(_SESSION)
        await runtime.process_message(session, _user_msg("hello"))

        store = runtime._transcript_store
        history = await store.load(_SESSION)
        assert len(history) == 2  # user message + assistant response

    async def test_session_history_updated_in_place(self, tmp_path: Path) -> None:
        runtime = _make_runtime(tmp_path, _mock_provider(_text_response("reply")))
        session = await runtime.initialize_session(_SESSION)
        assert len(session.history) == 0
        await runtime.process_message(session, _user_msg("hello"))
        assert len(session.history) == 2


# ---------------------------------------------------------------------------
# process_message — audit logging
# ---------------------------------------------------------------------------


class TestAuditLogging:
    async def test_agent_turn_event_logged(self, tmp_path: Path) -> None:
        runtime = _make_runtime(tmp_path, _mock_provider(_text_response("ok")))
        session = await runtime.initialize_session(_SESSION)
        await runtime.process_message(session, _user_msg())

        events = await runtime._audit.query(event_type="agent_turn")
        assert len(events) == 1

    async def test_audit_event_contains_session_key(self, tmp_path: Path) -> None:
        runtime = _make_runtime(tmp_path, _mock_provider(_text_response("ok")))
        session = await runtime.initialize_session(_SESSION)
        await runtime.process_message(session, _user_msg())

        events = await runtime._audit.query(event_type="agent_turn")
        assert events[0].session_key == _SESSION

    async def test_audit_event_records_tool_loops(self, tmp_path: Path) -> None:
        runtime = _make_runtime(tmp_path, _mock_provider(_text_response("ok")))
        session = await runtime.initialize_session(_SESSION)
        await runtime.process_message(session, _user_msg())

        events = await runtime._audit.query(event_type="agent_turn")
        assert events[0].details["tool_loops"] == 0


# ---------------------------------------------------------------------------
# process_message — tool call → result → final response
# ---------------------------------------------------------------------------


class TestToolCallFlow:
    async def test_tool_call_triggers_tool_execution(self, tmp_path: Path) -> None:
        executed: list[str] = []

        async def handler(**kwargs: object) -> str:
            executed.append("called")
            return "tool-output"

        td = ToolDefinition(
            name="echo",
            description="Echo",
            parameters={},
            trust_level_required=TrustLevel.main,
        )
        provider = _mock_provider(
            _tool_response("echo", {}, "c1"),
            _text_response("All done"),
        )
        runtime = _make_runtime(
            tmp_path,
            provider,
            extra_tools=[(td, handler)],
            allowed_tools=["echo"],
        )
        session = await runtime.initialize_session(_SESSION)
        result = await runtime.process_message(session, _user_msg("do it"))

        assert result.type == "response"
        assert result.params["content"] == "All done"
        assert executed == ["called"]

    async def test_provider_called_twice_for_one_tool_call(self, tmp_path: Path) -> None:
        async def handler(**kwargs: object) -> str:
            return "out"

        td = ToolDefinition(
            name="t",
            description="",
            parameters={},
            trust_level_required=TrustLevel.main,
        )
        provider = _mock_provider(
            _tool_response("t", {}, "c1"),
            _text_response("done"),
        )
        runtime = _make_runtime(
            tmp_path, provider, extra_tools=[(td, handler)], allowed_tools=["t"]
        )
        session = await runtime.initialize_session(_SESSION)
        await runtime.process_message(session, _user_msg())
        assert provider.complete.call_count == 2

    async def test_tool_result_included_in_second_llm_call(self, tmp_path: Path) -> None:
        async def handler(**kwargs: object) -> str:
            return "the-result"

        td = ToolDefinition(
            name="fetch",
            description="",
            parameters={},
            trust_level_required=TrustLevel.main,
        )
        provider = _mock_provider(
            _tool_response("fetch", {}, "call-99"),
            _text_response("done"),
        )
        runtime = _make_runtime(
            tmp_path, provider, extra_tools=[(td, handler)], allowed_tools=["fetch"]
        )
        session = await runtime.initialize_session(_SESSION)
        await runtime.process_message(session, _user_msg())

        # Inspect the second LLM call's messages
        second_call_messages = provider.complete.call_args_list[1].kwargs["messages"]
        tool_result_msgs = [m for m in second_call_messages if m.get("role") == "tool"]
        assert len(tool_result_msgs) == 1
        assert "the-result" in tool_result_msgs[0]["content"]

    async def test_audit_log_records_tool_loop_count(self, tmp_path: Path) -> None:
        async def handler(**kwargs: object) -> str:
            return "ok"

        td = ToolDefinition(
            name="t2",
            description="",
            parameters={},
            trust_level_required=TrustLevel.main,
        )
        provider = _mock_provider(
            _tool_response("t2", {}, "x"),
            _text_response("final"),
        )
        runtime = _make_runtime(
            tmp_path, provider, extra_tools=[(td, handler)], allowed_tools=["t2"]
        )
        session = await runtime.initialize_session(_SESSION)
        await runtime.process_message(session, _user_msg())

        events = await runtime._audit.query(event_type="agent_turn")
        assert events[0].details["tool_loops"] == 1


# ---------------------------------------------------------------------------
# process_message — tool loop safety (max iterations)
# ---------------------------------------------------------------------------


class TestToolLoopSafety:
    async def test_loop_stops_at_max_iterations(self, tmp_path: Path) -> None:
        """Provider always returns a tool call — loop must terminate."""

        async def handler(**kwargs: object) -> str:
            return "ok"

        td = ToolDefinition(
            name="inf",
            description="",
            parameters={},
            trust_level_required=TrustLevel.main,
        )
        # Provide _MAX_TOOL_LOOPS + 1 tool responses (initial + max loop calls)
        responses = [_tool_response("inf", {}, f"c{i}") for i in range(_MAX_TOOL_LOOPS + 1)]
        provider = _mock_provider(*responses)
        runtime = _make_runtime(
            tmp_path, provider, extra_tools=[(td, handler)], allowed_tools=["inf"]
        )
        session = await runtime.initialize_session(_SESSION)
        result = await runtime.process_message(session, _user_msg())

        # Should return an error, not loop forever
        assert result.type == "error"
        assert result.error is not None
        assert "loop" in (result.error.get("message") or "").lower()

    async def test_provider_called_exactly_max_plus_one_times(self, tmp_path: Path) -> None:
        async def handler(**kwargs: object) -> str:
            return "ok"

        td = ToolDefinition(
            name="inf2",
            description="",
            parameters={},
            trust_level_required=TrustLevel.main,
        )
        responses = [_tool_response("inf2", {}, f"c{i}") for i in range(_MAX_TOOL_LOOPS + 1)]
        provider = _mock_provider(*responses)
        runtime = _make_runtime(
            tmp_path, provider, extra_tools=[(td, handler)], allowed_tools=["inf2"]
        )
        session = await runtime.initialize_session(_SESSION)
        await runtime.process_message(session, _user_msg())
        # 1 initial + _MAX_TOOL_LOOPS in-loop = _MAX_TOOL_LOOPS + 1
        assert provider.complete.call_count == _MAX_TOOL_LOOPS + 1

    async def test_exceeded_limit_logged_in_audit(self, tmp_path: Path) -> None:
        async def handler(**kwargs: object) -> str:
            return "ok"

        td = ToolDefinition(
            name="inf3",
            description="",
            parameters={},
            trust_level_required=TrustLevel.main,
        )
        responses = [_tool_response("inf3", {}, f"c{i}") for i in range(_MAX_TOOL_LOOPS + 1)]
        provider = _mock_provider(*responses)
        runtime = _make_runtime(
            tmp_path, provider, extra_tools=[(td, handler)], allowed_tools=["inf3"]
        )
        session = await runtime.initialize_session(_SESSION)
        await runtime.process_message(session, _user_msg())

        events = await runtime._audit.query(event_type="agent_turn")
        assert events[0].details["exceeded_loop_limit"] is True
