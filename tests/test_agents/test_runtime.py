"""Tests for AgentRuntime — the core agent turn loop."""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock

import pytest

from openrattler.agents.providers.base import LLMProvider, LLMResponse, TokenUsage
from openrattler.agents.runtime import AgentRuntime, _MAX_TOOL_LOOPS
from openrattler.models.agents import AgentConfig, TrustLevel
from openrattler.models.messages import MessageAttachment, UniversalMessage, create_message
from openrattler.models.sessions import Session
from openrattler.models.tools import ToolCall, ToolDefinition
from openrattler.storage.audit import AuditLog
from openrattler.storage.memory import MemoryStore
from openrattler.storage.transcripts import TranscriptStore
from openrattler.storage.usage import UsageStore
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
    usage_store: UsageStore | None = None,
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
        usage_store=usage_store,
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


# ---------------------------------------------------------------------------
# process_message — token usage recording
# ---------------------------------------------------------------------------


class TestUsageRecording:
    async def test_no_tools_writes_one_record_with_llm_calls_one(self, tmp_path: Path) -> None:
        store = UsageStore(tmp_path / "usage" / "usage_log.jsonl")
        runtime = _make_runtime(
            tmp_path,
            _mock_provider(_text_response("hi")),
            usage_store=store,
        )
        session = await runtime.initialize_session(_SESSION)
        await runtime.process_message(session, _user_msg())

        records = await store.load_since(datetime(2000, 1, 1, tzinfo=timezone.utc))
        assert len(records) == 1
        print(f"[test] llm_calls={records[0].llm_calls}, tool_calls={records[0].tool_calls}")
        assert records[0].llm_calls == 1
        assert records[0].tool_calls == []

    async def test_two_tool_calls_recorded_in_tool_calls_list(self, tmp_path: Path) -> None:
        async def handler_a(**kwargs: object) -> str:
            return "a"

        async def handler_b(**kwargs: object) -> str:
            return "b"

        td_a = ToolDefinition(
            name="tool_a",
            description="",
            parameters={},
            trust_level_required=TrustLevel.main,
        )
        td_b = ToolDefinition(
            name="tool_b",
            description="",
            parameters={},
            trust_level_required=TrustLevel.main,
        )

        # First response has two tool calls in a single loop; second response is final.
        first_response = LLMResponse(
            content="",
            tool_calls=[
                ToolCall(tool_name="tool_a", arguments={}, call_id="c1"),
                ToolCall(tool_name="tool_b", arguments={}, call_id="c2"),
            ],
            usage=_usage(),
            model="test-model",
            finish_reason="tool_calls",
        )
        store = UsageStore(tmp_path / "usage" / "usage_log.jsonl")
        runtime = _make_runtime(
            tmp_path,
            _mock_provider(first_response, _text_response("done")),
            extra_tools=[(td_a, handler_a), (td_b, handler_b)],
            allowed_tools=["tool_a", "tool_b"],
            usage_store=store,
        )
        session = await runtime.initialize_session(_SESSION)
        await runtime.process_message(session, _user_msg())

        records = await store.load_since(datetime(2000, 1, 1, tzinfo=timezone.utc))
        assert len(records) == 1
        print(f"[test] tool_calls={records[0].tool_calls}")
        assert records[0].tool_calls == ["tool_a", "tool_b"]

    async def test_multi_loop_accumulates_prompt_tokens(self, tmp_path: Path) -> None:
        async def handler(**kwargs: object) -> str:
            return "ok"

        td = ToolDefinition(
            name="looper",
            description="",
            parameters={},
            trust_level_required=TrustLevel.main,
        )

        # Two tool loops: initial call + loop1 call + final (no-tool) call = 3 total calls.
        # Each call has 10 prompt_tokens → expected total = 30.
        provider = _mock_provider(
            _tool_response("looper", {}, "c1"),
            _tool_response("looper", {}, "c2"),
            _text_response("done"),
        )
        store = UsageStore(tmp_path / "usage" / "usage_log.jsonl")
        runtime = _make_runtime(
            tmp_path,
            provider,
            extra_tools=[(td, handler)],
            allowed_tools=["looper"],
            usage_store=store,
        )
        session = await runtime.initialize_session(_SESSION)
        await runtime.process_message(session, _user_msg())

        records = await store.load_since(datetime(2000, 1, 1, tzinfo=timezone.utc))
        assert len(records) == 1
        print(
            f"[test] llm_calls={records[0].llm_calls}, " f"prompt_tokens={records[0].prompt_tokens}"
        )
        assert records[0].llm_calls == 3
        assert records[0].prompt_tokens == 30  # 3 calls × 10 tokens each

    async def test_usage_store_none_no_record_no_error(self, tmp_path: Path) -> None:
        runtime = _make_runtime(
            tmp_path,
            _mock_provider(_text_response("ok")),
            usage_store=None,
        )
        session = await runtime.initialize_session(_SESSION)
        result = await runtime.process_message(session, _user_msg())
        # Response returned normally — no crash because usage_store is None.
        assert result.type == "response"

    async def test_usage_store_failure_does_not_affect_response(self, tmp_path: Path) -> None:
        broken_store = MagicMock(spec=UsageStore)
        broken_store.record_turn = AsyncMock(side_effect=RuntimeError("disk full"))

        runtime = _make_runtime(
            tmp_path,
            _mock_provider(_text_response("ok")),
            usage_store=broken_store,
        )
        session = await runtime.initialize_session(_SESSION)
        result = await runtime.process_message(session, _user_msg())
        print(f"[test] result.type={result.type}")
        assert result.type == "response"
        assert result.params["content"] == "ok"

    async def test_turn_number_increments_across_two_turns(self, tmp_path: Path) -> None:
        store = UsageStore(tmp_path / "usage" / "usage_log.jsonl")
        runtime = _make_runtime(
            tmp_path,
            _mock_provider(_text_response("first"), _text_response("second")),
            usage_store=store,
        )
        session = await runtime.initialize_session(_SESSION)
        await runtime.process_message(session, _user_msg("turn1"))
        await runtime.process_message(session, _user_msg("turn2"))

        records = await store.load_since(datetime(2000, 1, 1, tzinfo=timezone.utc))
        assert len(records) == 2
        turn_numbers = [r.turn_number for r in records]
        print(f"[test] turn_numbers={turn_numbers}")
        assert turn_numbers == [1, 2]


# ---------------------------------------------------------------------------
# process_message — tool_allowlist (46.2)
# ---------------------------------------------------------------------------


class TestToolAllowlist:
    """Verifies that tool_allowlist restricts the tools parameter in the LLM API call."""

    async def test_without_allowlist_sends_all_permitted_tools(self, tmp_path: Path) -> None:
        """When no allowlist is passed, all allowed tools appear in the API tools parameter."""
        td_a = ToolDefinition(
            name="tool_alpha", description="", parameters={}, trust_level_required=TrustLevel.main
        )
        td_b = ToolDefinition(
            name="tool_beta", description="", parameters={}, trust_level_required=TrustLevel.main
        )

        async def handler(**kwargs: object) -> str:
            return "ok"

        provider = _mock_provider(_text_response("done"))
        runtime = _make_runtime(
            tmp_path,
            provider,
            extra_tools=[(td_a, handler), (td_b, handler)],
            allowed_tools=["tool_alpha", "tool_beta"],
        )
        session = await runtime.initialize_session(_SESSION)
        await runtime.process_message(session, _user_msg())

        tools_sent = provider.complete.call_args.kwargs["tools"]
        assert tools_sent is not None
        names = {t["function"]["name"] for t in tools_sent}
        print(f"[test] tools_sent_names={names}")
        assert "tool_alpha" in names
        assert "tool_beta" in names

    async def test_with_allowlist_sends_only_listed_tool(self, tmp_path: Path) -> None:
        """When tool_allowlist=["tool_alpha"], only tool_alpha appears in the API tools parameter."""
        td_a = ToolDefinition(
            name="tool_alpha", description="", parameters={}, trust_level_required=TrustLevel.main
        )
        td_b = ToolDefinition(
            name="tool_beta", description="", parameters={}, trust_level_required=TrustLevel.main
        )

        async def handler(**kwargs: object) -> str:
            return "ok"

        provider = _mock_provider(_text_response("done"))
        runtime = _make_runtime(
            tmp_path,
            provider,
            extra_tools=[(td_a, handler), (td_b, handler)],
            allowed_tools=["tool_alpha", "tool_beta"],
        )
        session = await runtime.initialize_session(_SESSION)
        await runtime.process_message(session, _user_msg(), tool_allowlist=["tool_alpha"])

        tools_sent = provider.complete.call_args.kwargs["tools"]
        assert tools_sent is not None
        names = {t["function"]["name"] for t in tools_sent}
        print(f"[test] tools_sent_names={names}")
        assert "tool_alpha" in names
        assert "tool_beta" not in names

    async def test_allowlist_does_not_affect_executor_permissions(self, tmp_path: Path) -> None:
        """A tool excluded from tool_allowlist can still be executed if called by the LLM."""
        executed: list[str] = []

        async def handler(**kwargs: object) -> str:
            executed.append("tool_beta_ran")
            return "beta-result"

        td_b = ToolDefinition(
            name="tool_beta", description="", parameters={}, trust_level_required=TrustLevel.main
        )
        # The LLM calls tool_beta even though tool_allowlist excluded it from the tools param.
        provider = _mock_provider(
            _tool_response("tool_beta", {}, "c1"),
            _text_response("done"),
        )
        runtime = _make_runtime(
            tmp_path,
            provider,
            extra_tools=[(td_b, handler)],
            allowed_tools=["tool_beta"],
        )
        session = await runtime.initialize_session(_SESSION)
        # Exclude tool_beta from the tools parameter — but execution still succeeds.
        await runtime.process_message(session, _user_msg(), tool_allowlist=["tool_beta"])
        print(f"[test] executed={executed}")
        assert "tool_beta_ran" in executed

    async def test_empty_allowlist_uses_all_permitted_tools(self, tmp_path: Path) -> None:
        """An empty list is treated as 'no restriction' — all permitted tools are sent."""
        td_a = ToolDefinition(
            name="tool_alpha", description="", parameters={}, trust_level_required=TrustLevel.main
        )

        async def handler(**kwargs: object) -> str:
            return "ok"

        provider = _mock_provider(_text_response("done"))
        runtime = _make_runtime(
            tmp_path,
            provider,
            extra_tools=[(td_a, handler)],
            allowed_tools=["tool_alpha"],
        )
        session = await runtime.initialize_session(_SESSION)
        # Empty list → treated as None in _build_tool_defs → all permitted tools sent.
        await runtime.process_message(session, _user_msg(), tool_allowlist=[])

        tools_sent = provider.complete.call_args.kwargs["tools"]
        assert tools_sent is not None
        names = {t["function"]["name"] for t in tools_sent}
        print(f"[test] tools_sent_names={names}")
        assert "tool_alpha" in names


# ---------------------------------------------------------------------------
# _build_messages -- image attachment content blocks (Sub-step 4)
# ---------------------------------------------------------------------------


def _make_attachment_msg(content: str = "look at this", channel="slack"):
    from openrattler.models.messages import MessageAttachment

    att = MessageAttachment(
        attachment_id="att-1",
        media_type="image/jpeg",
        data="abc123base64==",
        size_bytes=100,
        sha256="deadbeef" * 8,
        origin_channel="slack",
        declared_by_sender="U123",
        received_at=datetime.now(timezone.utc),
    )
    return create_message(
        from_agent="user",
        to_agent=_SESSION,
        session_key=_SESSION,
        type="request",
        operation="chat",
        trust_level="main",
        channel=channel,
        params={"content": content},
        attachments=[att],
    )


def _make_session_with_history(msgs):
    from openrattler.models.sessions import Session

    return Session(key=_SESSION, agent_id=_SESSION, history=msgs, system_prompt="")


class TestBuildMessagesWithAttachments:
    def test_text_only_produces_string_content(self, tmp_path):
        runtime = _make_runtime(tmp_path, _mock_provider())
        msg = _user_msg("hello world")
        session = _make_session_with_history([msg])
        built = runtime._build_messages(session)
        user_msg = next(m for m in built if m["role"] == "user")
        assert isinstance(user_msg["content"], str)
        assert "hello world" in user_msg["content"]
        print("[OK] text-only message produces string content")

    def test_attachment_produces_list_content(self, tmp_path):
        runtime = _make_runtime(tmp_path, _mock_provider())
        msg = _make_attachment_msg()
        session = _make_session_with_history([msg])
        built = runtime._build_messages(session)
        user_msg = next(m for m in built if m["role"] == "user")
        assert isinstance(user_msg["content"], list)
        print("[OK] message with attachment produces list content")

    def test_image_block_comes_before_text_block(self, tmp_path):
        runtime = _make_runtime(tmp_path, _mock_provider())
        msg = _make_attachment_msg()
        session = _make_session_with_history([msg])
        built = runtime._build_messages(session)
        user_msg = next(m for m in built if m["role"] == "user")
        blocks = user_msg["content"]
        assert isinstance(blocks, list)
        assert blocks[0]["type"] == "image"
        assert blocks[-1]["type"] == "text"
        print("[OK] image block comes before text block")

    def test_image_block_has_correct_base64_source(self, tmp_path):
        runtime = _make_runtime(tmp_path, _mock_provider())
        msg = _make_attachment_msg()
        session = _make_session_with_history([msg])
        built = runtime._build_messages(session)
        user_msg = next(m for m in built if m["role"] == "user")
        image_block = user_msg["content"][0]
        assert image_block["source"]["type"] == "base64"
        assert image_block["source"]["media_type"] == "image/jpeg"
        assert image_block["source"]["data"] == "abc123base64=="
        print("[OK] image block has correct base64 source fields")

    def test_two_attachments_produce_two_image_blocks(self, tmp_path):
        runtime = _make_runtime(tmp_path, _mock_provider())
        att1 = MessageAttachment(
            attachment_id="att-1",
            media_type="image/jpeg",
            data="data1==",
            size_bytes=100,
            sha256="a" * 64,
            origin_channel="slack",
            declared_by_sender="U1",
            received_at=datetime.now(timezone.utc),
        )
        att2 = MessageAttachment(
            attachment_id="att-2",
            media_type="image/png",
            data="data2==",
            size_bytes=200,
            sha256="b" * 64,
            origin_channel="slack",
            declared_by_sender="U1",
            received_at=datetime.now(timezone.utc),
        )
        msg = create_message(
            from_agent="user",
            to_agent=_SESSION,
            session_key=_SESSION,
            type="request",
            operation="chat",
            trust_level="main",
            params={"content": "two images"},
            attachments=[att1, att2],
        )
        session = _make_session_with_history([msg])
        built = runtime._build_messages(session)
        user_msg = next(m for m in built if m["role"] == "user")
        blocks = user_msg["content"]
        image_blocks = [b for b in blocks if b["type"] == "image"]
        text_blocks = [b for b in blocks if b["type"] == "text"]
        assert len(image_blocks) == 2
        assert len(text_blocks) == 1
        print("[OK] two attachments produce two image blocks and one text block")

    def test_standing_note_in_text_block_when_attachment(self, tmp_path):
        runtime = _make_runtime(tmp_path, _mock_provider())
        msg = _make_attachment_msg(content="here is my photo")
        session = _make_session_with_history([msg])
        built = runtime._build_messages(session)
        user_msg = next(m for m in built if m["role"] == "user")
        text_block = next(b for b in user_msg["content"] if b["type"] == "text")
        assert "Verified image" in text_block["text"]
        assert "here is my photo" in text_block["text"]
        print("[OK] standing provenance note present in text block")

    def test_no_standing_note_when_no_attachments(self, tmp_path):
        runtime = _make_runtime(tmp_path, _mock_provider())
        msg = _user_msg("just text")
        session = _make_session_with_history([msg])
        built = runtime._build_messages(session)
        user_msg = next(m for m in built if m["role"] == "user")
        assert isinstance(user_msg["content"], str)
        assert "Verified image" not in user_msg["content"]
        print("[OK] no provenance note when message has no attachments")

    def test_channel_prefix_in_text_block_with_attachment(self, tmp_path):
        runtime = _make_runtime(tmp_path, _mock_provider())
        msg = _make_attachment_msg(content="hi", channel="slack")
        session = _make_session_with_history([msg])
        built = runtime._build_messages(session)
        user_msg = next(m for m in built if m["role"] == "user")
        text_block = next(b for b in user_msg["content"] if b["type"] == "text")
        assert "[Channel: slack]" in text_block["text"]
        print("[OK] channel prefix present in text block with attachment")
