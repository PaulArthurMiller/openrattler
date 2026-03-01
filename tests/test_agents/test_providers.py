"""Tests for OpenAIProvider and AnthropicProvider.

All tests mock the underlying SDK clients — no real API calls are made and
no API keys are required.
"""

from __future__ import annotations

import json
from unittest.mock import AsyncMock, MagicMock, patch

import httpx
import openai
import anthropic
import pytest

from anthropic.types import Message as AnthropicMessage
from anthropic.types import TextBlock, ToolUseBlock, Usage as AnthropicUsage
from openai.types.chat import ChatCompletion, ChatCompletionMessage
from openai.types.chat.chat_completion import Choice
from openai.types.chat.chat_completion_message_tool_call import (
    ChatCompletionMessageToolCall,
    Function,
)
from openai.types import CompletionUsage

from openrattler.agents.providers.anthropic_provider import (
    AnthropicProvider,
    _convert_messages,
    _convert_tools,
)
from openrattler.agents.providers.base import LLMProvider, LLMResponse, TokenUsage
from openrattler.agents.providers.openai_provider import OpenAIProvider

# ---------------------------------------------------------------------------
# Helpers: build realistic SDK response objects
# ---------------------------------------------------------------------------


def _openai_response(
    content: str = "Hello",
    tool_calls: list[ChatCompletionMessageToolCall] | None = None,
    model: str = "gpt-4o-mini",
    finish_reason: str = "stop",
    prompt_tokens: int = 10,
    completion_tokens: int = 5,
) -> ChatCompletion:
    message = ChatCompletionMessage(
        role="assistant",
        content=content,
        tool_calls=tool_calls,
    )
    choice = Choice(index=0, message=message, finish_reason=finish_reason, logprobs=None)
    usage = CompletionUsage(
        prompt_tokens=prompt_tokens,
        completion_tokens=completion_tokens,
        total_tokens=prompt_tokens + completion_tokens,
    )
    return ChatCompletion(
        id="chatcmpl-test",
        choices=[choice],
        created=1700000000,
        model=model,
        object="chat.completion",
        usage=usage,
    )


def _openai_tool_call(call_id: str, name: str, args: dict) -> ChatCompletionMessageToolCall:
    return ChatCompletionMessageToolCall(
        id=call_id,
        type="function",
        function=Function(name=name, arguments=json.dumps(args)),
    )


def _openai_rate_limit_error() -> openai.RateLimitError:
    resp = httpx.Response(429, request=httpx.Request("POST", "https://api.openai.com/v1/chat"))
    return openai.RateLimitError("rate limited", response=resp, body={})


def _anthropic_response(
    text: str = "Hello",
    tool_uses: list[tuple[str, str, dict]] | None = None,
    model: str = "claude-sonnet-4-6",
    stop_reason: str = "end_turn",
    input_tokens: int = 10,
    output_tokens: int = 5,
) -> AnthropicMessage:
    content: list[TextBlock | ToolUseBlock] = []
    if text:
        content.append(TextBlock(type="text", text=text))
    if tool_uses:
        for tu_id, tu_name, tu_input in tool_uses:
            content.append(ToolUseBlock(type="tool_use", id=tu_id, name=tu_name, input=tu_input))
    return AnthropicMessage(
        id="msg-test",
        content=content,
        model=model,
        role="assistant",
        stop_reason=stop_reason,
        stop_sequence=None,
        type="message",
        usage=AnthropicUsage(input_tokens=input_tokens, output_tokens=output_tokens),
    )


def _anthropic_rate_limit_error() -> anthropic.RateLimitError:
    resp = httpx.Response(
        429, request=httpx.Request("POST", "https://api.anthropic.com/v1/messages")
    )
    return anthropic.RateLimitError(message="rate limited", response=resp, body={})


# ---------------------------------------------------------------------------
# OpenAIProvider tests
# ---------------------------------------------------------------------------


@pytest.fixture
def openai_provider() -> OpenAIProvider:
    return OpenAIProvider(api_key="test-key-do-not-log")


class TestOpenAIProviderInterface:
    def test_is_llm_provider(self, openai_provider: OpenAIProvider) -> None:
        assert isinstance(openai_provider, LLMProvider)


class TestOpenAIProviderComplete:
    async def test_normal_response_parsed(self, openai_provider: OpenAIProvider) -> None:
        openai_provider._client = MagicMock()
        openai_provider._client.chat.completions.create = AsyncMock(
            return_value=_openai_response("Hello, world!")
        )
        result = await openai_provider.complete([{"role": "user", "content": "Hi"}])
        assert isinstance(result, LLMResponse)
        assert result.content == "Hello, world!"
        assert result.tool_calls == []
        assert result.finish_reason == "stop"
        assert result.model == "gpt-4o-mini"

    async def test_empty_content_allowed(self, openai_provider: OpenAIProvider) -> None:
        openai_provider._client = MagicMock()
        openai_provider._client.chat.completions.create = AsyncMock(
            return_value=_openai_response(content="", finish_reason="tool_calls")
        )
        result = await openai_provider.complete([{"role": "user", "content": "run tool"}])
        assert result.content == ""
        assert result.finish_reason == "tool_calls"

    async def test_tool_calls_parsed(self, openai_provider: OpenAIProvider) -> None:
        tc = _openai_tool_call("call-42", "web_search", {"query": "test"})
        openai_provider._client = MagicMock()
        openai_provider._client.chat.completions.create = AsyncMock(
            return_value=_openai_response("", tool_calls=[tc], finish_reason="tool_calls")
        )
        result = await openai_provider.complete([{"role": "user", "content": "search"}])
        assert len(result.tool_calls) == 1
        tc_result = result.tool_calls[0]
        assert tc_result.tool_name == "web_search"
        assert tc_result.arguments == {"query": "test"}
        assert tc_result.call_id == "call-42"

    async def test_multiple_tool_calls_parsed(self, openai_provider: OpenAIProvider) -> None:
        tcs = [
            _openai_tool_call("c1", "tool_a", {"x": 1}),
            _openai_tool_call("c2", "tool_b", {"y": 2}),
        ]
        openai_provider._client = MagicMock()
        openai_provider._client.chat.completions.create = AsyncMock(
            return_value=_openai_response("", tool_calls=tcs)
        )
        result = await openai_provider.complete([{"role": "user", "content": "go"}])
        assert len(result.tool_calls) == 2
        assert {tc.tool_name for tc in result.tool_calls} == {"tool_a", "tool_b"}

    async def test_token_usage_populated(self, openai_provider: OpenAIProvider) -> None:
        openai_provider._client = MagicMock()
        openai_provider._client.chat.completions.create = AsyncMock(
            return_value=_openai_response(prompt_tokens=100, completion_tokens=50)
        )
        result = await openai_provider.complete([{"role": "user", "content": "Hi"}])
        assert isinstance(result.usage, TokenUsage)
        assert result.usage.prompt_tokens == 100
        assert result.usage.completion_tokens == 50
        assert result.usage.total_tokens == 150
        assert result.usage.estimated_cost_usd >= 0.0

    async def test_model_override(self, openai_provider: OpenAIProvider) -> None:
        openai_provider._client = MagicMock()
        mock_create = AsyncMock(return_value=_openai_response(model="gpt-4o"))
        openai_provider._client.chat.completions.create = mock_create
        result = await openai_provider.complete([{"role": "user", "content": "Hi"}], model="gpt-4o")
        assert result.model == "gpt-4o"
        call_kwargs = mock_create.call_args.kwargs
        assert call_kwargs["model"] == "gpt-4o"

    async def test_tools_passed_to_api(self, openai_provider: OpenAIProvider) -> None:
        openai_provider._client = MagicMock()
        mock_create = AsyncMock(return_value=_openai_response())
        openai_provider._client.chat.completions.create = mock_create
        tools = [{"type": "function", "function": {"name": "f", "description": "d"}}]
        await openai_provider.complete([{"role": "user", "content": "Hi"}], tools=tools)
        assert "tools" in mock_create.call_args.kwargs

    async def test_no_tools_omits_tools_key(self, openai_provider: OpenAIProvider) -> None:
        openai_provider._client = MagicMock()
        mock_create = AsyncMock(return_value=_openai_response())
        openai_provider._client.chat.completions.create = mock_create
        await openai_provider.complete([{"role": "user", "content": "Hi"}])
        assert "tools" not in mock_create.call_args.kwargs


class TestOpenAIProviderRetry:
    async def test_rate_limit_triggers_retry(self, openai_provider: OpenAIProvider) -> None:
        openai_provider._client = MagicMock()
        openai_provider._client.chat.completions.create = AsyncMock(
            side_effect=[_openai_rate_limit_error(), _openai_response("retried")]
        )
        with patch("asyncio.sleep", new_callable=AsyncMock):
            result = await openai_provider.complete([{"role": "user", "content": "Hi"}])
        assert result.content == "retried"
        assert openai_provider._client.chat.completions.create.call_count == 2

    async def test_rate_limit_raises_after_max_retries(
        self, openai_provider: OpenAIProvider
    ) -> None:
        openai_provider._client = MagicMock()
        openai_provider._client.chat.completions.create = AsyncMock(
            side_effect=[_openai_rate_limit_error()] * 4
        )
        with patch("asyncio.sleep", new_callable=AsyncMock):
            with pytest.raises(openai.RateLimitError):
                await openai_provider.complete([{"role": "user", "content": "Hi"}])
        assert openai_provider._client.chat.completions.create.call_count == 4


class TestOpenAIProviderHealthCheck:
    async def test_health_check_true_when_api_works(self, openai_provider: OpenAIProvider) -> None:
        openai_provider._client = MagicMock()
        openai_provider._client.models.list = AsyncMock(return_value=MagicMock())
        assert await openai_provider.health_check() is True

    async def test_health_check_false_on_error(self, openai_provider: OpenAIProvider) -> None:
        openai_provider._client = MagicMock()
        openai_provider._client.models.list = AsyncMock(side_effect=Exception("connection refused"))
        assert await openai_provider.health_check() is False


# ---------------------------------------------------------------------------
# AnthropicProvider tests
# ---------------------------------------------------------------------------


@pytest.fixture
def anthropic_provider() -> AnthropicProvider:
    return AnthropicProvider(api_key="test-key-do-not-log")


class TestAnthropicProviderInterface:
    def test_is_llm_provider(self, anthropic_provider: AnthropicProvider) -> None:
        assert isinstance(anthropic_provider, LLMProvider)


class TestAnthropicProviderComplete:
    async def test_normal_response_parsed(self, anthropic_provider: AnthropicProvider) -> None:
        anthropic_provider._client = MagicMock()
        anthropic_provider._client.messages.create = AsyncMock(
            return_value=_anthropic_response("Hello from Claude")
        )
        result = await anthropic_provider.complete([{"role": "user", "content": "Hi"}])
        assert isinstance(result, LLMResponse)
        assert result.content == "Hello from Claude"
        assert result.tool_calls == []
        assert result.finish_reason == "end_turn"

    async def test_tool_calls_parsed(self, anthropic_provider: AnthropicProvider) -> None:
        anthropic_provider._client = MagicMock()
        anthropic_provider._client.messages.create = AsyncMock(
            return_value=_anthropic_response(
                text="",
                tool_uses=[("tu-1", "file_read", {"path": "/tmp/f.txt"})],
                stop_reason="tool_use",
            )
        )
        result = await anthropic_provider.complete([{"role": "user", "content": "read file"}])
        assert len(result.tool_calls) == 1
        tc = result.tool_calls[0]
        assert tc.tool_name == "file_read"
        assert tc.arguments == {"path": "/tmp/f.txt"}
        assert tc.call_id == "tu-1"
        assert result.finish_reason == "tool_use"

    async def test_multiple_tool_calls_parsed(self, anthropic_provider: AnthropicProvider) -> None:
        anthropic_provider._client = MagicMock()
        anthropic_provider._client.messages.create = AsyncMock(
            return_value=_anthropic_response(
                text="",
                tool_uses=[
                    ("tu-1", "search", {"query": "a"}),
                    ("tu-2", "fetch", {"url": "http://x"}),
                ],
            )
        )
        result = await anthropic_provider.complete([{"role": "user", "content": "go"}])
        assert len(result.tool_calls) == 2

    async def test_token_usage_populated(self, anthropic_provider: AnthropicProvider) -> None:
        anthropic_provider._client = MagicMock()
        anthropic_provider._client.messages.create = AsyncMock(
            return_value=_anthropic_response(input_tokens=80, output_tokens=40)
        )
        result = await anthropic_provider.complete([{"role": "user", "content": "Hi"}])
        assert result.usage.prompt_tokens == 80
        assert result.usage.completion_tokens == 40
        assert result.usage.total_tokens == 120
        assert result.usage.estimated_cost_usd >= 0.0

    async def test_system_message_extracted(self, anthropic_provider: AnthropicProvider) -> None:
        anthropic_provider._client = MagicMock()
        mock_create = AsyncMock(return_value=_anthropic_response())
        anthropic_provider._client.messages.create = mock_create
        messages = [
            {"role": "system", "content": "You are helpful."},
            {"role": "user", "content": "Hi"},
        ]
        await anthropic_provider.complete(messages)
        call_kwargs = mock_create.call_args.kwargs
        assert call_kwargs.get("system") == "You are helpful."
        # System message should NOT appear in the messages list
        for msg in call_kwargs["messages"]:
            assert msg.get("role") != "system"

    async def test_model_override(self, anthropic_provider: AnthropicProvider) -> None:
        anthropic_provider._client = MagicMock()
        mock_create = AsyncMock(return_value=_anthropic_response(model="claude-haiku-4-5-20251001"))
        anthropic_provider._client.messages.create = mock_create
        result = await anthropic_provider.complete(
            [{"role": "user", "content": "Hi"}],
            model="claude-haiku-4-5-20251001",
        )
        assert result.model == "claude-haiku-4-5-20251001"


class TestAnthropicProviderRetry:
    async def test_rate_limit_triggers_retry(self, anthropic_provider: AnthropicProvider) -> None:
        anthropic_provider._client = MagicMock()
        anthropic_provider._client.messages.create = AsyncMock(
            side_effect=[_anthropic_rate_limit_error(), _anthropic_response("retried")]
        )
        with patch("asyncio.sleep", new_callable=AsyncMock):
            result = await anthropic_provider.complete([{"role": "user", "content": "Hi"}])
        assert result.content == "retried"
        assert anthropic_provider._client.messages.create.call_count == 2

    async def test_rate_limit_raises_after_max_retries(
        self, anthropic_provider: AnthropicProvider
    ) -> None:
        anthropic_provider._client = MagicMock()
        anthropic_provider._client.messages.create = AsyncMock(
            side_effect=[_anthropic_rate_limit_error()] * 4
        )
        with patch("asyncio.sleep", new_callable=AsyncMock):
            with pytest.raises(anthropic.RateLimitError):
                await anthropic_provider.complete([{"role": "user", "content": "Hi"}])
        assert anthropic_provider._client.messages.create.call_count == 4


class TestAnthropicProviderHealthCheck:
    async def test_health_check_true_when_api_works(
        self, anthropic_provider: AnthropicProvider
    ) -> None:
        anthropic_provider._client = MagicMock()
        anthropic_provider._client.models.list = AsyncMock(return_value=MagicMock())
        assert await anthropic_provider.health_check() is True

    async def test_health_check_false_on_error(self, anthropic_provider: AnthropicProvider) -> None:
        anthropic_provider._client = MagicMock()
        anthropic_provider._client.models.list = AsyncMock(side_effect=Exception("no connection"))
        assert await anthropic_provider.health_check() is False


# ---------------------------------------------------------------------------
# Message / tool conversion helpers
# ---------------------------------------------------------------------------


class TestConvertMessages:
    def test_system_extracted(self) -> None:
        msgs = [{"role": "system", "content": "Be helpful."}, {"role": "user", "content": "Hi"}]
        system, converted = _convert_messages(msgs)
        assert system == "Be helpful."
        assert len(converted) == 1
        assert converted[0]["role"] == "user"

    def test_multiple_system_messages_joined(self) -> None:
        msgs = [
            {"role": "system", "content": "Part 1."},
            {"role": "system", "content": "Part 2."},
            {"role": "user", "content": "Hi"},
        ]
        system, _ = _convert_messages(msgs)
        assert "Part 1." in system
        assert "Part 2." in system

    def test_tool_result_converted(self) -> None:
        msgs = [
            {"role": "tool", "tool_call_id": "call-1", "content": "result text"},
        ]
        _, converted = _convert_messages(msgs)
        assert converted[0]["role"] == "user"
        content_block = converted[0]["content"][0]
        assert content_block["type"] == "tool_result"
        assert content_block["tool_use_id"] == "call-1"
        assert content_block["content"] == "result text"

    def test_no_system_returns_empty_string(self) -> None:
        msgs = [{"role": "user", "content": "Hi"}]
        system, _ = _convert_messages(msgs)
        assert system == ""


class TestConvertTools:
    def test_openai_format_converted(self) -> None:
        tools = [
            {
                "type": "function",
                "function": {
                    "name": "web_search",
                    "description": "Search the web",
                    "parameters": {"type": "object", "properties": {"query": {"type": "string"}}},
                },
            }
        ]
        converted = _convert_tools(tools)
        assert len(converted) == 1
        assert converted[0]["name"] == "web_search"
        assert converted[0]["description"] == "Search the web"
        assert "input_schema" in converted[0]
        assert converted[0]["input_schema"]["type"] == "object"
