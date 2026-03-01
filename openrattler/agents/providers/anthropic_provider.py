"""Anthropic LLM provider.

Implements the ``LLMProvider`` interface for Anthropic's Messages API
(Claude model family).

MESSAGE FORMAT CONVERSION
--------------------------
The ``complete()`` interface accepts messages in OpenAI format.  This provider
converts them to Anthropic's format before the API call:

* ``system`` role messages are extracted and joined into a single ``system``
  string (Anthropic passes system context as a top-level parameter).
* ``tool`` role messages are wrapped as Anthropic ``tool_result`` user turns.
* ``user`` and ``assistant`` messages pass through unchanged.

TOOL FORMAT CONVERSION
-----------------------
Tools supplied in OpenAI function-calling format are converted to Anthropic's
``input_schema`` format (``function.parameters`` → ``input_schema``).

SECURITY
--------
- The ``api_key`` is **never** written to logs or error messages.
- Rate-limit errors are retried with exponential backoff (up to
  ``_MAX_RETRIES`` retries) before re-raising.
"""

from __future__ import annotations

import asyncio
from typing import Any, Optional

import anthropic
from anthropic import AsyncAnthropic

from openrattler.agents.providers.base import LLMProvider, LLMResponse, TokenUsage
from openrattler.models.tools import ToolCall

# ---------------------------------------------------------------------------
# Per-model cost table  (USD per 1 000 tokens; input, output)
# Prices are approximations — check https://www.anthropic.com/pricing for
# current rates.
# ---------------------------------------------------------------------------

_COST_PER_1K: dict[str, tuple[float, float]] = {
    "claude-opus-4-6": (0.015, 0.075),
    "claude-sonnet-4-6": (0.003, 0.015),
    "claude-haiku-4-5-20251001": (0.00025, 0.00125),
    # Legacy names kept for compatibility
    "claude-3-5-sonnet-20241022": (0.003, 0.015),
    "claude-3-haiku-20240307": (0.00025, 0.00125),
}
_DEFAULT_COST: tuple[float, float] = (0.003, 0.015)

_MAX_RETRIES = 3


def _estimate_cost(model: str, input_tokens: int, output_tokens: int) -> float:
    """Return a USD cost estimate for *model* given the token counts."""
    input_rate, output_rate = _COST_PER_1K.get(model, _DEFAULT_COST)
    return (input_tokens * input_rate + output_tokens * output_rate) / 1000.0


# ---------------------------------------------------------------------------
# Message / tool format converters
# ---------------------------------------------------------------------------


def _convert_messages(
    messages: list[dict[str, Any]],
) -> tuple[str, list[dict[str, Any]]]:
    """Split out the system prompt and convert messages to Anthropic format.

    Returns:
        (system_str, anthropic_messages) where ``system_str`` may be empty.
    """
    system_parts: list[str] = []
    converted: list[dict[str, Any]] = []

    for msg in messages:
        role = msg.get("role", "")
        content = msg.get("content", "")

        if role == "system":
            if content:
                system_parts.append(content)
        elif role in ("user", "assistant"):
            converted.append({"role": role, "content": content})
        elif role == "tool":
            # Tool results become a user message with tool_result content.
            converted.append(
                {
                    "role": "user",
                    "content": [
                        {
                            "type": "tool_result",
                            "tool_use_id": msg.get("tool_call_id", ""),
                            "content": content,
                        }
                    ],
                }
            )

    system_str = "\n\n".join(system_parts)
    return system_str, converted


def _convert_tools(tools: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Convert OpenAI-format tool definitions to Anthropic format.

    OpenAI:   ``{"type": "function", "function": {"name": ..., "description": ...,
              "parameters": {...}}}``
    Anthropic: ``{"name": ..., "description": ..., "input_schema": {...}}``
    """
    result: list[dict[str, Any]] = []
    for tool in tools:
        fn = tool.get("function", tool)  # handle both wrapped and bare dicts
        result.append(
            {
                "name": fn.get("name", ""),
                "description": fn.get("description", ""),
                "input_schema": fn.get("parameters", {"type": "object", "properties": {}}),
            }
        )
    return result


# ---------------------------------------------------------------------------
# Provider
# ---------------------------------------------------------------------------


class AnthropicProvider(LLMProvider):
    """LLM provider backed by the Anthropic Messages API.

    Security notes:
    - The API key is never logged or included in exception messages.
    - Rate-limit errors are retried with exponential backoff.
    """

    def __init__(
        self,
        api_key: str,
        default_model: str = "claude-sonnet-4-6",
        base_url: Optional[str] = None,
    ) -> None:
        """Initialise the provider.

        Args:
            api_key:       Anthropic API key.  Never logged or re-raised.
            default_model: Model used when ``complete()`` is called without an
                           explicit ``model`` override.
            base_url:      Optional URL override for compatible endpoints.
        """
        self._client = AsyncAnthropic(api_key=api_key, base_url=base_url)
        self._default_model = default_model

    async def complete(
        self,
        messages: list[dict[str, Any]],
        tools: Optional[list[dict[str, Any]]] = None,
        model: Optional[str] = None,
        max_tokens: int = 4096,
    ) -> LLMResponse:
        """Call the Anthropic Messages endpoint.

        Retries up to ``_MAX_RETRIES`` times on ``RateLimitError`` with
        exponential backoff (1 s, 2 s, 4 s).
        """
        effective_model = model or self._default_model
        system_str, anthropic_messages = _convert_messages(messages)

        kwargs: dict[str, Any] = {
            "model": effective_model,
            "messages": anthropic_messages,
            "max_tokens": max_tokens,
        }
        if system_str:
            kwargs["system"] = system_str
        if tools:
            kwargs["tools"] = _convert_tools(tools)

        for attempt in range(_MAX_RETRIES + 1):
            try:
                response = await self._client.messages.create(**kwargs)
                return self._parse_response(response, effective_model)
            except anthropic.RateLimitError:
                if attempt == _MAX_RETRIES:
                    raise
                await asyncio.sleep(2.0**attempt)

        raise AssertionError("unreachable")  # pragma: no cover

    def _parse_response(self, response: Any, requested_model: str) -> LLMResponse:
        """Convert a raw Anthropic ``Message`` into a ``LLMResponse``."""
        content_text = ""
        tool_calls: list[ToolCall] = []

        for block in response.content:
            block_type = getattr(block, "type", None)
            if block_type == "text":
                content_text += block.text
            elif block_type == "tool_use":
                tool_calls.append(
                    ToolCall(
                        tool_name=block.name,
                        arguments=dict(block.input) if block.input else {},
                        call_id=block.id,
                    )
                )

        actual_model: str = getattr(response, "model", None) or requested_model
        input_tokens: int = response.usage.input_tokens
        output_tokens: int = response.usage.output_tokens

        usage = TokenUsage(
            prompt_tokens=input_tokens,
            completion_tokens=output_tokens,
            total_tokens=input_tokens + output_tokens,
            estimated_cost_usd=_estimate_cost(actual_model, input_tokens, output_tokens),
        )

        return LLMResponse(
            content=content_text,
            tool_calls=tool_calls,
            usage=usage,
            model=actual_model,
            finish_reason=getattr(response, "stop_reason", None) or "end_turn",
        )

    async def health_check(self) -> bool:
        """Return ``True`` if the Anthropic API is reachable."""
        try:
            await self._client.models.list()
            return True
        except Exception:
            return False
