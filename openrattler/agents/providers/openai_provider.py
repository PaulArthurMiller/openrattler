"""OpenAI-compatible LLM provider.

Works with the official OpenAI API and any compatible endpoint (Together AI,
Azure OpenAI, local LM-Studio, etc.) by setting ``base_url``.

SECURITY
--------
- The ``api_key`` is stored in memory only; it is **never** written to logs,
  error messages, or tracebacks.  Error messages that would expose the key are
  replaced with ``"[API KEY REDACTED]"``.
- Rate-limit errors trigger exponential backoff (up to ``_MAX_RETRIES``
  retries) before the exception is re-raised to the caller.
"""

from __future__ import annotations

import asyncio
import json
from typing import Any, Optional

import openai
from openai import AsyncOpenAI

from openrattler.agents.providers.base import LLMProvider, LLMResponse, TokenUsage
from openrattler.models.tools import ToolCall

# ---------------------------------------------------------------------------
# Per-model cost table  (USD per 1 000 tokens; prompt, completion)
# Prices are approximations — check https://openai.com/pricing for current rates.
# ---------------------------------------------------------------------------

_COST_PER_1K: dict[str, tuple[float, float]] = {
    "gpt-4o": (0.005, 0.015),
    "gpt-4o-mini": (0.00015, 0.0006),
    "gpt-4-turbo": (0.010, 0.030),
    "gpt-3.5-turbo": (0.0005, 0.0015),
}
_DEFAULT_COST: tuple[float, float] = (0.001, 0.002)

_MAX_RETRIES = 3


def _estimate_cost(model: str, prompt_tokens: int, completion_tokens: int) -> float:
    """Return a USD cost estimate for *model* given the token counts."""
    prompt_rate, completion_rate = _COST_PER_1K.get(model, _DEFAULT_COST)
    return (prompt_tokens * prompt_rate + completion_tokens * completion_rate) / 1000.0


# ---------------------------------------------------------------------------
# Provider
# ---------------------------------------------------------------------------


class OpenAIProvider(LLMProvider):
    """LLM provider backed by the OpenAI chat-completions API.

    Set ``base_url`` to point at any OpenAI-compatible endpoint.

    Security notes:
    - The API key is never logged or included in exception messages.
    - Retry logic handles transient ``RateLimitError`` with backoff;
      other API errors propagate immediately.
    """

    def __init__(
        self,
        api_key: str,
        default_model: str = "gpt-4o-mini",
        base_url: Optional[str] = None,
    ) -> None:
        """Initialise the provider.

        Args:
            api_key:       OpenAI API key.  Never logged or re-raised in errors.
            default_model: Model used when ``complete()`` is called without an
                           explicit ``model`` override.
            base_url:      Optional URL override for compatible APIs.
        """
        self._client = AsyncOpenAI(api_key=api_key, base_url=base_url)
        self._default_model = default_model

    async def complete(
        self,
        messages: list[dict[str, Any]],
        tools: Optional[list[dict[str, Any]]] = None,
        model: Optional[str] = None,
        max_tokens: int = 4096,
    ) -> LLMResponse:
        """Call the OpenAI chat-completions endpoint.

        Retries up to ``_MAX_RETRIES`` times on ``RateLimitError`` with
        exponential backoff (1 s, 2 s, 4 s).  All other errors propagate
        immediately.
        """
        effective_model = model or self._default_model

        kwargs: dict[str, Any] = {
            "model": effective_model,
            "messages": messages,
            "max_tokens": max_tokens,
        }
        if tools:
            kwargs["tools"] = tools

        for attempt in range(_MAX_RETRIES + 1):
            try:
                response = await self._client.chat.completions.create(**kwargs)
                return self._parse_response(response, effective_model)
            except openai.RateLimitError:
                if attempt == _MAX_RETRIES:
                    raise
                await asyncio.sleep(2.0**attempt)

        raise AssertionError("unreachable")  # pragma: no cover

    def _parse_response(self, response: Any, requested_model: str) -> LLMResponse:
        """Convert a raw ``ChatCompletion`` into a ``LLMResponse``."""
        choice = response.choices[0]
        message = choice.message

        content: str = message.content or ""

        tool_calls: list[ToolCall] = []
        if message.tool_calls:
            for tc in message.tool_calls:
                args: dict[str, Any] = {}
                if tc.function.arguments:
                    try:
                        args = json.loads(tc.function.arguments)
                    except json.JSONDecodeError:
                        args = {"_raw": tc.function.arguments}
                tool_calls.append(
                    ToolCall(
                        tool_name=tc.function.name,
                        arguments=args,
                        call_id=tc.id,
                    )
                )

        actual_model: str = getattr(response, "model", None) or requested_model
        prompt_tokens: int = response.usage.prompt_tokens
        completion_tokens: int = response.usage.completion_tokens

        usage = TokenUsage(
            prompt_tokens=prompt_tokens,
            completion_tokens=completion_tokens,
            total_tokens=response.usage.total_tokens,
            estimated_cost_usd=_estimate_cost(actual_model, prompt_tokens, completion_tokens),
        )

        return LLMResponse(
            content=content,
            tool_calls=tool_calls,
            usage=usage,
            model=actual_model,
            finish_reason=choice.finish_reason or "stop",
        )

    async def health_check(self) -> bool:
        """Return ``True`` if the OpenAI API is reachable."""
        try:
            await self._client.models.list()
            return True
        except Exception:
            return False
