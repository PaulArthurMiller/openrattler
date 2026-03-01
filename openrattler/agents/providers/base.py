"""Abstract base class and shared response models for LLM providers.

All concrete provider implementations (OpenAI, Anthropic, …) must subclass
``LLMProvider`` and implement ``complete()`` and ``health_check()``.  The
``AgentRuntime`` depends only on this interface, making providers fully
swappable.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any, Optional

from pydantic import BaseModel, Field

from openrattler.models.tools import ToolCall

# ---------------------------------------------------------------------------
# Response models
# ---------------------------------------------------------------------------


class TokenUsage(BaseModel):
    """Token consumption and estimated cost for a single LLM call.

    ``estimated_cost_usd`` is a best-effort approximation based on per-model
    pricing tables embedded in each provider implementation.  The actual
    amount billed may differ (batch discounts, subscription credits, etc.).
    """

    prompt_tokens: int
    completion_tokens: int
    total_tokens: int
    estimated_cost_usd: float = Field(ge=0.0)


class LLMResponse(BaseModel):
    """Normalised response from any LLM provider.

    ``tool_calls`` uses the ``ToolCall`` model from Piece 1.2 so the rest of
    the system never needs to know which provider produced the call.
    ``content`` may be an empty string when the model responds with tool calls
    only.
    """

    content: str
    tool_calls: list[ToolCall] = Field(default_factory=list)
    usage: TokenUsage
    model: str
    finish_reason: str


# ---------------------------------------------------------------------------
# Abstract provider
# ---------------------------------------------------------------------------


class LLMProvider(ABC):
    """Model-agnostic interface for calling an LLM backend.

    Security notes:
    - Implementations must **never** include API keys in log output or error
      messages.
    - The ``complete()`` contract guarantees a ``LLMResponse`` on success;
      all retry/backoff logic is internal to each implementation.
    """

    @abstractmethod
    async def complete(
        self,
        messages: list[dict[str, Any]],
        tools: Optional[list[dict[str, Any]]] = None,
        model: Optional[str] = None,
        max_tokens: int = 4096,
    ) -> LLMResponse:
        """Send *messages* to the LLM and return a normalised response.

        Args:
            messages:   Conversation history in OpenAI message format
                        (``{"role": "user"|"assistant"|"system"|"tool",
                        "content": "..."}``)
            tools:      Optional tool definitions in OpenAI function-calling
                        format.  ``None`` or empty list means no tools.
            model:      Override the provider's default model for this call.
            max_tokens: Maximum tokens in the completion.

        Returns:
            ``LLMResponse`` with parsed content, tool calls, and usage.
        """

    @abstractmethod
    async def health_check(self) -> bool:
        """Return ``True`` if the provider API is reachable and credentials work."""
