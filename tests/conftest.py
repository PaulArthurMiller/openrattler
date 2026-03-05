"""Shared pytest fixtures for the OpenRattler test suite.

The ``make_stack`` fixture provides a factory that assembles every major
component (storage, tools, runtime) into a ``FullStack`` for integration
tests.  Unit tests typically build the components they need directly.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Optional
from unittest.mock import AsyncMock, MagicMock

import pytest

from openrattler.agents.providers.base import LLMProvider, LLMResponse, TokenUsage
from openrattler.agents.runtime import AgentRuntime
from openrattler.models.agents import AgentConfig, TrustLevel
from openrattler.models.tools import ToolCall
from openrattler.storage.audit import AuditLog
from openrattler.storage.memory import MemoryStore
from openrattler.storage.transcripts import TranscriptStore
from openrattler.tools.executor import ToolExecutor
from openrattler.tools.registry import ToolRegistry

# ---------------------------------------------------------------------------
# LLM mock helpers (importable by any test module)
# ---------------------------------------------------------------------------


def _make_usage() -> TokenUsage:
    return TokenUsage(
        prompt_tokens=10, completion_tokens=5, total_tokens=15, estimated_cost_usd=0.0
    )


def make_text_response(content: str) -> LLMResponse:
    """Build a text-only mock LLM response."""
    return LLMResponse(
        content=content,
        tool_calls=[],
        usage=_make_usage(),
        model="mock-model",
        finish_reason="stop",
    )


def make_tool_response(tool_name: str, arguments: dict, call_id: str = "call-1") -> LLMResponse:
    """Build a mock LLM response that requests a single tool call."""
    return LLMResponse(
        content="",
        tool_calls=[ToolCall(tool_name=tool_name, arguments=arguments, call_id=call_id)],
        usage=_make_usage(),
        model="mock-model",
        finish_reason="tool_calls",
    )


def make_mock_provider(*responses: LLMResponse) -> LLMProvider:
    """Return a mock LLMProvider that yields *responses* in sequence."""
    provider = MagicMock(spec=LLMProvider)
    provider.complete = AsyncMock(side_effect=list(responses))
    return provider


# ---------------------------------------------------------------------------
# FullStack — every component wired together for integration tests
# ---------------------------------------------------------------------------


@dataclass
class FullStack:
    """All major OpenRattler components assembled with shared storage.

    Attributes:
        runtime:          AgentRuntime with the mock provider wired in.
        transcript_store: Shared TranscriptStore (all sessions written here).
        memory_store:     Shared MemoryStore.
        audit_log:        Shared AuditLog.
        tool_registry:    ToolRegistry — register test tools here.
        tool_executor:    ToolExecutor backed by the same registry.
        agent_config:     AgentConfig used to build the runtime.
    """

    runtime: AgentRuntime
    transcript_store: TranscriptStore
    memory_store: MemoryStore
    audit_log: AuditLog
    tool_registry: ToolRegistry
    tool_executor: ToolExecutor
    agent_config: AgentConfig


@pytest.fixture()
def make_stack(tmp_path: Path):
    """Fixture: factory that assembles a FullStack with temp-dir storage.

    Usage::

        def test_something(make_stack):
            provider = make_mock_provider(make_text_response("Hello!"))
            stack = make_stack(provider)
            # optionally register tools on stack.tool_registry before use

        # Custom agent trust level:
        stack = make_stack(provider, trust_level=TrustLevel.public)

        # Pre-approved tool list:
        stack = make_stack(provider, allowed_tools=["my_tool"])

        # Fully custom config:
        stack = make_stack(provider, agent_config=my_config)

    Security notes:
    - Each test invocation gets a fresh set of temp directories via
      pytest's built-in ``tmp_path`` fixture — no state leaks between tests.
    - The mock provider never makes real API calls.
    """

    def factory(
        provider: LLMProvider,
        *,
        agent_config: Optional[AgentConfig] = None,
        allowed_tools: Optional[list[str]] = None,
        trust_level: TrustLevel = TrustLevel.main,
    ) -> FullStack:
        sessions_dir = tmp_path / "sessions"
        memory_dir = tmp_path / "memory"
        audit_path = tmp_path / "audit.jsonl"

        sessions_dir.mkdir(parents=True, exist_ok=True)
        memory_dir.mkdir(parents=True, exist_ok=True)

        transcript_store = TranscriptStore(sessions_dir)
        memory_store = MemoryStore(memory_dir)
        audit_log = AuditLog(audit_path)
        registry = ToolRegistry()
        executor = ToolExecutor(registry, audit_log)

        config = agent_config or AgentConfig(
            agent_id="agent:main:main",
            name="IntegrationTestAgent",
            description="Full-stack integration test agent",
            model="mock-model",
            trust_level=trust_level,
            allowed_tools=allowed_tools or [],
            system_prompt="You are a helpful test agent.",
        )

        runtime = AgentRuntime(
            config=config,
            provider=provider,
            tool_executor=executor,
            transcript_store=transcript_store,
            memory_store=memory_store,
            audit_log=audit_log,
        )

        return FullStack(
            runtime=runtime,
            transcript_store=transcript_store,
            memory_store=memory_store,
            audit_log=audit_log,
            tool_registry=registry,
            tool_executor=executor,
            agent_config=config,
        )

    return factory
