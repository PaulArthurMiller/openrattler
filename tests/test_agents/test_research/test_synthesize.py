"""Tests for ResearchAgent._synthesize() — real LLM synthesis via LLMProvider.

Coverage:
- Provider is called with the expected message structure (system = SKILL.md,
  user contains query and page content).
- Response content flows through to the raw_summary and is capped at 2000 chars.
- provider=None falls back to the stub (backward compat).
- Provider exception falls back to the stub and logs a warning.
- Empty fetched list produces a graceful no-sources message.
- Model prefix is stripped ("anthropic/..." → bare model ID) before the call.
- Full run() pipeline with a mock provider returns synthesized text in the UM.
- Sanitizer always runs after synthesis (even with a real provider).
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from openrattler.agents.providers.base import LLMProvider, LLMResponse, TokenUsage
from openrattler.agents.research.agent import ResearchAgent
from openrattler.agents.research.config import ResearchAgentConfig
from openrattler.agents.research.models import ResearchRequest
from openrattler.models.tools import ToolCall
from openrattler.storage.audit import AuditLog

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_SKILL_TEXT = "# Test skill prompt\nYou are a research assistant."
_QUERY = "best practices for async Python"
_PAGE_CONTENT = "Async Python is great for I/O-bound tasks."


def _make_config(
    tmp_path: Path, model: str = "anthropic/claude-haiku-4-5-20251001"
) -> ResearchAgentConfig:
    """Build a ResearchAgentConfig with a real SKILL.md in tmp_path."""
    skill_path = tmp_path / "SKILL.md"
    skill_path.write_text(_SKILL_TEXT, encoding="utf-8")
    return ResearchAgentConfig(
        skill_prompt_path=skill_path,
        model=model,
        max_fetch_size_bytes=10_000,
        request_timeout_seconds=5,
        allowed_content_types=["text/html", "text/plain"],
    )


def _make_llm_response(content: str) -> LLMResponse:
    """Construct a minimal LLMResponse with the given text content."""
    usage = TokenUsage(
        prompt_tokens=10,
        completion_tokens=20,
        total_tokens=30,
        estimated_cost_usd=0.0,
    )
    return LLMResponse(
        content=content,
        tool_calls=[],
        usage=usage,
        model="claude-haiku-4-5-20251001",
        finish_reason="end_turn",
    )


def _make_mock_provider(response_text: str = "LLM synthesis result.") -> MagicMock:
    """Return a mock LLMProvider whose complete() returns response_text."""
    provider = MagicMock(spec=LLMProvider)
    provider.complete = AsyncMock(return_value=_make_llm_response(response_text))
    return provider


def _make_fetched_pages() -> list[dict[str, Any]]:
    return [
        {
            "title": "Async Python Guide",
            "url": "https://example.com/async",
            "domain": "example.com",
            "source_type": "general",
            "retrieval_timestamp": "2026-04-02T00:00:00+00:00",
            "content": _PAGE_CONTENT,
        }
    ]


def _make_request(**overrides: Any) -> ResearchRequest:
    defaults: dict[str, Any] = {"query": _QUERY, "max_results": 3}
    defaults.update(overrides)
    return ResearchRequest(**defaults)


# ---------------------------------------------------------------------------
# _synthesize — provider is called
# ---------------------------------------------------------------------------


class TestSynthesizeWithProvider:
    async def test_synthesize_calls_provider(self, tmp_path: Path) -> None:
        """provider.complete() must be called exactly once when fetched content exists."""
        provider = _make_mock_provider()
        audit = AuditLog(tmp_path / "audit.jsonl")
        config = _make_config(tmp_path)
        agent = ResearchAgent(config=config, audit=audit, provider=provider)

        await agent._synthesize(_make_request(), _make_fetched_pages())

        provider.complete.assert_called_once()

    async def test_synthesize_system_message_is_skill_prompt(self, tmp_path: Path) -> None:
        """The system message content must equal the loaded SKILL.md text."""
        provider = _make_mock_provider()
        audit = AuditLog(tmp_path / "audit.jsonl")
        config = _make_config(tmp_path)
        agent = ResearchAgent(config=config, audit=audit, provider=provider)

        await agent._synthesize(_make_request(), _make_fetched_pages())

        call_kwargs = provider.complete.call_args
        messages = call_kwargs.kwargs.get("messages") or call_kwargs.args[0]
        system_msgs = [m for m in messages if m.get("role") == "system"]
        assert len(system_msgs) == 1
        assert system_msgs[0]["content"] == _SKILL_TEXT

    async def test_synthesize_user_message_contains_query(self, tmp_path: Path) -> None:
        """The user message must include the research query string."""
        provider = _make_mock_provider()
        audit = AuditLog(tmp_path / "audit.jsonl")
        config = _make_config(tmp_path)
        agent = ResearchAgent(config=config, audit=audit, provider=provider)

        await agent._synthesize(_make_request(), _make_fetched_pages())

        call_kwargs = provider.complete.call_args
        messages = call_kwargs.kwargs.get("messages") or call_kwargs.args[0]
        user_msgs = [m for m in messages if m.get("role") == "user"]
        assert len(user_msgs) == 1
        assert _QUERY in user_msgs[0]["content"]

    async def test_synthesize_user_message_contains_page_content(self, tmp_path: Path) -> None:
        """The user message must include the fetched page content snippet."""
        provider = _make_mock_provider()
        audit = AuditLog(tmp_path / "audit.jsonl")
        config = _make_config(tmp_path)
        agent = ResearchAgent(config=config, audit=audit, provider=provider)

        await agent._synthesize(_make_request(), _make_fetched_pages())

        call_kwargs = provider.complete.call_args
        messages = call_kwargs.kwargs.get("messages") or call_kwargs.args[0]
        user_msgs = [m for m in messages if m.get("role") == "user"]
        assert _PAGE_CONTENT in user_msgs[0]["content"]

    async def test_synthesize_returns_provider_response(self, tmp_path: Path) -> None:
        """The return value must be the LLM response content."""
        expected = "Async Python leverages event loops for efficient I/O."
        provider = _make_mock_provider(expected)
        audit = AuditLog(tmp_path / "audit.jsonl")
        config = _make_config(tmp_path)
        agent = ResearchAgent(config=config, audit=audit, provider=provider)

        result = await agent._synthesize(_make_request(), _make_fetched_pages())

        assert result == expected

    async def test_synthesize_caps_response_at_2000_chars(self, tmp_path: Path) -> None:
        """LLM response longer than 2000 chars must be truncated."""
        long_text = "x" * 3_000
        provider = _make_mock_provider(long_text)
        audit = AuditLog(tmp_path / "audit.jsonl")
        config = _make_config(tmp_path)
        agent = ResearchAgent(config=config, audit=audit, provider=provider)

        result = await agent._synthesize(_make_request(), _make_fetched_pages())

        assert len(result) == 2000

    async def test_synthesize_no_tools_passed_to_provider(self, tmp_path: Path) -> None:
        """tools=None must be passed to provider.complete() — no tool loop during synthesis."""
        provider = _make_mock_provider()
        audit = AuditLog(tmp_path / "audit.jsonl")
        config = _make_config(tmp_path)
        agent = ResearchAgent(config=config, audit=audit, provider=provider)

        await agent._synthesize(_make_request(), _make_fetched_pages())

        call_kwargs = provider.complete.call_args
        tools_arg = call_kwargs.kwargs.get("tools")
        assert tools_arg is None

    async def test_synthesize_strips_anthropic_prefix_from_model(self, tmp_path: Path) -> None:
        """The 'anthropic/' prefix must be stripped before passing model to provider.complete()."""
        provider = _make_mock_provider()
        audit = AuditLog(tmp_path / "audit.jsonl")
        config = _make_config(tmp_path, model="anthropic/claude-haiku-4-5-20251001")
        agent = ResearchAgent(config=config, audit=audit, provider=provider)

        await agent._synthesize(_make_request(), _make_fetched_pages())

        call_kwargs = provider.complete.call_args
        model_arg = call_kwargs.kwargs.get("model")
        assert model_arg == "claude-haiku-4-5-20251001"
        assert "anthropic/" not in model_arg


# ---------------------------------------------------------------------------
# _synthesize — fallback behaviour
# ---------------------------------------------------------------------------


class TestSynthesizeFallback:
    async def test_synthesize_no_provider_uses_stub(self, tmp_path: Path) -> None:
        """When provider=None the stub summary is returned (no LLM call)."""
        audit = AuditLog(tmp_path / "audit.jsonl")
        config = _make_config(tmp_path)
        agent = ResearchAgent(config=config, audit=audit, provider=None)

        result = await agent._synthesize(_make_request(), _make_fetched_pages())

        # Stub produces a metadata-only summary, not a rich synthesis
        assert _QUERY in result
        # Stub includes title and URL, not arbitrary content
        assert "Async Python Guide" in result

    async def test_synthesize_provider_exception_falls_back(
        self, tmp_path: Path, caplog: pytest.LogCaptureFixture
    ) -> None:
        """When provider.complete() raises, the stub is returned and a warning is logged."""
        provider = MagicMock(spec=LLMProvider)
        provider.complete = AsyncMock(side_effect=RuntimeError("API unavailable"))
        audit = AuditLog(tmp_path / "audit.jsonl")
        config = _make_config(tmp_path)
        agent = ResearchAgent(config=config, audit=audit, provider=provider)

        with caplog.at_level(logging.WARNING):
            result = await agent._synthesize(_make_request(), _make_fetched_pages())

        # Still returns a valid (stub) summary
        assert isinstance(result, str)
        assert len(result) > 0
        # Warning was logged
        assert any("LLM call failed" in r.message for r in caplog.records)

    async def test_synthesize_empty_fetched_list_no_provider(self, tmp_path: Path) -> None:
        """Empty fetched list with no provider returns a graceful no-sources message."""
        audit = AuditLog(tmp_path / "audit.jsonl")
        config = _make_config(tmp_path)
        agent = ResearchAgent(config=config, audit=audit, provider=None)

        result = await agent._synthesize(_make_request(), [])

        assert "No sources" in result
        assert isinstance(result, str)

    async def test_synthesize_empty_fetched_list_with_provider(self, tmp_path: Path) -> None:
        """Empty fetched list is communicated to the LLM via the user message."""
        provider = _make_mock_provider("No relevant sources found.")
        audit = AuditLog(tmp_path / "audit.jsonl")
        config = _make_config(tmp_path)
        agent = ResearchAgent(config=config, audit=audit, provider=provider)

        result = await agent._synthesize(_make_request(), [])

        # Provider was still called — the LLM is informed there are no sources
        provider.complete.assert_called_once()
        assert result == "No relevant sources found."


# ---------------------------------------------------------------------------
# Full pipeline integration
# ---------------------------------------------------------------------------


class TestSynthesizePipelineIntegration:
    async def test_run_pipeline_uses_real_synthesis(self, tmp_path: Path) -> None:
        """Full run() with a mock provider must return the synthesized text in UM params."""
        synthesis_text = "Python async is ideal for network-bound workloads."
        provider = _make_mock_provider(synthesis_text)
        audit = AuditLog(tmp_path / "audit.jsonl")
        config = _make_config(tmp_path)
        agent = ResearchAgent(config=config, audit=audit, provider=provider)

        request = _make_request()
        trace_id = "test-trace-001"

        # Patch _web_search to return one hit, _fetch_url to return page content
        with (
            patch.object(
                agent,
                "_web_search",
                new=AsyncMock(
                    return_value=[
                        {
                            "url": "https://example.com/async",
                            "title": "Async Python Guide",
                            "source_type": "general",
                        }
                    ]
                ),
            ),
            patch.object(
                agent,
                "_fetch_url",
                new=AsyncMock(
                    return_value=(
                        "https://example.com/async",
                        "text/html",
                        _PAGE_CONTENT.encode(),
                    )
                ),
            ),
        ):
            um = await agent.run(request, trace_id)

        assert um.type == "response"
        # The synthesis text flows into the sanitizer and then into the summary field
        assert synthesis_text in um.params.get("summary", "")

    async def test_sanitizer_runs_after_synthesis(self, tmp_path: Path) -> None:
        """The sanitizer must always be invoked even when real synthesis is used."""
        provider = _make_mock_provider("Safe synthesis result.")
        audit = AuditLog(tmp_path / "audit.jsonl")
        config = _make_config(tmp_path)
        agent = ResearchAgent(config=config, audit=audit, provider=provider)

        request = _make_request()

        with patch.object(
            agent._sanitizer,
            "sanitize",
            wraps=agent._sanitizer.sanitize,
        ) as mock_sanitize:
            with (patch.object(agent, "_web_search", new=AsyncMock(return_value=[])),):
                await agent.run(request, "trace-002")

        mock_sanitize.assert_called_once()
