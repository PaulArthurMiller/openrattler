"""Tests for ResearchAgent._plan_search() — LLM-driven search parameter selection.

Coverage:
- provider.complete() is called once with tools=None.
- System message equals the loaded SEARCH_PLAN.md content.
- User message includes the query and the enabled endpoints list.
- Valid JSON from LLM → correctly populated WebSearchParams.
- tbs and location filters flow through from the LLM response.
- LLM returns a disabled endpoint → fallback default used.
- provider=None → default WebSearchParams returned (no LLM call).
- provider.complete() raises → default returned, warning logged.
- Malformed JSON → default returned, warning logged.
- Markdown code fences (```json ... ```) are stripped before JSON parse.
- _web_search receives the full planned params dict (not just the query).
- Full run() with a mock provider: planned endpoint reaches web_search call.
"""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from openrattler.agents.providers.base import LLMProvider, LLMResponse, TokenUsage
from openrattler.agents.research.agent import ResearchAgent
from openrattler.agents.research.config import ResearchAgentConfig
from openrattler.agents.research.models import ResearchRequest
from openrattler.storage.audit import AuditLog
from openrattler.tools.search.serper_config import SerperConfig
from openrattler.tools.search.web_search_tool import WebSearchParams

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_SKILL_TEXT = "# Skill\nYou are a research assistant."
_PLAN_TEXT = "# Search Planner\nOutput a JSON object."
_QUERY = "No Kings protests Ohio March 2026"


def _make_config(
    tmp_path: Path,
    enabled_endpoints: frozenset[str] = frozenset({"search", "news", "images"}),
    model: str = "anthropic/claude-haiku-4-5-20251001",
) -> ResearchAgentConfig:
    """Build a ResearchAgentConfig with both prompt files and a custom endpoint set."""
    skill_path = tmp_path / "SKILL.md"
    skill_path.write_text(_SKILL_TEXT, encoding="utf-8")
    plan_path = tmp_path / "SEARCH_PLAN.md"
    plan_path.write_text(_PLAN_TEXT, encoding="utf-8")
    serper_cfg = SerperConfig(enabled_endpoints=enabled_endpoints)
    return ResearchAgentConfig(
        skill_prompt_path=skill_path,
        search_plan_path=plan_path,
        serper_config=serper_cfg,
        model=model,
        max_fetch_size_bytes=10_000,
        request_timeout_seconds=5,
        allowed_content_types=["text/html", "text/plain"],
    )


def _make_llm_response(content: str) -> LLMResponse:
    usage = TokenUsage(
        prompt_tokens=5,
        completion_tokens=15,
        total_tokens=20,
        estimated_cost_usd=0.0,
    )
    return LLMResponse(
        content=content,
        tool_calls=[],
        usage=usage,
        model="claude-haiku-4-5-20251001",
        finish_reason="end_turn",
    )


def _make_mock_provider(response_json: dict[str, Any]) -> MagicMock:
    """Return a mock LLMProvider whose complete() returns the given dict as JSON."""
    provider = MagicMock(spec=LLMProvider)
    provider.complete = AsyncMock(return_value=_make_llm_response(json.dumps(response_json)))
    return provider


def _make_request(**overrides: Any) -> ResearchRequest:
    defaults: dict[str, Any] = {"query": _QUERY, "max_results": 3}
    defaults.update(overrides)
    return ResearchRequest(**defaults)


def _make_agent(
    tmp_path: Path,
    provider: Any = None,
    enabled_endpoints: frozenset[str] = frozenset({"search", "news", "images"}),
) -> tuple[ResearchAgent, AuditLog]:
    audit = AuditLog(tmp_path / "audit.jsonl")
    config = _make_config(tmp_path, enabled_endpoints=enabled_endpoints)
    agent = ResearchAgent(config=config, audit=audit, provider=provider)
    return agent, audit


# ---------------------------------------------------------------------------
# _plan_search — provider call structure
# ---------------------------------------------------------------------------


class TestPlanSearchProviderCall:
    async def test_plan_search_calls_provider_once(self, tmp_path: Path) -> None:
        """provider.complete() must be called exactly once per _plan_search call."""
        provider = _make_mock_provider({"endpoint": "news", "query": _QUERY})
        agent, _ = _make_agent(tmp_path, provider=provider)

        await agent._plan_search(_make_request())

        provider.complete.assert_called_once()
        print("[TestPlanSearchProviderCall] provider called once ✓")

    async def test_plan_search_passes_tools_none(self, tmp_path: Path) -> None:
        """tools=None must be passed — no tool loop during planning."""
        provider = _make_mock_provider({"endpoint": "news", "query": _QUERY})
        agent, _ = _make_agent(tmp_path, provider=provider)

        await agent._plan_search(_make_request())

        call_kwargs = provider.complete.call_args
        tools_arg = call_kwargs.kwargs.get("tools")
        print(f"[TestPlanSearchProviderCall] tools arg: {tools_arg!r}")
        assert tools_arg is None

    async def test_plan_search_system_message_is_search_plan_prompt(self, tmp_path: Path) -> None:
        """The system message must equal the SEARCH_PLAN.md content."""
        provider = _make_mock_provider({"endpoint": "news", "query": _QUERY})
        agent, _ = _make_agent(tmp_path, provider=provider)

        await agent._plan_search(_make_request())

        call_kwargs = provider.complete.call_args
        messages = call_kwargs.kwargs.get("messages") or call_kwargs.args[0]
        system_msgs = [m for m in messages if m.get("role") == "system"]
        print(f"[TestPlanSearchProviderCall] system message: {system_msgs[0]['content']!r}")
        assert len(system_msgs) == 1
        assert system_msgs[0]["content"] == _PLAN_TEXT

    async def test_plan_search_user_message_contains_query(self, tmp_path: Path) -> None:
        """The user message must include the research query text."""
        provider = _make_mock_provider({"endpoint": "news", "query": _QUERY})
        agent, _ = _make_agent(tmp_path, provider=provider)

        await agent._plan_search(_make_request())

        call_kwargs = provider.complete.call_args
        messages = call_kwargs.kwargs.get("messages") or call_kwargs.args[0]
        user_msgs = [m for m in messages if m.get("role") == "user"]
        print(f"[TestPlanSearchProviderCall] user message snippet: {user_msgs[0]['content'][:80]}")
        assert _QUERY in user_msgs[0]["content"]

    async def test_plan_search_user_message_contains_enabled_endpoints(
        self, tmp_path: Path
    ) -> None:
        """The user message must list the currently-enabled endpoints."""
        provider = _make_mock_provider({"endpoint": "news", "query": _QUERY})
        enabled = frozenset({"search", "news"})
        agent, _ = _make_agent(tmp_path, provider=provider, enabled_endpoints=enabled)

        await agent._plan_search(_make_request())

        call_kwargs = provider.complete.call_args
        messages = call_kwargs.kwargs.get("messages") or call_kwargs.args[0]
        user_content = next(m["content"] for m in messages if m.get("role") == "user")
        print(f"[TestPlanSearchProviderCall] user content: {user_content}")
        assert "news" in user_content
        assert "search" in user_content
        # An endpoint not in the enabled set should not appear
        assert "images" not in user_content

    async def test_plan_search_strips_anthropic_prefix_from_model(self, tmp_path: Path) -> None:
        """The 'anthropic/' prefix must be stripped before passing model to provider."""
        provider = _make_mock_provider({"endpoint": "news", "query": _QUERY})
        agent, _ = _make_agent(tmp_path, provider=provider, enabled_endpoints=frozenset({"news"}))

        await agent._plan_search(_make_request())

        call_kwargs = provider.complete.call_args
        model_arg = call_kwargs.kwargs.get("model")
        print(f"[TestPlanSearchProviderCall] model arg: {model_arg!r}")
        assert model_arg is not None
        assert "anthropic/" not in model_arg


# ---------------------------------------------------------------------------
# _plan_search — return value
# ---------------------------------------------------------------------------


class TestPlanSearchReturnValue:
    async def test_plan_search_returns_websearchparams(self, tmp_path: Path) -> None:
        """A valid JSON response must produce the correct WebSearchParams."""
        provider = _make_mock_provider({"endpoint": "news", "query": _QUERY})
        agent, _ = _make_agent(tmp_path, provider=provider)

        result = await agent._plan_search(_make_request())

        print(f"[TestPlanSearchReturnValue] result: {result!r}")
        assert isinstance(result, WebSearchParams)
        assert result.endpoint == "news"
        assert result.query == _QUERY

    async def test_plan_search_passes_tbs_filter(self, tmp_path: Path) -> None:
        """A tbs value in the LLM JSON must appear in the returned WebSearchParams."""
        provider = _make_mock_provider({"endpoint": "news", "query": _QUERY, "tbs": "qdr:m"})
        agent, _ = _make_agent(tmp_path, provider=provider)

        result = await agent._plan_search(_make_request())

        print(f"[TestPlanSearchReturnValue] tbs: {result.tbs!r}")
        assert result.tbs == "qdr:m"

    async def test_plan_search_passes_location_filter(self, tmp_path: Path) -> None:
        """A location value in the LLM JSON must appear in the returned WebSearchParams."""
        provider = _make_mock_provider(
            {"endpoint": "news", "query": _QUERY, "location": "Columbus, Ohio"}
        )
        agent, _ = _make_agent(tmp_path, provider=provider)

        result = await agent._plan_search(_make_request())

        print(f"[TestPlanSearchReturnValue] location: {result.location!r}")
        assert result.location == "Columbus, Ohio"

    async def test_plan_search_strips_markdown_fences(self, tmp_path: Path) -> None:
        """LLM output wrapped in ```json ... ``` must still be parsed correctly."""
        raw_json = json.dumps({"endpoint": "news", "query": _QUERY})
        fenced = f"```json\n{raw_json}\n```"
        provider = MagicMock(spec=LLMProvider)
        provider.complete = AsyncMock(return_value=_make_llm_response(fenced))
        agent, _ = _make_agent(tmp_path, provider=provider)

        result = await agent._plan_search(_make_request())

        print(f"[TestPlanSearchReturnValue] fenced result: {result!r}")
        assert isinstance(result, WebSearchParams)
        assert result.endpoint == "news"


# ---------------------------------------------------------------------------
# _plan_search — fallback behaviour
# ---------------------------------------------------------------------------


class TestPlanSearchFallback:
    async def test_plan_search_no_provider_returns_default(self, tmp_path: Path) -> None:
        """provider=None must return the default without any LLM call."""
        agent, _ = _make_agent(tmp_path, provider=None)
        request = _make_request()

        result = await agent._plan_search(request)

        print(f"[TestPlanSearchFallback] no-provider result: {result!r}")
        assert isinstance(result, WebSearchParams)
        assert result.endpoint == "news"
        assert result.query == _QUERY

    async def test_plan_search_provider_exception_returns_default(
        self, tmp_path: Path, caplog: pytest.LogCaptureFixture
    ) -> None:
        """provider.complete() raising must return default and log a warning."""
        provider = MagicMock(spec=LLMProvider)
        provider.complete = AsyncMock(side_effect=RuntimeError("API down"))
        agent, _ = _make_agent(tmp_path, provider=provider)

        with caplog.at_level(logging.WARNING):
            result = await agent._plan_search(_make_request())

        print(f"[TestPlanSearchFallback] exception result: {result!r}")
        assert isinstance(result, WebSearchParams)
        assert result.endpoint == "news"
        assert any("_plan_search" in r.message for r in caplog.records)

    async def test_plan_search_invalid_json_returns_default(
        self, tmp_path: Path, caplog: pytest.LogCaptureFixture
    ) -> None:
        """Malformed JSON from the LLM must return default and log a warning."""
        provider = MagicMock(spec=LLMProvider)
        provider.complete = AsyncMock(return_value=_make_llm_response("This is not JSON at all."))
        agent, _ = _make_agent(tmp_path, provider=provider)

        with caplog.at_level(logging.WARNING):
            result = await agent._plan_search(_make_request())

        print(f"[TestPlanSearchFallback] invalid-JSON result: {result!r}")
        assert isinstance(result, WebSearchParams)
        assert result.endpoint == "news"
        assert any("_plan_search" in r.message for r in caplog.records)

    async def test_plan_search_rejects_disabled_endpoint(
        self, tmp_path: Path, caplog: pytest.LogCaptureFixture
    ) -> None:
        """LLM returning an endpoint not in enabled_endpoints must trigger fallback."""
        # Only "search" and "news" are enabled; LLM returns "scholar"
        provider = _make_mock_provider({"endpoint": "scholar", "query": _QUERY})
        enabled = frozenset({"search", "news"})
        agent, _ = _make_agent(tmp_path, provider=provider, enabled_endpoints=enabled)

        with caplog.at_level(logging.WARNING):
            result = await agent._plan_search(_make_request())

        print(f"[TestPlanSearchFallback] disabled-endpoint result: {result!r}")
        assert isinstance(result, WebSearchParams)
        assert result.endpoint == "news"  # default
        assert any("not in enabled_endpoints" in r.message for r in caplog.records)


# ---------------------------------------------------------------------------
# _web_search — receives planned params
# ---------------------------------------------------------------------------


class TestWebSearchReceivesPlannedParams:
    async def test_web_search_passes_endpoint_to_serper(self, tmp_path: Path) -> None:
        """_web_search must forward the full params dict (including endpoint) to web_search()."""
        agent, _ = _make_agent(tmp_path)
        params = WebSearchParams(query=_QUERY, endpoint="news", tbs="qdr:w")

        # web_search is lazily imported inside _web_search; patch it at its home module
        with patch(
            "openrattler.tools.search.web_search_tool.web_search",
            new=AsyncMock(return_value={"status": "ok", "results": []}),
        ) as mock_ws:
            await agent._web_search(params)

        call_params = mock_ws.call_args.kwargs.get("params") or mock_ws.call_args.args[0]
        print(f"[TestWebSearchReceivesPlannedParams] call_params: {call_params}")
        assert call_params.get("endpoint") == "news"
        assert call_params.get("query") == _QUERY
        assert call_params.get("tbs") == "qdr:w"

    async def test_web_search_excludes_none_fields(self, tmp_path: Path) -> None:
        """None-valued optional fields must be excluded from the params dict."""
        agent, _ = _make_agent(tmp_path)
        # Only endpoint and query set; location/tbs/gl are None
        params = WebSearchParams(query=_QUERY, endpoint="news")

        with patch(
            "openrattler.tools.search.web_search_tool.web_search",
            new=AsyncMock(return_value={"status": "ok", "results": []}),
        ) as mock_ws:
            await agent._web_search(params)

        call_params = mock_ws.call_args.kwargs.get("params") or mock_ws.call_args.args[0]
        print(f"[TestWebSearchReceivesPlannedParams] excluded-none params: {call_params}")
        assert "location" not in call_params
        assert "tbs" not in call_params
        assert "gl" not in call_params


# ---------------------------------------------------------------------------
# Full pipeline: planned endpoint flows through run()
# ---------------------------------------------------------------------------


class TestPlanSearchPipelineIntegration:
    async def test_run_pipeline_uses_planned_endpoint(self, tmp_path: Path) -> None:
        """run() must use the endpoint chosen by _plan_search, not a hardcoded value."""
        # Provider returns a "scholar" plan first (planning call), then synthesis text
        plan_response = _make_llm_response(json.dumps({"endpoint": "scholar", "query": _QUERY}))
        synthesis_response = _make_llm_response("Summary of research findings.")
        provider = MagicMock(spec=LLMProvider)
        provider.complete = AsyncMock(side_effect=[plan_response, synthesis_response])

        # Enable "scholar" so the plan is accepted
        agent, _ = _make_agent(
            tmp_path,
            provider=provider,
            enabled_endpoints=frozenset({"search", "news", "scholar"}),
        )

        captured_params: list[dict[str, Any]] = []

        async def fake_web_search(params: dict[str, Any], **kwargs: Any) -> dict[str, Any]:
            captured_params.append(params)
            return {"status": "ok", "results": []}

        with patch(
            "openrattler.tools.search.web_search_tool.web_search",
            new=fake_web_search,
        ):
            await agent.run(_make_request(), trace_id="test-plan-001")

        print(f"[TestPlanSearchPipelineIntegration] captured params: {captured_params}")
        assert len(captured_params) == 1
        assert captured_params[0].get("endpoint") == "scholar"

    async def test_search_plan_prompt_not_used_during_synthesis(self, tmp_path: Path) -> None:
        """The SEARCH_PLAN.md content must not appear in the synthesis LLM call."""
        plan_response = _make_llm_response(json.dumps({"endpoint": "news", "query": _QUERY}))
        synthesis_response = _make_llm_response("Clean synthesis result.")
        provider = MagicMock(spec=LLMProvider)
        provider.complete = AsyncMock(side_effect=[plan_response, synthesis_response])

        agent, _ = _make_agent(tmp_path, provider=provider)

        with patch(
            "openrattler.tools.search.web_search_tool.web_search",
            new=AsyncMock(return_value={"status": "ok", "results": []}),
        ):
            await agent.run(_make_request(), trace_id="test-plan-002")

        # Second call is synthesis — its system message must be SKILL.md, not SEARCH_PLAN.md
        synthesis_call = provider.complete.call_args_list[1]
        messages = synthesis_call.kwargs.get("messages") or synthesis_call.args[0]
        system_content = next(m["content"] for m in messages if m.get("role") == "system")
        print(f"[TestPlanSearchPipelineIntegration] synthesis system msg: {system_content!r}")
        assert system_content == _SKILL_TEXT
        assert _PLAN_TEXT not in system_content
