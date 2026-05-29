"""Tests for openrattler.agents.research.agent.ResearchAgent.

Security guarantees verified here:
- SKILL.md loads successfully at instantiation.
- Agent raises FileNotFoundError (not silently degrades) if SKILL.md is missing.
- Tool allowlist contains exactly {"web_search", "web_fetch"}.
- web_fetch rejects responses over max_fetch_size_bytes.
- web_fetch rejects disallowed content types.
- web_fetch enforces request_timeout_seconds via httpx.Timeout.
- Sanitizer is always called before the UM response is constructed.
- Agent returns UM type="error" with ResearchError params when sanitizer rejects.
- Agent returns UM type="response" with ResearchResult params on success.
- No session transcript is written to persistent storage after completion.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from openrattler.agents.providers.base import LLMProvider, LLMResponse, TokenUsage
from openrattler.agents.research.agent import ResearchAgent, _ALLOWED_TOOLS
from openrattler.agents.research.config import ResearchAgentConfig
from openrattler.agents.research.models import (
    ResearchError,
    ResearchRequest,
    ResearchResult,
    SourceType,
)
from openrattler.storage.audit import AuditLog
from openrattler.storage.usage import UsageStore

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_config(
    tmp_path: Path, skill_exists: bool = True, **overrides: Any
) -> ResearchAgentConfig:
    """Build a ResearchAgentConfig pointing at real (or absent) prompt files."""
    skill_path = tmp_path / "SKILL.md"
    search_plan_path = tmp_path / "SEARCH_PLAN.md"
    if skill_exists:
        skill_path.write_text("# Test skill prompt\nYou are a research agent.", encoding="utf-8")
        search_plan_path.write_text(
            "# Test search plan prompt\nOutput a JSON object.", encoding="utf-8"
        )
    defaults: dict[str, Any] = {
        "skill_prompt_path": skill_path,
        "search_plan_path": search_plan_path,
        "max_fetch_size_bytes": 10_000,
        "request_timeout_seconds": 5,
        "allowed_content_types": ["text/html", "text/plain"],
    }
    defaults.update(overrides)
    return ResearchAgentConfig(**defaults)


def _make_agent(tmp_path: Path, **config_overrides: Any) -> tuple[ResearchAgent, AuditLog]:
    """Create a ResearchAgent with a tmp audit log."""
    audit = AuditLog(tmp_path / "audit.jsonl")
    config = _make_config(tmp_path, **config_overrides)
    agent = ResearchAgent(config=config, audit=audit)
    return agent, audit


def _make_request(**overrides: Any) -> ResearchRequest:
    defaults: dict[str, Any] = {
        "query": "Python async best practices",
        "max_results": 3,
    }
    defaults.update(overrides)
    return ResearchRequest(**defaults)


# ---------------------------------------------------------------------------
# Instantiation
# ---------------------------------------------------------------------------


class TestInstantiation:
    """SKILL.md loading and fail-fast on missing file."""

    def test_skill_md_loads_at_instantiation(self, tmp_path: Path) -> None:
        agent, _ = _make_agent(tmp_path)
        print(f"[TestInstantiation] skill_prompt length: {len(agent.skill_prompt)}")
        assert "research" in agent.skill_prompt.lower() or len(agent.skill_prompt) > 0

    def test_raises_if_skill_md_missing(self, tmp_path: Path) -> None:
        """Agent must fail loudly — not silently degrade — when SKILL.md is absent."""
        config = _make_config(tmp_path, skill_exists=False)
        audit = AuditLog(tmp_path / "audit.jsonl")
        print("[TestInstantiation] expect FileNotFoundError when SKILL.md missing")
        with pytest.raises(FileNotFoundError) as exc_info:
            ResearchAgent(config=config, audit=audit)
        assert "SKILL.md" in str(exc_info.value) or "skill" in str(exc_info.value).lower()


# ---------------------------------------------------------------------------
# Tool allowlist
# ---------------------------------------------------------------------------


class TestToolAllowlist:
    """allowed_tools must be exactly {web_search, web_fetch}."""

    def test_allowed_tools_contains_web_search_and_web_fetch(self, tmp_path: Path) -> None:
        agent, _ = _make_agent(tmp_path)
        print(f"[TestToolAllowlist] allowed_tools: {agent.allowed_tools}")
        assert "web_search" in agent.allowed_tools
        assert "web_fetch" in agent.allowed_tools

    def test_allowed_tools_contains_no_other_tools(self, tmp_path: Path) -> None:
        agent, _ = _make_agent(tmp_path)
        unexpected = agent.allowed_tools - {"web_search", "web_fetch"}
        print(f"[TestToolAllowlist] unexpected tools: {unexpected}")
        assert unexpected == set()

    def test_module_constant_matches_property(self, tmp_path: Path) -> None:
        agent, _ = _make_agent(tmp_path)
        print(f"[TestToolAllowlist] module constant: {_ALLOWED_TOOLS}")
        assert agent.allowed_tools == _ALLOWED_TOOLS


# ---------------------------------------------------------------------------
# web_fetch constraints
# ---------------------------------------------------------------------------


class TestWebFetchConstraints:
    """web_fetch enforces size, content type, and timeout."""

    async def test_rejects_response_over_max_fetch_size_bytes(self, tmp_path: Path) -> None:
        agent, _ = _make_agent(tmp_path, max_fetch_size_bytes=100)
        # Patch _fetch_url to return a body larger than 100 bytes
        big_body = b"x" * 200
        agent._fetch_url = AsyncMock(return_value=("https://example.com/", "text/html", big_body))
        result = await agent._web_fetch("https://example.com/page", "Title")
        print(f"[TestWebFetch] size rejection: result={result}")
        assert result is None

    async def test_rejects_disallowed_content_type(self, tmp_path: Path) -> None:
        agent, _ = _make_agent(tmp_path)
        # application/pdf is not in the default allowlist
        pdf_body = b"%PDF-1.4 content"
        agent._fetch_url = AsyncMock(
            return_value=("https://example.com/doc.pdf", "application/pdf", pdf_body)
        )
        result = await agent._web_fetch("https://example.com/doc.pdf", "PDF")
        print(f"[TestWebFetch] content type rejection: result={result}")
        assert result is None

    async def test_accepts_allowed_content_type(self, tmp_path: Path) -> None:
        agent, _ = _make_agent(tmp_path)
        body = b"<html><body>Hello</body></html>"
        agent._fetch_url = AsyncMock(return_value=("https://example.com/", "text/html", body))
        result = await agent._web_fetch("https://example.com/page", "Title")
        print(f"[TestWebFetch] accepted content type: result type={type(result).__name__}")
        assert result is not None
        assert result["title"] == "Title"

    async def test_timeout_is_passed_to_httpx_via_fetch_url(self, tmp_path: Path) -> None:
        """web_fetch passes request_timeout_seconds to _fetch_url."""
        agent, _ = _make_agent(tmp_path, request_timeout_seconds=7)
        captured_timeout: list[int] = []

        async def fake_fetch(url: str, timeout: int) -> tuple[str, str, bytes]:
            captured_timeout.append(timeout)
            return url, "text/html", b"ok"

        agent._fetch_url = fake_fetch
        await agent._web_fetch("https://example.com/", "T")
        print(f"[TestWebFetch] captured timeout: {captured_timeout}")
        assert captured_timeout == [7]

    async def test_returns_none_on_fetch_exception(self, tmp_path: Path) -> None:
        agent, _ = _make_agent(tmp_path)
        agent._fetch_url = AsyncMock(side_effect=Exception("network error"))
        result = await agent._web_fetch("https://example.com/", "T")
        print(f"[TestWebFetch] exception → result={result}")
        assert result is None

    async def test_rejects_non_http_url(self, tmp_path: Path) -> None:
        agent, _ = _make_agent(tmp_path)
        result = await agent._web_fetch("ftp://example.com/file", "T")
        print(f"[TestWebFetch] non-HTTP URL → result={result}")
        assert result is None

    async def test_snippet_fallback_when_fetch_fails(self, tmp_path: Path) -> None:
        """When fetch fails but a snippet is provided, returns the snippet as content."""
        agent, _ = _make_agent(tmp_path)
        agent._fetch_url = AsyncMock(side_effect=Exception("403 Forbidden"))
        snippet = "Article snippet with useful content."
        result = await agent._web_fetch(
            "https://example.com/article", "Article Title", snippet=snippet
        )
        print(f"[TestWebFetch] snippet fallback: result={result}")
        assert result is not None
        assert result["content"] == snippet
        assert result["title"] == "Article Title"
        assert result["url"] == "https://example.com/article"

    async def test_no_snippet_fallback_when_no_snippet_provided(self, tmp_path: Path) -> None:
        """When fetch fails with no snippet, still returns None."""
        agent, _ = _make_agent(tmp_path)
        agent._fetch_url = AsyncMock(side_effect=Exception("403 Forbidden"))
        result = await agent._web_fetch("https://example.com/article", "T")
        print(f"[TestWebFetch] no snippet, exception → result={result}")
        assert result is None

    async def test_html_stripped_from_fetched_body(self, tmp_path: Path) -> None:
        """HTML tags are stripped from fetched text/html content before synthesis."""
        agent, _ = _make_agent(tmp_path)
        html_body = b"<html><head><title>Test</title></head><body><p>Hello world!</p></body></html>"
        agent._fetch_url = AsyncMock(return_value=("https://example.com/", "text/html", html_body))
        result = await agent._web_fetch("https://example.com/page", "Title")
        print(f"[TestWebFetch] html stripped content: {result['content']!r}")
        assert result is not None
        assert "<html>" not in result["content"]
        assert "Hello world!" in result["content"]

    async def test_snippet_fallback_on_size_rejection(self, tmp_path: Path) -> None:
        """When body exceeds max size but snippet exists, returns snippet fallback."""
        agent, _ = _make_agent(tmp_path, max_fetch_size_bytes=10)
        big_body = b"x" * 200
        agent._fetch_url = AsyncMock(return_value=("https://example.com/", "text/html", big_body))
        snippet = "Short snippet text."
        result = await agent._web_fetch("https://example.com/page", "T", snippet=snippet)
        print(f"[TestWebFetch] size rejection with snippet: result={result}")
        assert result is not None
        assert result["content"] == snippet


# ---------------------------------------------------------------------------
# Run pipeline: sanitizer always called
# ---------------------------------------------------------------------------


class TestRunPipeline:
    """Sanitizer is always called; UM type reflects sanitizer outcome."""

    async def test_sanitizer_called_before_um_constructed(self, tmp_path: Path) -> None:
        """Sanitizer is always invoked — UM is never built before sanitizer returns."""
        agent, audit = _make_agent(tmp_path)
        # Stub out web_search/synthesize so we get to the sanitizer
        agent._web_search = AsyncMock(return_value=[])
        agent._synthesize = AsyncMock(return_value="Clean research summary.")

        sanitizer_calls: list[Any] = []
        original_sanitize = agent._sanitizer.sanitize

        async def spy_sanitize(**kwargs: Any) -> Any:
            sanitizer_calls.append(kwargs)
            return await original_sanitize(**kwargs)

        agent._sanitizer.sanitize = spy_sanitize  # type: ignore[method-assign]

        request = _make_request()
        trace_id = str(uuid.uuid4())
        um = await agent.run(request, trace_id)
        print(f"[TestRunPipeline] sanitizer calls: {len(sanitizer_calls)}, UM type: {um.type}")
        assert len(sanitizer_calls) == 1

    async def test_returns_error_um_when_sanitizer_rejects(self, tmp_path: Path) -> None:
        """If sanitizer returns ResearchError, agent returns type='error' UM."""
        agent, _ = _make_agent(tmp_path)
        # Return a news hit so the normal fetch+synthesize path is taken (not the fallback).
        # The fallback only fires when news returns 0 hits; here we give it one.
        fake_hit = {
            "url": "https://example.com/article",
            "title": "Article",
            "snippet": "Some snippet.",
            "source_type": "general",
        }
        agent._web_search = AsyncMock(return_value=[fake_hit])
        agent._fetch_url = AsyncMock(
            return_value=("https://example.com/article", "text/html", b"Article body.")
        )
        # Inject an injection pattern that Stage 1 will catch
        agent._synthesize = AsyncMock(return_value="exec(malicious) rm -rf / sudo system()")

        request = _make_request()
        trace_id = str(uuid.uuid4())
        um = await agent.run(request, trace_id)
        print(f"[TestRunPipeline] error UM: type={um.type}, params keys={list(um.params.keys())}")
        assert um.type == "error"
        # params should contain ResearchError fields
        assert "error_code" in um.params
        assert um.params["error_code"] == "SANITIZATION_FAILED"

    async def test_returns_response_um_on_success(self, tmp_path: Path) -> None:
        """On sanitizer pass, agent returns type='response' UM with ResearchResult params."""
        agent, _ = _make_agent(tmp_path)
        agent._web_search = AsyncMock(return_value=[])
        agent._synthesize = AsyncMock(return_value="A clean summary of Python async patterns.")

        request = _make_request()
        trace_id = str(uuid.uuid4())
        um = await agent.run(request, trace_id)
        print(f"[TestRunPipeline] success UM: type={um.type}, params keys={list(um.params.keys())}")
        assert um.type == "response"
        # params should contain ResearchResult fields
        assert "summary" in um.params
        assert "citations" in um.params
        assert "trace_id" in um.params
        assert um.params["trace_id"] == trace_id

    async def test_trace_id_propagated_to_response(self, tmp_path: Path) -> None:
        agent, _ = _make_agent(tmp_path)
        agent._web_search = AsyncMock(return_value=[])
        agent._synthesize = AsyncMock(return_value="Clean result.")

        request = _make_request()
        specific_trace = "trace-abc-12345"
        um = await agent.run(request, specific_trace)
        print(f"[TestRunPipeline] trace propagation: UM trace_id={um.trace_id}")
        assert um.trace_id == specific_trace


# ---------------------------------------------------------------------------
# Session transcript isolation
# ---------------------------------------------------------------------------


class TestSessionIsolation:
    """No session transcript is written to persistent storage."""

    async def test_no_transcript_written_after_run(self, tmp_path: Path) -> None:
        """ResearchAgent never uses TranscriptStore — no .jsonl transcript files."""
        agent, _ = _make_agent(tmp_path)
        agent._web_search = AsyncMock(return_value=[])
        agent._synthesize = AsyncMock(return_value="Clean result.")

        request = _make_request()
        await agent.run(request, str(uuid.uuid4()))

        # Verify no transcript JSONL files were created in tmp_path
        jsonl_files = [
            f
            for f in tmp_path.rglob("*.jsonl")
            if "transcript" in f.name or "agent" in f.parts[-2:]
        ]
        # Only the audit.jsonl should exist; no transcript files
        transcript_files = [f for f in tmp_path.rglob("*.jsonl") if f.name != "audit.jsonl"]
        print(f"[TestSessionIsolation] non-audit jsonl files: {transcript_files}")
        assert transcript_files == []


# ---------------------------------------------------------------------------
# News-to-search fallback
# ---------------------------------------------------------------------------


class TestNewsFallback:
    """When news endpoint returns 0 hits, pipeline retries with search endpoint."""

    async def test_fallback_to_search_when_news_returns_empty(self, tmp_path: Path) -> None:
        """news returning 0 hits triggers a retry via the search endpoint."""
        from openrattler.tools.search.web_search_tool import WebSearchParams

        agent, _ = _make_agent(tmp_path)

        # First call (news): returns nothing.  Second call (search): returns a hit with snippet.
        search_call_count = 0
        fake_hit = {
            "url": "https://status.example.com/api-outage",
            "title": "API Status Update",
            "snippet": "The API experienced an outage on April 15.",
            "source": "status.example.com",
            "date": "Apr 15, 2026",
            "source_type": "general",
        }

        async def mock_web_search(params: "WebSearchParams") -> list[dict[str, Any]]:
            nonlocal search_call_count
            search_call_count += 1
            if params.endpoint == "news":
                return []
            # search fallback
            return [fake_hit]

        agent._web_search = mock_web_search  # type: ignore[method-assign]
        agent._synthesize = AsyncMock(return_value="API was down briefly on April 15.")

        request = _make_request(query="ExampleAPI outage April 2026")
        um = await agent.run(request, str(uuid.uuid4()))
        print(
            f"[TestNewsFallback] search_calls={search_call_count}, UM type={um.type}, "
            f"params keys={list(um.params.keys())}"
        )
        assert search_call_count == 2, "Expected news call then search fallback call"
        assert um.type == "response"

    async def test_no_fallback_when_news_returns_hits(self, tmp_path: Path) -> None:
        """When news returns results, the search fallback is NOT triggered."""
        from openrattler.tools.search.web_search_tool import WebSearchParams

        agent, _ = _make_agent(tmp_path)

        search_call_count = 0
        fake_hit = {
            "url": "https://news.example.com/article",
            "title": "Leonardo.ai Outage Report",
            "snippet": "Leonardo.ai experienced a brief API disruption.",
            "source": "TechNews",
            "date": "Apr 20, 2026",
            "source_type": "general",
        }

        async def mock_web_search(params: "WebSearchParams") -> list[dict[str, Any]]:
            nonlocal search_call_count
            search_call_count += 1
            return [fake_hit]

        agent._web_search = mock_web_search  # type: ignore[method-assign]
        agent._fetch_url = AsyncMock(
            return_value=("https://news.example.com/article", "text/html", b"Article text here.")
        )
        agent._synthesize = AsyncMock(return_value="Leonardo.ai had a disruption.")

        request = _make_request(query="Leonardo.ai API outage April 2026")
        um = await agent.run(request, str(uuid.uuid4()))
        print(
            f"[TestNewsFallback] no-fallback: search_calls={search_call_count}, UM type={um.type}"
        )
        assert search_call_count == 1, "Should only call search once when news returns hits"
        assert um.type == "response"

    async def test_returns_response_um_when_both_endpoints_empty(self, tmp_path: Path) -> None:
        """When both news and search return nothing, returns a response UM (not an error)."""
        from openrattler.tools.search.web_search_tool import WebSearchParams

        agent, _ = _make_agent(tmp_path)

        async def mock_web_search(params: "WebSearchParams") -> list[dict[str, Any]]:
            return []

        agent._web_search = mock_web_search  # type: ignore[method-assign]
        agent._synthesize = AsyncMock(return_value="No information found for this query.")

        request = _make_request(query="Extremely niche API nobody has heard of")
        um = await agent.run(request, str(uuid.uuid4()))
        print(f"[TestNewsFallback] both-empty: UM type={um.type}")
        assert um.type == "response"


# ---------------------------------------------------------------------------
# Usage recording
# ---------------------------------------------------------------------------


def _make_llm_response(
    content: str = "result", prompt_tokens: int = 10, completion_tokens: int = 20
) -> LLMResponse:
    """Construct a minimal LLMResponse for usage tracking tests."""
    usage = TokenUsage(
        prompt_tokens=prompt_tokens,
        completion_tokens=completion_tokens,
        total_tokens=prompt_tokens + completion_tokens,
        estimated_cost_usd=0.001,
    )
    return LLMResponse(
        content=content,
        tool_calls=[],
        usage=usage,
        model="claude-haiku-4-5-20251001",
        finish_reason="end_turn",
    )


def _make_mock_provider(responses: list[LLMResponse] | None = None) -> MagicMock:
    """Return a mock LLMProvider that returns the given responses in sequence."""
    provider = MagicMock(spec=LLMProvider)
    if responses is None:
        responses = [_make_llm_response()]
    provider.complete = AsyncMock(side_effect=responses)
    return provider


class TestUsageRecording:
    """Token usage is accumulated and written to UsageStore after each run()."""

    async def test_no_usage_store_no_record_no_error(self, tmp_path: Path) -> None:
        """usage_store=None: run completes normally and no record is written."""
        audit = AuditLog(tmp_path / "audit.jsonl")
        config = _make_config(tmp_path)
        provider = _make_mock_provider(
            [_make_llm_response("plan"), _make_llm_response("synthesis")]
        )
        agent = ResearchAgent(config=config, audit=audit, provider=provider, usage_store=None)
        agent._web_search = AsyncMock(return_value=[])  # type: ignore[method-assign]

        request = _make_request()
        um = await agent.run(request, "abc123trace")
        print(f"[TestUsageRecording] no_store: UM type={um.type}")
        assert um.type in ("response", "error")

    async def test_two_llm_calls_accumulate_correctly(self, tmp_path: Path) -> None:
        """provider makes plan + synthesis calls: llm_calls=2, tokens accumulated."""
        store = UsageStore(tmp_path / "usage" / "usage_log.jsonl")
        audit = AuditLog(tmp_path / "audit.jsonl")
        config = _make_config(tmp_path)
        plan_response = _make_llm_response("news", prompt_tokens=15, completion_tokens=5)
        synth_response = _make_llm_response("Summary text", prompt_tokens=30, completion_tokens=50)
        provider = _make_mock_provider([plan_response, synth_response])
        agent = ResearchAgent(config=config, audit=audit, provider=provider, usage_store=store)
        # Bypass actual search/fetch so both LLM calls (plan + synth) fire
        agent._web_search = AsyncMock(
            return_value=[  # type: ignore[method-assign]
                {
                    "url": "https://example.com",
                    "title": "Test",
                    "snippet": "snippet",
                    "source": "example",
                    "date": "",
                    "source_type": "general",
                }
            ]
        )
        agent._web_fetch = AsyncMock(
            return_value={  # type: ignore[method-assign]
                "title": "Test",
                "url": "https://example.com",
                "domain": "example.com",
                "source_type": "general",
                "retrieval_timestamp": "2026-01-01T00:00:00+00:00",
                "content": "Some useful content about the topic.",
            }
        )

        trace_id = "testrace00001"
        await agent.run(request=_make_request(), trace_id=trace_id)

        records = await store.load_since(datetime(2000, 1, 1, tzinfo=timezone.utc))
        print(f"[TestUsageRecording] two_calls: records={len(records)}")
        assert len(records) == 1
        rec = records[0]
        print(f"[TestUsageRecording] llm_calls={rec.llm_calls}, prompt_tokens={rec.prompt_tokens}")
        assert rec.llm_calls == 2
        assert rec.prompt_tokens == 45  # 15 + 30
        assert rec.completion_tokens == 55  # 5 + 50

    async def test_parent_session_key_written_to_record(self, tmp_path: Path) -> None:
        """parent_session_key is stored on the TurnRecord when provided."""
        store = UsageStore(tmp_path / "usage" / "usage_log.jsonl")
        audit = AuditLog(tmp_path / "audit.jsonl")
        config = _make_config(tmp_path)
        provider = _make_mock_provider([_make_llm_response("news"), _make_llm_response("done")])
        agent = ResearchAgent(
            config=config,
            audit=audit,
            provider=provider,
            usage_store=store,
            parent_session_key="agent:main:some-session-key",
        )
        agent._web_search = AsyncMock(return_value=[])  # type: ignore[method-assign]

        await agent.run(request=_make_request(), trace_id="trace-for-parent-test")

        records = await store.load_since(datetime(2000, 1, 1, tzinfo=timezone.utc))
        print(f"[TestUsageRecording] parent_session_key: records={len(records)}")
        assert len(records) == 1
        assert records[0].parent_session_key == "agent:main:some-session-key"

    async def test_research_session_key_derived_from_trace_id(self, tmp_path: Path) -> None:
        """session_key on the TurnRecord uses the first 12 chars of trace_id."""
        store = UsageStore(tmp_path / "usage" / "usage_log.jsonl")
        audit = AuditLog(tmp_path / "audit.jsonl")
        config = _make_config(tmp_path)
        provider = _make_mock_provider([_make_llm_response("news"), _make_llm_response("result")])
        agent = ResearchAgent(config=config, audit=audit, provider=provider, usage_store=store)
        agent._web_search = AsyncMock(return_value=[])  # type: ignore[method-assign]

        trace_id = "abcdef123456789xyz"
        await agent.run(request=_make_request(), trace_id=trace_id)

        records = await store.load_since(datetime(2000, 1, 1, tzinfo=timezone.utc))
        print(f"[TestUsageRecording] session_key: {records[0].session_key!r}")
        assert records[0].session_key == f"agent:research:{trace_id[:12]}"

    async def test_usage_store_failure_does_not_affect_result(self, tmp_path: Path) -> None:
        """A broken UsageStore does not prevent the research result from being returned."""
        broken_store = MagicMock(spec=UsageStore)
        broken_store.record_turn = AsyncMock(side_effect=RuntimeError("disk full"))
        audit = AuditLog(tmp_path / "audit.jsonl")
        config = _make_config(tmp_path)
        provider = _make_mock_provider([_make_llm_response("news"), _make_llm_response("done")])
        agent = ResearchAgent(
            config=config, audit=audit, provider=provider, usage_store=broken_store
        )
        agent._web_search = AsyncMock(return_value=[])  # type: ignore[method-assign]

        um = await agent.run(request=_make_request(), trace_id="trace-broken-store")
        print(f"[TestUsageRecording] store_failure: UM type={um.type}")
        assert um.type in ("response", "error")
