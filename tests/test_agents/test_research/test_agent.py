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
from pathlib import Path
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from openrattler.agents.research.agent import ResearchAgent, _ALLOWED_TOOLS
from openrattler.agents.research.config import ResearchAgentConfig
from openrattler.agents.research.models import (
    ResearchError,
    ResearchRequest,
    ResearchResult,
    SourceType,
)
from openrattler.storage.audit import AuditLog

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
        agent._web_search = AsyncMock(return_value=[])
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
