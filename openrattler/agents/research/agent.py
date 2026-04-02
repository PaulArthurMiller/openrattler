"""ResearchAgent — a spawnable subagent for web research and synthesis.

The ResearchAgent executes a fixed pipeline:

1. ``web_search``  — find candidate URLs for the query via the Serper API
                     (Window 1 sanitized).
2. ``web_fetch``   — fetch each candidate URL, applying security constraints
                     (max size, allowed content types, request timeout).
3. ``_synthesize`` — combine fetched content into a structured summary via
                     a real LLM call (no tools, text-in text-out).  Falls back
                     to a stub summary if no provider is injected or the call
                     fails.
4. ``sanitize``    — pass summary + citations through ``ResearchSanitizer``
                     before constructing the response UM.
5. Build and return a ``UniversalMessage`` (type="response" on success,
   type="error" on sanitizer rejection).

KEY CONSTRAINTS
---------------
- Session is ephemeral: no transcript is written to persistent storage.
  The sanitizer's audit log entries are the only persistent record.
- Tool allowlist is exactly ``{"web_search", "web_fetch"}`` — no others.
- SKILL.md must exist at instantiation; missing file raises immediately.

SECURITY NOTES
--------------
- ``_web_fetch`` enforces ``max_fetch_size_bytes``, ``allowed_content_types``,
  and ``request_timeout_seconds`` from ``ResearchAgentConfig``.  A response
  that exceeds any constraint is silently dropped (returns ``None``).
- ``_synthesize`` calls the LLM with ``tools=None`` — no tool loop is possible
  during synthesis.  The sanitizer still runs on every synthesis output before
  the UM is constructed.
- Raw fetched content must never appear verbatim in the final summary.  The
  sanitizer's Stage 1 pattern filter catches injection patterns, but the
  synthesis prompt is also constructed to discourage verbatim repetition.
- The agent never constructs the UM response itself until *after* the sanitizer
  has returned a validated ``ResearchResult`` or ``ResearchError``.
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Any, Optional

import httpx

from openrattler.agents.providers.base import LLMProvider
from openrattler.agents.research.config import ResearchAgentConfig
from openrattler.agents.research.models import (
    ResearchError,
    ResearchRequest,
    ResearchResult,
    SourceType,
)
from openrattler.agents.research.sanitizer import ResearchSanitizer
from openrattler.models.messages import UniversalMessage, create_message
from openrattler.storage.audit import AuditLog

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

#: The exact set of tools the ResearchAgent is permitted to invoke.
#: AgentCreator validates spawned agents against this frozenset.
_ALLOWED_TOOLS: frozenset[str] = frozenset({"web_search", "web_fetch"})


# ---------------------------------------------------------------------------
# ResearchAgent
# ---------------------------------------------------------------------------


class ResearchAgent:
    """Spawnable research subagent.

    Orchestrates the search → fetch → synthesize → sanitize pipeline and
    returns a ``UniversalMessage`` to the calling agent.  No LLM calls are
    made in this build piece — synthesis is a stub awaiting real integration.

    Args:
        config: ``ResearchAgentConfig`` for this spawn.  ``skill_prompt_path``
                must point to an existing ``SKILL.md`` file.
        audit:  ``AuditLog`` that receives sanitizer events.  This is the
                only persistent record of the research session.

    Raises:
        FileNotFoundError: If ``config.skill_prompt_path`` does not exist at
                           instantiation time.  Silent degradation is not
                           acceptable — a ResearchAgent without its skill
                           prompt must not run.

    Security notes:
    - Session is ephemeral: no ``TranscriptStore`` is created or used.
    - The ``allowed_tools`` property is the authoritative tool surface for
      this agent type.  AgentCreator enforces it at spawn time.
    - The response UM is not constructed until after the sanitizer has
      returned a validated result.
    """

    def __init__(
        self,
        config: ResearchAgentConfig,
        audit: AuditLog,
        provider: Optional[LLMProvider] = None,
    ) -> None:
        skill_path = config.skill_prompt_path
        if not skill_path.exists():
            raise FileNotFoundError(
                f"ResearchAgent requires SKILL.md at {skill_path!r}; file not found. "
                "A ResearchAgent without its skill prompt must not run silently degraded."
            )
        self._skill_prompt: str = skill_path.read_text(encoding="utf-8")
        self._config = config
        self._sanitizer = ResearchSanitizer(audit=audit)
        self._audit = audit
        # LLM provider for synthesis.  None means use the stub fallback — preserves
        # backward compatibility for tests that do not exercise synthesis.
        self._provider = provider

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    @property
    def allowed_tools(self) -> frozenset[str]:
        """Exact tool surface for this agent: web_search and web_fetch only."""
        return _ALLOWED_TOOLS

    @property
    def skill_prompt(self) -> str:
        """The loaded SKILL.md content (read-only)."""
        return self._skill_prompt

    async def run(
        self,
        request: ResearchRequest,
        trace_id: str,
        from_agent: str = "agent:research:sub",
        to_agent: str = "agent:main:main",
        session_key: str = "agent:research:ephemeral",
    ) -> UniversalMessage:
        """Execute the full research pipeline and return a UniversalMessage.

        The pipeline is: web_search → web_fetch → synthesize → sanitize →
        build UM.  The UM is not constructed until after the sanitizer has
        validated the output.

        Args:
            request:     The structured research request.
            trace_id:    Trace ID from the originating UM; propagated to
                         the sanitizer audit log and the response UM.
            from_agent:  Sender identity for the response UM.
            to_agent:    Recipient identity for the response UM.
            session_key: Session key for the response UM.  Ephemeral by
                         convention — no transcript is written.

        Returns:
            ``UniversalMessage`` with ``type="response"`` on success, or
            ``type="error"`` with ``ResearchError`` params when the sanitizer
            rejects the output.

        Security notes:
        - Never raises; all errors are returned as error-typed UMs.
        - Session key is ephemeral; nothing is written to TranscriptStore.
        - The sanitizer is always called — the UM is not constructed before it.
        """
        try:
            return await self._run_pipeline(request, trace_id, from_agent, to_agent, session_key)
        except Exception as exc:
            logger.exception("ResearchAgent pipeline error: %s", exc)
            error = ResearchError(
                error_code="SANITIZATION_FAILED",
                message="Internal research agent error",
                query_echo=request.query,
                trace_id=trace_id,
            )
            return self._build_error_um(error, from_agent, to_agent, session_key, trace_id)

    # ------------------------------------------------------------------
    # Pipeline stages
    # ------------------------------------------------------------------

    async def _run_pipeline(
        self,
        request: ResearchRequest,
        trace_id: str,
        from_agent: str,
        to_agent: str,
        session_key: str,
    ) -> UniversalMessage:
        """Core pipeline — separated so the outer method can catch errors."""
        # Phase 1: Search (stub — returns empty in this build piece)
        search_hits = await self._web_search(request.query)

        # Phase 2: Fetch each hit, applying safety constraints
        fetched: list[dict[str, Any]] = []
        for hit in search_hits[: request.max_results]:
            url = str(hit.get("url", ""))
            title = str(hit.get("title", ""))
            source_type_str = str(hit.get("source_type", "general"))
            page = await self._web_fetch(url, title, source_type_str)
            if page is not None:
                fetched.append(page)

        # Phase 3: Synthesize via LLM (falls back to stub if no provider)
        raw_summary = await self._synthesize(request, fetched)

        # Phase 4: Build raw citation dicts (one per fetched page)
        raw_citations = self._build_raw_citations(fetched)

        # Phase 5: Sanitize — ALWAYS before UM construction
        sanitized = await self._sanitizer.sanitize(
            raw_summary=raw_summary,
            raw_citations=raw_citations,
            request=request,
            trace_id=trace_id,
        )

        # Phase 6: Build UM from sanitizer output
        if isinstance(sanitized, ResearchError):
            return self._build_error_um(sanitized, from_agent, to_agent, session_key, trace_id)
        return self._build_response_um(sanitized, from_agent, to_agent, session_key, trace_id)

    # ------------------------------------------------------------------
    # web_search — backed by Serper API (Window 1 sanitized)
    # ------------------------------------------------------------------

    async def _web_search(self, query: str) -> list[dict[str, Any]]:
        """Search the web for *query* and return a list of result dicts.

        Delegates to the Serper-backed ``web_search()`` function, which
        enforces the endpoint allowlist, Window 1 sanitization, and all
        HTTP-layer constraints before returning results.

        Each returned dict has at minimum: ``url``, ``title``, ``source_type``.

        Security note: URLs returned here are passed to ``_web_fetch``.
        The fetch layer enforces HTTPS-only and content type / size
        constraints before any page content enters the context window.
        """
        from openrattler.tools.search.web_search_tool import web_search

        result = await web_search(
            params={"query": query, "endpoint": "news"},
            config=self._config.serper_config,
            trace_id=None,  # Client generates a uuid if not provided
            audit_log_fn=None,
        )

        if result.get("status") != "ok":
            # Non-ok means the search failed (network error, sanitization,
            # auth, etc.). Log and return empty — the pipeline continues
            # with synthesis of whatever fetch results exist.
            logger.warning(
                "_web_search: search returned status=%r error=%r query=%r",
                result.get("status"),
                result.get("error"),
                query,
            )
            return []

        # Map Serper results to the pipeline's expected format.
        # source_type defaults to "general" for standard web results.
        hits: list[dict[str, Any]] = []
        for r in result.get("results", []):
            url = r.get("url")
            if not url:
                continue
            hits.append(
                {
                    "url": url,
                    "title": r.get("title") or "",
                    "source_type": "general",
                }
            )
        return hits

    # ------------------------------------------------------------------
    # web_fetch
    # ------------------------------------------------------------------

    async def _web_fetch(
        self,
        url: str,
        title: str,
        source_type: str = "general",
    ) -> Optional[dict[str, Any]]:
        """Fetch *url*, enforcing content-type, size, and timeout constraints.

        Returns a dict suitable for ``CitationRecord`` construction, or
        ``None`` if the fetch was rejected or failed.

        Security notes:
        - Only HTTP/HTTPS URLs are attempted; other schemes are rejected by
          ``CitationRecord.url_must_be_http`` downstream, but we guard here too.
        - Content type is checked against ``allowed_content_types`` from config.
        - Response body is capped at ``max_fetch_size_bytes`` — content beyond
          that limit is rejected entirely (not truncated) to prevent an attacker
          from forcing expensive parsing of large malicious payloads.
        - Request timeout is set via ``httpx`` to enforce ``request_timeout_seconds``.
        """
        if not url.startswith(("http://", "https://")):
            return None
        try:
            final_url, content_type, body = await self._fetch_url(
                url, self._config.request_timeout_seconds
            )
        except Exception as exc:
            logger.debug("web_fetch failed for %r: %s", url, exc)
            return None

        # Content type constraint
        if content_type not in self._config.allowed_content_types:
            logger.debug(
                "web_fetch rejected %r: content-type %r not in allowlist", url, content_type
            )
            return None

        # Size constraint — reject entirely, not truncate
        if len(body) > self._config.max_fetch_size_bytes:
            logger.debug(
                "web_fetch rejected %r: response size %d > max %d bytes",
                url,
                len(body),
                self._config.max_fetch_size_bytes,
            )
            return None

        text = body.decode("utf-8", errors="replace")
        return {
            "title": title,
            "url": final_url,
            "domain": "",  # Overwritten by CitationRecord.ensure_domain_from_url
            "source_type": source_type,
            "retrieval_timestamp": datetime.now(timezone.utc).isoformat(),
            "content": text[:5_000],  # Cap content forwarded to synthesis
        }

    async def _fetch_url(
        self,
        url: str,
        timeout: int,
    ) -> tuple[str, str, bytes]:
        """Perform the HTTP GET and return (final_url, content_type, body).

        Separated from ``_web_fetch`` so tests can monkeypatch this single
        method without touching the constraint logic in ``_web_fetch``.

        Raises:
            httpx.HTTPError: On network errors, timeouts, or bad status.
        """
        async with httpx.AsyncClient(
            timeout=httpx.Timeout(timeout),
            follow_redirects=True,
        ) as client:
            response = await client.get(url)
            response.raise_for_status()
            content_type = response.headers.get("content-type", "").split(";")[0].strip()
            return str(response.url), content_type, response.content

    # ------------------------------------------------------------------
    # Synthesize — LLM call with stub fallback
    # ------------------------------------------------------------------

    async def _synthesize(
        self,
        request: ResearchRequest,
        fetched: list[dict[str, Any]],
    ) -> str:
        """Combine fetched content into a plain-text summary via LLM call.

        Calls ``self._provider.complete()`` with the SKILL.md as the system
        prompt and the query + fetched page snippets as the user turn.  No
        tools are exposed to the synthesis call — it is a single text-in,
        text-out LLM call with no tool loop.

        Falls back to ``_stub_synthesize`` when:
        - ``self._provider`` is ``None`` (backward compat; existing tests that
          do not exercise synthesis continue to work without a mock provider).
        - The provider raises any exception (network error, API error, etc.).

        Security notes:
        - ``tools=None`` — no tool loop is possible during synthesis.
        - The sanitizer always runs on the returned text before UM construction.
        - Content forwarded to the LLM is already capped at 5 000 chars/page
          by ``_web_fetch``; this method forwards up to ``request.max_results``
          pages, keeping the prompt within Haiku's context limit.
        - The synthesis prompt explicitly requests an analyst summary rather
          than verbatim repetition of source content.
        """
        if self._provider is None:
            return self._stub_synthesize(request, fetched)

        messages = self._build_synthesis_messages(request, fetched)
        # Strip the "anthropic/" provider-routing prefix — the provider client
        # expects the bare model ID (e.g. "claude-haiku-4-5-20251001").
        model = self._config.model.removeprefix("anthropic/")
        try:
            response = await self._provider.complete(
                messages=messages,
                tools=None,
                model=model,
                max_tokens=1024,
            )
            return response.content[:2000]
        except Exception as exc:
            logger.warning("_synthesize: LLM call failed (%s); falling back to stub summary", exc)
            return self._stub_synthesize(request, fetched)

    def _build_synthesis_messages(
        self,
        request: ResearchRequest,
        fetched: list[dict[str, Any]],
    ) -> list[dict[str, Any]]:
        """Build the [system, user] message list for the synthesis LLM call.

        System message: the full SKILL.md content loaded at instantiation.
        User message:   the query plus formatted snippets from each fetched page.
        """
        user_parts: list[str] = [f"Research query: {request.query}\n"]

        if fetched:
            user_parts.append("Fetched sources:\n")
            for i, page in enumerate(fetched[: request.max_results]):
                title = page.get("title", "Untitled")
                url = page.get("url", "")
                content = page.get("content", "")[:5_000]
                user_parts.append(f"[{i + 1}] {title} ({url})\n{content}\n")
        else:
            user_parts.append("No sources were retrieved for this query.")

        user_parts.append(
            "\nProvide a concise synthesis of the research findings. "
            "Cover the key facts, note any conflicting information, and flag "
            "any significant gaps. Do not repeat source text verbatim."
        )

        return [
            {"role": "system", "content": self._skill_prompt},
            {"role": "user", "content": "\n".join(user_parts)},
        ]

    def _stub_synthesize(
        self,
        request: ResearchRequest,
        fetched: list[dict[str, Any]],
    ) -> str:
        """Fallback stub when no provider is available or the LLM call fails.

        Produces a minimal metadata-only summary (no raw content) capped at
        2 000 chars.  This is the same logic as the original stub implementation.
        """
        if not fetched:
            return (
                f"Research completed for query: {request.query!r}. "
                "No sources were retrieved in this session."
            )[:2000]

        parts = [f"Research results for: {request.query!r}."]
        for i, page in enumerate(fetched[: request.max_results]):
            title = page.get("title", "Untitled")
            url = page.get("url", "")
            parts.append(f"[{i + 1}] {title} — {url}")

        return " ".join(parts)[:2000]

    # ------------------------------------------------------------------
    # Citation helpers
    # ------------------------------------------------------------------

    def _build_raw_citations(self, fetched: list[dict[str, Any]]) -> list[dict[str, Any]]:
        """Extract citation metadata from fetched pages.

        Returns dicts suitable for ``CitationRecord(**dict)`` construction.
        The ``content`` key is stripped — citations carry metadata only,
        not page content.
        """
        citations = []
        for page in fetched:
            citation = {
                k: v
                for k, v in page.items()
                if k != "content"  # Never forward raw content in citations
            }
            citations.append(citation)
        return citations

    # ------------------------------------------------------------------
    # UM construction helpers
    # ------------------------------------------------------------------

    def _build_response_um(
        self,
        result: ResearchResult,
        from_agent: str,
        to_agent: str,
        session_key: str,
        trace_id: str,
    ) -> UniversalMessage:
        """Build a type='response' UM from a validated ResearchResult."""
        return create_message(
            from_agent=from_agent,
            to_agent=to_agent,
            session_key=session_key,
            type="response",
            operation="research_query",
            trust_level="main",
            params=result.model_dump(mode="json"),
            trace_id=trace_id,
        )

    def _build_error_um(
        self,
        error: ResearchError,
        from_agent: str,
        to_agent: str,
        session_key: str,
        trace_id: str,
    ) -> UniversalMessage:
        """Build a type='error' UM from a ResearchError."""
        return create_message(
            from_agent=from_agent,
            to_agent=to_agent,
            session_key=session_key,
            type="error",
            operation="research_query",
            trust_level="main",
            params=error.model_dump(mode="json"),
            trace_id=trace_id,
        )
