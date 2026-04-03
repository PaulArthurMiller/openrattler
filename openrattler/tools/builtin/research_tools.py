"""Research tools — research_query tool for web research via ResearchAgent.

``ResearchTools`` registers the ``research_query`` tool into a ``ToolRegistry``.
All research spawning goes through ``AgentCreator.create_research_agent()``,
which is the authorised and audited pathway for ResearchAgent creation.

SECURITY NOTES
--------------
- The tool constructs a ``UniversalMessage`` with ``trust_level="main"`` before
  calling the AgentCreator pathway.  This is safe because the tool itself is
  gated to ``trust_level_required=TrustLevel.main`` — only main-trust agents
  can invoke it.
- The ResearchAgent is ephemeral: no transcript is written to persistent
  storage.  The sanitizer audit log is the only permanent record.
- Network calls are made by the ResearchAgent, not by this tool handler.
  The ResearchAgent enforces its own content-type, size, and timeout constraints.
"""

from __future__ import annotations

import logging
import uuid
from typing import TYPE_CHECKING

from openrattler.models.agents import TrustLevel
from openrattler.models.messages import UniversalMessage, create_message
from openrattler.models.tools import ToolDefinition
from openrattler.storage.audit import AuditLog

if TYPE_CHECKING:
    from openrattler.agents.creator import AgentCreator
    from openrattler.tools.registry import ToolRegistry

logger = logging.getLogger(__name__)


class ResearchTools:
    """Registers the research_query tool into a ToolRegistry.

    Wraps ResearchAgent execution behind a single callable tool so that
    main-trust agents can trigger web research with a structured query.

    Args:
        creator: The AgentCreator that owns the authorised ResearchAgent spawn
                 pathway.  Every research_query call passes through
                 ``creator.create_research_agent()``.
        audit:   Audit log forwarded to the spawned ResearchAgent so
                 sanitisation decisions are recorded centrally.
    """

    def __init__(self, creator: "AgentCreator", audit: AuditLog) -> None:
        self._creator = creator
        self._audit = audit

    # ------------------------------------------------------------------
    # Registration
    # ------------------------------------------------------------------

    def register_all(self, registry: "ToolRegistry") -> None:
        """Register ``research_query`` into *registry*."""
        registry.register(
            ToolDefinition(
                name="research_query",
                description=(
                    "Search the web for current information and return a structured summary "
                    "with source citations. Use this when you need information beyond your "
                    "training knowledge — breaking news, current events, live data."
                ),
                parameters={
                    "type": "object",
                    "properties": {
                        "query": {
                            "type": "string",
                            "description": "The research question (max 300 characters).",
                        },
                        "max_results": {
                            "type": "integer",
                            "description": (
                                "Maximum number of sources to retrieve (1–10, default 3)."
                            ),
                        },
                    },
                    "required": ["query"],
                },
                trust_level_required=TrustLevel.main,
                requires_approval=False,
                security_notes=(
                    "Spawns an ephemeral ResearchAgent via AgentCreator — the authorised "
                    "spawn pathway.  Output passes through ResearchSanitizer before return. "
                    "Session is ephemeral; no transcript is written to persistent storage. "
                    "Network calls are bounded by ResearchAgentConfig timeouts and size limits."
                ),
            ),
            self._research_query,
        )

    # ------------------------------------------------------------------
    # Tool handler
    # ------------------------------------------------------------------

    async def _research_query(self, query: str, max_results: int = 3) -> str:
        """Execute a research query and return a formatted result string.

        Pipeline:
        1. Construct a UniversalMessage for AgentCreator validation.
        2. Spawn a ResearchAgent via create_research_agent().
        3. Build a ResearchRequest and call agent.run().
        4. Format and return the result.

        Never raises — all error paths return a human-readable error string.
        """
        # Lazy import to avoid top-level circular deps (same pattern as creator.py)
        from openrattler.agents.research.models import ResearchRequest

        trace_id = uuid.uuid4().hex

        # Step 1: Build the UM that create_research_agent() validates.
        # trust_level="main" is safe here: the tool itself requires main trust,
        # so this handler is only reachable by main-trust agents.
        request_msg = create_message(
            from_agent="agent:main:main",
            to_agent="agent:main:main",
            session_key="agent:main:main",
            type="request",
            operation="research_query",
            trust_level="main",
            params={"query": query, "max_results": max_results},
            trace_id=trace_id,
        )

        # Step 2: Spawn the ResearchAgent through the authorised pathway.
        try:
            agent = await self._creator.create_research_agent(request_msg, self._audit)
        except Exception as exc:
            logger.error("research_query: failed to spawn ResearchAgent: %s", exc)
            return f"Research failed: could not spawn research agent — {exc}"

        # Step 3: Build request and execute.
        try:
            request = ResearchRequest(query=query, max_results=max_results)
        except Exception as exc:
            logger.error("research_query: invalid ResearchRequest params: %s", exc)
            return f"Research failed: invalid request parameters — {exc}"

        result_msg: UniversalMessage = await agent.run(request, trace_id)

        # Smoke-test visibility: log the full UM params so we can inspect
        # exactly what the ResearchAgent sends to the calling LLM.
        import json as _json

        logger.info(
            "research_query UM [type=%s trace=%s]:\n%s",
            result_msg.type,
            trace_id,
            _json.dumps(result_msg.params, indent=2, default=str),
        )

        # Step 4: Format and return.
        return self._format_result(result_msg)

    # ------------------------------------------------------------------
    # Formatting helpers
    # ------------------------------------------------------------------

    def _format_result(self, msg: UniversalMessage) -> str:
        """Format a ResearchAgent response UM as a human-readable string."""
        if msg.type == "error":
            err = msg.params
            code = err.get("error_code", "UNKNOWN")
            message = err.get("message", "Unknown error")
            return f"Research error [{code}]: {message}"

        summary = msg.params.get("summary", "No summary available.")
        citations = msg.params.get("citations", [])
        warnings = msg.params.get("warnings", [])

        parts = [f"**Research Summary**\n{summary}"]

        if citations:
            parts.append("\n**Sources**")
            for i, c in enumerate(citations, 1):
                title = c.get("title", "Untitled")
                url = c.get("url", "")
                parts.append(f"{i}. {title} — {url}")
        else:
            parts.append(
                "\n*(No sources retrieved — the web search index is not yet connected. "
                "This summary is based on a stub pipeline.)*"
            )

        if warnings:
            parts.append("\n**Warnings**")
            for w in warnings:
                parts.append(f"- {w}")

        return "\n".join(parts)
