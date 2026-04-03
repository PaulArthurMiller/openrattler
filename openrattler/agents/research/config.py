"""Configuration for a ResearchAgent spawn.

``ResearchAgentConfig`` is validated by ``AgentCreator.create_research_agent``
before the agent is instantiated.

SECURITY NOTES
--------------
- ``allowed_content_types`` is an allowlist; the agent rejects any response
  with a MIME type not in this list before the content enters the context.
- ``max_fetch_size_bytes`` caps the volume of external content the agent
  processes per URL, limiting the injection surface area.
- ``mcp_servers`` defaults to empty; no MCP server receives traffic unless
  explicitly added via an approved manifest.
- ``skill_prompt_path`` must point to an existing SKILL.md at instantiation.
  Missing file raises ``FileNotFoundError`` — silent degradation is not acceptable.
- ``search_plan_path`` must point to an existing SEARCH_PLAN.md at instantiation.
  Same hard-fail policy — a planner without its prompt must not run.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

from openrattler.tools.search.serper_config import SerperConfig

# ---------------------------------------------------------------------------
# Approved model allowlist
# ---------------------------------------------------------------------------

#: Models that may be used for ResearchAgent synthesis.  Any model override
#: submitted via UniversalMessage metadata is validated against this set.
#: Adding a new model requires a code change — no config override possible.
APPROVED_RESEARCH_MODELS: frozenset[str] = frozenset(
    {
        "anthropic/claude-haiku-4-5-20251001",
        "anthropic/claude-haiku-4-5",
        "anthropic/claude-sonnet-4-6",
    }
)


# ---------------------------------------------------------------------------
# ResearchAgentConfig
# ---------------------------------------------------------------------------


@dataclass
class ResearchAgentConfig:
    """Configuration for a ResearchAgent spawn.

    Attributes:
        model:                  LLM model for synthesis.  Must be in
                                ``APPROVED_RESEARCH_MODELS``.
        max_fetch_size_bytes:   Maximum response body size in bytes.  Responses
                                larger than this are rejected before their content
                                enters the context window.
        allowed_content_types:  MIME type allowlist for web_fetch.  Responses
                                with unlisted types are rejected.
        mcp_servers:            MCP server names to expose to this agent.  Empty
                                by default — servers are added via manifest only.
        request_timeout_seconds: HTTP request timeout for web_fetch and
                                web_search calls.
        skill_prompt_path:      Path to SKILL.md.  Loaded at instantiation;
                                missing file raises ``FileNotFoundError``.
        search_plan_path:       Path to SEARCH_PLAN.md.  Loaded at instantiation;
                                missing file raises ``FileNotFoundError``.

    Security notes:
    - ``allowed_content_types`` is the fetch gate.  Do not add ``text/javascript``,
      ``application/x-www-form-urlencoded``, or binary types.
    - ``max_fetch_size_bytes`` at 300 KB is intentionally conservative.  Increase
      only with documented justification — larger values expand the injection surface.
    """

    model: str = "anthropic/claude-haiku-4-5-20251001"
    max_fetch_size_bytes: int = 300_000
    allowed_content_types: list[str] = field(
        default_factory=lambda: ["text/html", "text/plain", "application/json"]
    )
    mcp_servers: list[str] = field(default_factory=list)
    request_timeout_seconds: int = 30
    skill_prompt_path: Path = field(default_factory=lambda: Path(__file__).parent / "SKILL.md")
    search_plan_path: Path = field(default_factory=lambda: Path(__file__).parent / "SEARCH_PLAN.md")
    serper_config: SerperConfig = field(default_factory=SerperConfig)
