"""Agent models — trust levels, configurations, templates, and spawn limits.

These models define who agents are, what they can do, and under what
constraints they operate.  AgentConfig is the central runtime descriptor
for every agent in the system.
"""

from __future__ import annotations

from enum import Enum
from typing import Literal, Optional

from pydantic import BaseModel, Field, field_validator

# ---------------------------------------------------------------------------
# TrustLevel — agent permission tier
# ---------------------------------------------------------------------------


class TrustLevel(str, Enum):
    """Permission tier for an agent or message.

    Values must exactly match the ``trust_level`` literals in UniversalMessage
    so that permission checks can compare them directly.

    - ``public``:   Sandboxed; read-only tools only (public Discord/Telegram groups)
    - ``main``:     Standard; file read/write, web search (personal DMs)
    - ``local``:    Elevated; exec, full file ops (on-device local agent)
    - ``security``: Special; memory diff, pattern detection (security review agent)
    - ``mcp``:      Per-server; permissions declared in MCP manifest
    """

    public = "public"
    main = "main"
    local = "local"
    security = "security"
    mcp = "mcp"


# ---------------------------------------------------------------------------
# AgentConfig — full runtime descriptor for one agent
# ---------------------------------------------------------------------------

ModelSelection = Literal["fixed", "cost_optimized", "quality_optimized", "adaptive"]


class AgentConfig(BaseModel):
    """Complete configuration for an agent instance.

    Security notes:
    - ``allowed_tools`` is an allowlist; only listed tools may be invoked.
    - ``denied_tools`` is an explicit deny override (takes precedence over
      allowed_tools if a name appears in both).
    - ``trust_level`` must never be escalated beyond the parent agent's level
      when creating subagents.
    - ``can_spawn_subagents`` should only be True for agents explicitly
      authorised to delegate work via the Agent Creator.
    """

    # === Identity ===
    agent_id: str = Field(description="Unique agent identifier, e.g. 'agent:main:main'")
    name: str = Field(description="Human-readable agent name")
    description: str = Field(description="What this agent does")

    # === Model ===
    model: str = Field(description="LLM model string, e.g. 'anthropic/claude-sonnet-4.5'")
    model_selection: ModelSelection = Field(
        default="fixed",
        description="Strategy for choosing which model to use",
    )
    fallback_models: list[str] = Field(
        default_factory=list,
        description="Ordered list of fallback model strings if the primary is unavailable",
    )

    # === Tool Permissions ===
    allowed_tools: list[str] = Field(
        default_factory=list,
        description="Allowlist of tool names this agent may invoke",
    )
    denied_tools: list[str] = Field(
        default_factory=list,
        description="Explicit deny-list of tool names (overrides allowed_tools)",
    )

    # === Security ===
    trust_level: TrustLevel = Field(
        description="Permission tier for this agent; controls which tools and operations it may use"
    )
    can_spawn_subagents: bool = Field(
        default=False,
        description="Whether this agent may request subagent creation via the Agent Creator",
    )

    # === Cost ===
    max_cost_per_turn: Optional[float] = Field(
        default=None,
        description="Per-turn cost cap in USD; None means no cap",
    )

    # === Session / Workspace ===
    session_key: Optional[str] = Field(
        default=None,
        description="Default session key for this agent; usually set at runtime",
    )
    workspace: Optional[str] = Field(
        default=None,
        description="Filesystem path to this agent's workspace directory",
    )

    # === Prompt / Memory ===
    system_prompt: str = Field(
        default="",
        description="Base system prompt template for this agent",
    )
    memory_files: list[str] = Field(
        default_factory=list,
        description="Memory file names to inject into the system prompt (e.g. 'AGENTS.md')",
    )


# ---------------------------------------------------------------------------
# TaskTemplate — reusable subagent type definition
# ---------------------------------------------------------------------------


class TaskTemplate(BaseModel):
    """Template for creating a specialised subagent via the Agent Creator.

    Defines the system prompt, required tools, and cost/complexity guidance
    for a category of tasks (research, coding, execution, analysis).
    """

    name: str
    description: str
    system_prompt: str
    required_tools: list[str]
    suggested_model: str
    typical_complexity_range: tuple[int, int] = Field(
        description="(min, max) complexity scores 0-10 for tasks suited to this template"
    )
    suggested_cost_limit: float = Field(
        default=0.10,
        description="Suggested per-turn cost limit in USD",
    )
    workflow: Optional[list[str]] = Field(
        default=None,
        description="Ordered list of high-level workflow steps (guidance only)",
    )

    @field_validator("typical_complexity_range")
    @classmethod
    def validate_complexity_range(cls, v: tuple[int, int]) -> tuple[int, int]:
        """Ensure min <= max and both values are in [0, 10]."""
        lo, hi = v
        if not (0 <= lo <= 10 and 0 <= hi <= 10):
            raise ValueError("Complexity range values must be between 0 and 10")
        if lo > hi:
            raise ValueError("Complexity range min must be <= max")
        return v


# ---------------------------------------------------------------------------
# AgentCreationRequest — submitted to the Agent Creator
# ---------------------------------------------------------------------------


class AgentCreationRequest(BaseModel):
    """Request to create a specialised subagent.

    Submitted by a main or channel agent to the Agent Creator.  The Creator
    validates this request before spawning any subagent.

    Security notes:
    - ``original_user_message`` is required so the Creator can verify the
      task legitimately follows from what the user actually asked.
    - ``depth`` tracks position in the spawn tree for depth-limit enforcement.
    - ``reason`` is audited and visible in approval prompts.
    """

    # === Requester Identity ===
    from_agent: str = Field(description="Agent requesting creation")
    session_key: str = Field(description="Session context for the new agent")

    # === Task Specification ===
    task: str = Field(description="What the subagent should accomplish")
    task_complexity: int = Field(
        ge=0,
        le=10,
        description="Estimated complexity score 0-10",
    )
    estimated_duration_seconds: Optional[int] = Field(
        default=None,
        description="Expected runtime in seconds (optional hint)",
    )

    # === Agent Type ===
    template: str = Field(description="Name of the task template to use, e.g. 'research', 'coding'")

    # === Customisations ===
    custom_tools: list[str] = Field(
        default_factory=list,
        description="Additional tool names beyond the template's required_tools",
    )
    custom_model: Optional[str] = Field(
        default=None,
        description="Override the template's suggested model",
    )

    # === Resource Limits ===
    max_cost_per_turn: Optional[float] = Field(
        default=None,
        description="Per-turn cost cap in USD; falls back to template's suggested_cost_limit",
    )
    max_runtime_seconds: int = Field(
        default=300,
        description="Hard timeout; agent is killed after this many seconds",
    )

    # === Spawn Context ===
    depth: int = Field(description="Depth in the spawn tree (0 = direct child of main agent)")
    parent_agent: str = Field(description="agent_id of the agent that submitted this request")

    # === Audit / Security ===
    reason: str = Field(description="Why this agent is needed (appears in audit log and approvals)")
    original_user_message: str = Field(
        description="The user's original message; used to verify task-intent alignment"
    )

    # === Retry Handling ===
    is_retry: bool = Field(
        default=False,
        description="True if this is a retry after a previous attempt failed or timed out",
    )
    previous_agent_id: Optional[str] = Field(
        default=None,
        description="agent_id to kill before spawning the new agent (retry flow)",
    )
    task_id: Optional[str] = Field(
        default=None,
        description="Shared task identifier used to find and kill all previous attempts",
    )


# ---------------------------------------------------------------------------
# AgentSpawnLimits — system-wide subagent creation constraints
# ---------------------------------------------------------------------------


class AgentSpawnLimits(BaseModel):
    """System-wide limits on agent spawning.

    All defaults are conservative.  Operators can relax them via config.

    Security notes:
    - ``max_depth`` prevents infinite delegation chains.
    - ``max_total_subagents_per_session`` bounds session-level resource use.
    - ``max_total_cost_per_spawn_chain`` prevents runaway API spend.
    """

    # Depth
    max_depth: int = Field(default=3, description="Maximum spawn tree depth (main=0, L1=1, …)")

    # Width
    max_children_per_agent: int = Field(
        default=5, description="Maximum direct children per parent agent"
    )
    max_total_subagents_per_session: int = Field(
        default=20, description="Total live subagents allowed within one session"
    )

    # Rate
    max_spawns_per_minute: int = Field(default=10, description="Spawn rate limit per minute")
    max_spawns_per_hour: int = Field(default=50, description="Spawn rate limit per hour")

    # Resources
    max_concurrent_agents: int = Field(
        default=10, description="Maximum simultaneously running agents system-wide"
    )
    max_total_cost_per_spawn_chain: float = Field(
        default=1.00, description="Total USD cost cap across one spawn chain"
    )

    # Timeouts
    subagent_max_runtime_seconds: int = Field(
        default=300, description="Hard kill timeout for subagents"
    )
    subagent_idle_timeout_seconds: int = Field(
        default=60, description="Kill subagent after this many seconds of inactivity"
    )

    # Retries
    max_retries_on_failure: int = Field(
        default=2, description="Maximum retry attempts before giving up"
    )
    retry_backoff_seconds: int = Field(
        default=5, description="Seconds to wait between retry attempts"
    )
