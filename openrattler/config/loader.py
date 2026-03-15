"""Configuration loading and data models for OpenRattler.

The central config lives at ``~/.openrattler/config.json`` by default.  All
fields have sensible defaults so a minimal (or even empty) JSON file is valid.

CONFIG STRUCTURE
----------------
AppConfig
├── agents: dict[str, AgentConfig]    — per-agent runtime descriptors
├── security: SecurityConfig          — security profile + per-layer overrides
├── budget: BudgetConfig              — daily/monthly spend limits
└── channels: dict[str, ChannelConfig] — enabled channels + their settings

SECURITY OVERRIDES
------------------
``SecurityConfig.profile`` selects the baseline (minimal / standard / paranoid).
Individual layer fields (``session_isolation``, ``audit_logging``, …) default to
``None``, meaning "use the profile default".  Setting them to ``True`` or
``False`` overrides the profile for that specific layer without touching the
others.  Use ``apply_profile`` from ``openrattler.config.profiles`` to resolve
a config to its fully-explicit form.

SECURITY NOTES
--------------
- ``load_config`` never logs or prints config contents — secrets such as API
  keys must not appear in logs.
- ``save_config`` creates the parent directory with ``mode=0o700`` (user-only
  read/write/execute) to protect credentials stored in the file.
- Pydantic validation is run on every load so malformed configs are caught
  at startup rather than at runtime.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Literal, Optional

from pydantic import BaseModel, Field

from openrattler.models.agents import AgentConfig
from openrattler.models.mcp import MCPSecurityConfig
from openrattler.models.social import SocialSecretaryConfig

# ---------------------------------------------------------------------------
# Default config path
# ---------------------------------------------------------------------------

#: Default location for the user's config file.
DEFAULT_CONFIG_PATH: Path = Path.home() / ".openrattler" / "config.json"


# ---------------------------------------------------------------------------
# SecurityConfig
# ---------------------------------------------------------------------------

SecurityProfile = Literal["minimal", "standard", "paranoid"]


class SecurityConfig(BaseModel):
    """Security settings — a baseline profile plus per-layer overrides.

    The ``profile`` field selects the baseline configuration (see
    ``openrattler.config.profiles.SECURITY_PROFILES``).  Each layer field
    defaults to ``None``, meaning "inherit from profile".  Set a layer to
    ``True`` or ``False`` to override the profile for that layer only.

    Use ``openrattler.config.profiles.apply_profile`` to produce a fully
    explicit ``SecurityConfig`` with all ``None`` values resolved.
    """

    profile: SecurityProfile = Field(
        default="standard",
        description="Baseline security profile: 'minimal', 'standard', or 'paranoid'",
    )

    # ------------------------------------------------------------------
    # Per-layer overrides (None = use profile default)
    # ------------------------------------------------------------------

    # Layer 1 — Session Isolation
    session_isolation: Optional[bool] = Field(
        default=None,
        description="Separate storage per channel/group. Always-on in all profiles.",
    )
    # Layer 2 — Channel Isolation
    channel_isolation: Optional[bool] = Field(
        default=None,
        description="Different agents per trust context (DMs vs groups).",
    )
    # Layer 3 — Agent Trust Levels
    agent_trust_levels: Optional[bool] = Field(
        default=None,
        description="Explicit permission scopes per agent.",
    )
    # Layer 4 — Pitch-Catch Handoffs
    pitch_catch: Optional[bool] = Field(
        default=None,
        description="Security brokers between untrusted components.",
    )
    # Layer 5 — Need-to-Know Isolation
    need_to_know: Optional[bool] = Field(
        default=None,
        description="Minimal information passed to each component.",
    )
    # Layer 6 — Input/Output Filtering
    input_output_filtering: Optional[bool] = Field(
        default=None,
        description="Pydantic validation + path/command sanitization at all boundaries.",
    )
    # Layer 7 — Approval Gates
    approval_gates: Optional[bool] = Field(
        default=None,
        description="Human-in-the-loop approval for high-risk operations.",
    )
    # Layer 8 — Rate Limiting
    rate_limiting: Optional[bool] = Field(
        default=None,
        description="Per-agent rate limits to prevent abuse.",
    )
    # Layer 9 — Audit Logging
    audit_logging: Optional[bool] = Field(
        default=None,
        description="Immutable forensic trail of all security-relevant events.",
    )
    # Layer 10 — Memory Security
    memory_security: Optional[bool] = Field(
        default=None,
        description="Security review of all persistent memory changes.",
    )

    # ------------------------------------------------------------------
    # Additional controls
    # ------------------------------------------------------------------

    heartbeat_history_sanitization: Optional[bool] = Field(
        default=None,
        description=(
            "Wrap public/untrusted session history in adversarial framing "
            "before heartbeat reprompt turns."
        ),
    )
    heartbeat_tool_restriction: Optional[bool] = Field(
        default=None,
        description="Restrict tool allowlist during scheduled heartbeat turns.",
    )
    approval_provenance: Optional[bool] = Field(
        default=None,
        description=(
            "Display system-recorded provenance (origin, trust level, timestamp) "
            "in approval prompts, independently of the agent's stated reason."
        ),
    )
    dependency_hash_verification: Optional[bool] = Field(
        default=None,
        description="Pin all Python dependencies with hash verification.",
    )
    startup_integrity_check: Optional[bool] = Field(
        default=None,
        description=(
            "Verify tool module hashes against a known-good manifest at startup. "
            "Paranoid profile only."
        ),
    )

    # ------------------------------------------------------------------
    # MCP
    # ------------------------------------------------------------------

    mcp_allow_auto_discovered: Optional[str] = Field(
        default=None,
        description=(
            "Policy for auto-discovered MCP servers: " "'allow', 'prompt' (ask user), or 'deny'."
        ),
    )


# ---------------------------------------------------------------------------
# MCPConfig
# ---------------------------------------------------------------------------


class MCPServerEntry(BaseModel):
    """Enable/disable control for a single MCP server."""

    enabled: bool = Field(
        default=True,
        description="Whether this MCP server should be connected at startup.",
    )


class MCPConfig(BaseModel):
    """MCP framework configuration.

    Security notes:
    - ``security`` inherits safe defaults from ``MCPSecurityConfig`` (strict
      network isolation, 30-second timeout, 100 KB response cap).
    - ``servers`` controls which servers connect at startup; unknown server
      IDs here are ignored (the manifest on disk is authoritative).
    """

    security: MCPSecurityConfig = Field(
        default_factory=MCPSecurityConfig,
        description="MCP security settings (trust tiers, size limits, timeouts).",
    )
    servers: dict[str, MCPServerEntry] = Field(
        default_factory=dict,
        description="Per-server enable/disable overrides. Key is the server_id.",
    )


# ---------------------------------------------------------------------------
# BudgetConfig
# ---------------------------------------------------------------------------

BudgetTier = Literal["cheap", "balanced", "quality"]


class BudgetConfig(BaseModel):
    """Spend limits and model-selection tier preference.

    Security notes:
    - Limits are enforced per-session, not just at startup, so a long-running
      session cannot silently exhaust the budget.
    - ``prefer_tier`` influences model selection when no per-agent override
      is set; it does not override explicit per-agent model choices.
    """

    daily_limit_usd: float = Field(
        default=5.00,
        ge=0.0,
        description="Maximum API spend per day in USD.",
    )
    monthly_limit_usd: float = Field(
        default=150.00,
        ge=0.0,
        description="Maximum API spend per month in USD.",
    )
    prefer_tier: BudgetTier = Field(
        default="balanced",
        description=(
            "Preferred cost/quality tier for automatic model selection: "
            "'cheap', 'balanced', or 'quality'."
        ),
    )


# ---------------------------------------------------------------------------
# ChannelConfig
# ---------------------------------------------------------------------------


class ChannelConfig(BaseModel):
    """Configuration for a single communication channel.

    Channel-specific settings (e.g. Twilio SID for SMS, SMTP host for email)
    go in the ``settings`` dict so that the model stays generic while still
    accepting arbitrary per-channel values.
    """

    enabled: bool = Field(
        default=False,
        description="Whether this channel is active.",
    )
    settings: dict[str, Any] = Field(
        default_factory=dict,
        description="Channel-specific settings (e.g. {'twilio_sid': '...', 'smtp_host': '...'}).",
    )


# ---------------------------------------------------------------------------
# AppConfig — top-level configuration model
# ---------------------------------------------------------------------------


# ---------------------------------------------------------------------------
# MemoryConfig
# ---------------------------------------------------------------------------


class MemoryConfig(BaseModel):
    """Configuration for the agent's narrative memory file (MEMORY.md).

    The narrative memory file is a free-form Markdown document loaded into the
    system prompt at session start.  Both limits are enforced in the
    ``update_memory_narrative`` tool using a character-based token approximation
    (``len(text) // 4``) to avoid a tokeniser dependency.

    Security notes:
    - Token limits are enforced before the security review gate, so even a
      legitimate write cannot grow MEMORY.md beyond the configured ceiling.
    - Defaults are conservative; increase ``narrative_max_tokens`` only if the
      assistant consistently runs out of space for meaningful context.
    """

    narrative_max_tokens: int = Field(
        default=2000,
        ge=1,
        description=(
            "Maximum size of MEMORY.md in approximate tokens (chars ÷ 4). "
            "Default 2000. Increase if working memory regularly fills up."
        ),
    )
    narrative_max_write_tokens: int = Field(
        default=300,
        ge=1,
        description=(
            "Maximum tokens allowed in a single write to MEMORY.md. "
            "Keeps individual entries concise. Default 300."
        ),
    )
    user_profile_max_tokens: int = Field(
        default=500,
        ge=1,
        description=(
            "Maximum size of USER.md in approximate tokens (chars ÷ 4). "
            "Default 500. USER.md is always a full replace."
        ),
    )


# ---------------------------------------------------------------------------
# AppConfig — top-level configuration model
# ---------------------------------------------------------------------------


class AppConfig(BaseModel):
    """Top-level OpenRattler configuration.

    All fields have defaults so an empty JSON file ``{}`` is a valid config
    that uses sensible defaults throughout.

    Security notes:
    - ``agents`` and ``channels`` may contain API keys or secrets in their
      ``settings`` fields.  Never log this object in full.
    - The ``security`` field controls all 10 security layers.  Defaults to
      the ``standard`` profile.
    - Pydantic validation runs on every ``load_config`` call, so malformed
      values are caught at startup.
    """

    agents: dict[str, AgentConfig] = Field(
        default_factory=dict,
        description="Named agent configurations.  Key is the agent's short name.",
    )
    security: SecurityConfig = Field(
        default_factory=SecurityConfig,
        description="Security profile and per-layer overrides.",
    )
    budget: BudgetConfig = Field(
        default_factory=BudgetConfig,
        description="Daily/monthly spend limits and model-tier preference.",
    )
    channels: dict[str, ChannelConfig] = Field(
        default_factory=dict,
        description="Named channel configurations.  Key is the channel name.",
    )
    mcp: MCPConfig = Field(
        default_factory=MCPConfig,
        description="MCP framework configuration (security settings and server list).",
    )
    social_secretary: SocialSecretaryConfig = Field(
        default_factory=SocialSecretaryConfig,
        description="Social Secretary proactive processor configuration.",
    )
    memory: MemoryConfig = Field(
        default_factory=MemoryConfig,
        description="Narrative memory (MEMORY.md) and user profile (USER.md) size limits.",
    )


# ---------------------------------------------------------------------------
# load_config / save_config
# ---------------------------------------------------------------------------


def load_config(config_path: Path = DEFAULT_CONFIG_PATH) -> AppConfig:
    """Load and validate ``AppConfig`` from *config_path*.

    If the file does not exist, a default ``AppConfig`` is returned.  All
    missing fields are filled with their Pydantic defaults.

    Args:
        config_path: Path to the JSON config file.  Defaults to
                     ``~/.openrattler/config.json``.

    Returns:
        A validated ``AppConfig`` instance.

    Raises:
        json.JSONDecodeError:       If the file exists but is not valid JSON.
        pydantic.ValidationError:   If the JSON is valid but fails schema
                                    validation (e.g. a required AgentConfig
                                    field is missing).

    Security notes:
    - The function never logs config contents; secrets in ``channels`` or
      ``agents`` settings remain private.
    - A missing config file is treated as an empty config (all defaults
      applied), not as an error, so the first run works without setup.
    """
    if not config_path.exists():
        return AppConfig()

    raw = config_path.read_text(encoding="utf-8")
    data: dict[str, Any] = json.loads(raw)
    return AppConfig.model_validate(data)


def save_config(config: AppConfig, config_path: Path = DEFAULT_CONFIG_PATH) -> None:
    """Serialise *config* to JSON and write it to *config_path*.

    The parent directory is created automatically if it does not exist.
    The directory is created with ``mode=0o700`` (user-only permissions)
    to protect any secrets stored inside.

    Args:
        config:      The ``AppConfig`` to persist.
        config_path: Destination path.  Defaults to
                     ``~/.openrattler/config.json``.

    Security notes:
    - The parent directory is created with ``mode=0o700`` so only the
      owning user can list or read files inside it.
    - ``model_dump`` serialises ``None`` values so that a reload produces
      the same ``AppConfig`` (Pydantic applies defaults to ``None`` fields,
      preserving the "use profile default" semantics).
    """
    config_path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    payload = config.model_dump()
    config_path.write_text(
        json.dumps(payload, indent=2, default=str),
        encoding="utf-8",
    )
