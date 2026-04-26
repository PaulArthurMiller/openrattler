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

from pydantic import BaseModel, Field, field_validator

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
    # Action approval threshold (piece 39.3)
    # ------------------------------------------------------------------

    approval_threshold: Optional[int] = Field(
        default=None,
        description=(
            "Override the profile's default approval threshold. "
            "Tools with action_level <= this value require human approval. "
            "Valid range: 1 (approve only level-1 actions) to 5 (approve everything). "
            "None means use the profile default: minimal=1, standard=3, paranoid=5."
        ),
    )

    @field_validator("approval_threshold")
    @classmethod
    def _validate_approval_threshold(cls, v: Optional[int]) -> Optional[int]:
        """Reject out-of-range threshold values rather than silently clamping them.

        Silent clamping would hide misconfiguration (e.g. a typo of 0 instead of 1
        would silently disable all approval gates in a minimal profile).
        """
        if v is not None and not (1 <= v <= 5):
            raise ValueError(
                f"approval_threshold must be between 1 and 5 (got {v}). "
                "Valid values: 1 (approve only permanent/irreversible actions) "
                "to 5 (require approval for all actions including read-only)."
            )
        return v

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
    identity_max_tokens: int = Field(
        default=500,
        ge=1,
        description=(
            "Maximum size of IDENTITY.md in approximate tokens (chars ÷ 4). "
            "Default 500. IDENTITY.md is always a full replace."
        ),
    )


# ---------------------------------------------------------------------------
# ToolsConfig
# ---------------------------------------------------------------------------


class HeartbeatConfig(BaseModel):
    """Configuration for the scheduled heartbeat check-in processor.

    The heartbeat processor runs the main agent on a timer with HEARTBEAT.md
    injected into the system prompt so the agent can review pending alerts
    and working memory in a brief background turn.

    Security notes:
    - The heartbeat runs in a separate session (``agent:main:heartbeat``) so
      it never races with the user's active CLI session.
    - Disable the heartbeat (``enabled: false``) if the agent should only run
      reactively.
    """

    enabled: bool = Field(
        default=True,
        description=(
            "Whether the heartbeat processor is active. "
            "Set to false to disable scheduled background check-ins."
        ),
    )
    interval_minutes: int = Field(
        default=60,
        ge=1,
        description=(
            "How often (in minutes) the heartbeat turn runs. " "Default 60 (hourly). Minimum 1."
        ),
    )
    log_context_entries: int = Field(
        default=7,
        ge=1,
        le=50,
        description=(
            "How many recent heartbeat log entries are injected into each heartbeat "
            "system prompt.  Default 7 suits an active daily user.  Raise to 20–30 "
            "for users with low direct-interaction periods (e.g. background monitoring "
            "use cases) where pattern detection requires a longer lookback window."
        ),
    )
    log_max_retained: int = Field(
        default=100,
        ge=10,
        description=(
            "Total heartbeat log entries kept on disk.  Intentionally larger than "
            "log_context_entries — the audit trail and the LLM context window have "
            "different optimal sizes.  100 entries at 60-min intervals ≈ ~4 days "
            "of full retention."
        ),
    )
    bypass_approval: bool = Field(
        default=True,
        description=(
            "When True, heartbeat sessions may send a single outbound message "
            "to approved channels and write to approved memory files (MEMORY.md, "
            "memory.json) without requiring human approval.  Without this bypass, "
            "the approval gate blocks all outbound messages and memory writes, "
            "making the heartbeat unable to report results.  Set to False to "
            "require approval for all heartbeat tool calls (not recommended)."
        ),
    )


class GoogleAuthConfig(BaseModel):
    """Configuration for Google OAuth 2.0 credential management.

    One set of credentials covers all three Google APIs (Gmail, Drive, Calendar).
    The ``scopes`` list determines which APIs are accessible; the
    ``client_secrets_file`` identifies the app to Google.

    Security notes:
    - ``client_secrets.json`` must not be committed to a public repository.
    - ``google_tokens.enc`` is Fernet-encrypted at rest; the passphrase comes
      from ``GOOGLE_OAUTH_PASSPHRASE`` (env var) at runtime.
    - The ``credentials_path`` value is joined to the workspace root at startup.
    """

    credentials_path: str = Field(
        default="auth",
        description="Sub-directory within the workspace for OAuth credential files.",
    )
    token_file: str = Field(
        default="google_tokens.enc",
        description="Filename of the encrypted token within credentials_path.",
    )
    client_secrets_file: str = Field(
        default="client_secrets.json",
        description="Filename of the OAuth client secrets file within credentials_path.",
    )
    scopes: list[str] = Field(
        default_factory=lambda: [
            "https://www.googleapis.com/auth/gmail.readonly",
            "https://www.googleapis.com/auth/drive.file",
            "https://www.googleapis.com/auth/calendar.events",
        ],
        description="OAuth 2.0 scopes requested during authorisation.",
    )
    oauth_callback_port: int = Field(
        default=8765,
        ge=1024,
        le=65535,
        description=(
            "Localhost port for the temporary OAuth callback server during authorisation. "
            "Must be registered as an authorised redirect URI in Google Cloud Console."
        ),
    )


class OutboundChannelConfig(BaseModel):
    """Configuration for agent-initiated outbound messaging tools.

    Controls which channel tools are registered and what recipients the agent
    is allowed to contact proactively.  The ``*_allowed_recipients`` lists are
    seeded at startup from each adapter's inbound configuration so the security
    posture is consistent between inbound and outbound by default.

    Security notes:
    - ``*_allowed_recipients`` lists are the primary guard against prompt-injection
      attacks that try to exfiltrate data to a third party's number/address.
      Keep these lists narrow — only the user's own contacts.
    - ``max_message_length`` defaults to 1600 (Twilio SMS hard limit); applied to
      all channels so that all tool sends stay under SMS constraints.
    """

    sms_enabled: bool = Field(
        default=True,
        description="Whether the send_sms tool is active when an SMS adapter is configured.",
    )
    slack_enabled: bool = Field(
        default=True,
        description="Whether the send_slack_message tool is active when a Slack adapter is configured.",
    )
    email_enabled: bool = Field(
        default=True,
        description="Whether the send_email tool is active when an email adapter is configured.",
    )
    max_message_length: int = Field(
        default=1600,
        ge=1,
        description=(
            "Maximum character length for any outbound message body.  "
            "Content beyond this limit is truncated with a [truncated] suffix.  "
            "Default 1600 — the Twilio SMS hard limit."
        ),
    )
    sms_allowed_recipients: list[str] = Field(
        default_factory=list,
        description=(
            "Phone numbers (E.164) the agent is permitted to SMS proactively.  "
            "Seeded at startup from the SMS adapter's from_number and sender_allowlist.  "
            "Extend this list to allow additional numbers."
        ),
    )
    slack_allowed_recipients: list[str] = Field(
        default_factory=list,
        description=(
            "Slack channels (#channel) or users (@user) the agent may message proactively.  "
            "Seeded from the Slack adapter's channel_id.  "
            "Extend this list to allow additional targets."
        ),
    )
    email_allowed_recipients: list[str] = Field(
        default_factory=list,
        description=(
            "Email addresses the agent is permitted to send to proactively.  "
            "Seeded from the email adapter's sender_allowlist and default_to_address.  "
            "Extend this list to allow additional addresses."
        ),
    )


class ToolsConfig(BaseModel):
    """Trust-level tool allowlist defaults.

    Tools listed under a trust level are automatically added to the
    ``allowed_tools`` list of any agent running at that trust level.
    Individual ``AgentConfig.allowed_tools`` entries extend (not replace)
    these defaults — they are merged at startup before the runtime is built.

    Security notes:
    - Only tools that are also registered in the ``ToolRegistry`` will
      actually be available; listing an unknown tool name here is harmless.
    - The merge is additive only — tools are never removed from an agent's
      explicit ``allowed_tools`` list by these defaults.
    - Changing this config does not bypass trust-level permission checks;
      each tool still enforces its own ``trust_level_required`` at call time.
    """

    trust_defaults: dict[str, list[str]] = Field(
        default_factory=lambda: {
            "public": [],
            "mcp": [],
            "main": [
                # --- Narrative memory ---
                "update_memory_narrative",
                "update_user_profile",
                "update_identity",
                "memory_read",
                "memory_write",
                # --- Heartbeat & social awareness ---
                "update_heartbeat",
                "acknowledge_social_alert",
                "add_learning_observation",
                "adjust_contact_attention",
                # --- Research ---
                "research_query",
                # --- Outbound messaging ---
                "send_sms",
                "send_slack_message",
                "send_email",
                # --- File operations (workspace-sandboxed) ---
                "file_read",
                "file_write",
                "file_list",
                # --- Session history (approval-gated) ---
                "sessions_history",
                # --- Google Calendar ---
                "calendar_list_events",
                "calendar_read_event",
                "calendar_create_event",
                # --- Google Drive ---
                "drive_list_files",
                "drive_list_folders",
                "drive_read_file",
                "drive_create_folder",
                "drive_upload_file",
                # --- Gmail ---
                "gmail_list_threads",
                "gmail_read_thread",
                "gmail_list_labels",
                "gmail_create_label",
                "gmail_apply_label",
                "gmail_remove_label",
                "gmail_star_message",
                "gmail_mark_important",
                "gmail_archive",
                # --- Google Tasks ---
                "tasks_list_tasklists",
                "tasks_list_tasks",
                "tasks_read_task",
                "tasks_create_task",
                "tasks_complete_task",
                # --- Claude Code (registered only when cc.enabled=True) ---
                "cc_read_analyze",
                "cc_write_task",
                "cc_run_with_shell",
                "cc_git_commit",
                "cc_git_push_branch",
                "cc_promote_request",
            ],
            "local": [],
            "security": [],
        },
        description=(
            "Tools automatically permitted for agents at each trust level. "
            "Keys are trust level names ('public', 'mcp', 'main', 'local', 'security'). "
            "Per-agent allowed_tools extend these defaults without replacing them."
        ),
    )


# ---------------------------------------------------------------------------
# SearchConfig / SerperConfigSection
# ---------------------------------------------------------------------------


class SerperConfigSection(BaseModel):
    """
    Serper-specific config loaded from config.json under 'search.serper'.

    Maps to SerperConfig dataclass via SerperConfig.from_app_config().
    Defaults mirror SerperConfig's own defaults so an empty JSON section
    is fully valid.

    Security note: The API key is NOT here. It is read from the
    SERPER_API_KEY environment variable at call time by SerperClient.
    """

    enabled_endpoints: list[str] = Field(
        default_factory=lambda: list(["search", "news", "images"]),
        description=(
            "Serper endpoints the ResearchAgent is permitted to call. "
            "Subset of: search, images, news, videos, places, maps, "
            "shopping, scholar, patents, autocomplete, lens."
        ),
    )
    max_results: int = Field(
        default=10,
        ge=1,
        le=100,
        description="Maximum results per query (Serper 'num' parameter). Range 1–100.",
    )
    request_timeout_seconds: float = Field(
        default=10.0,
        gt=0,
        description="HTTP request timeout in seconds.",
    )
    max_retries: int = Field(
        default=2,
        ge=0,
        description="Retry attempts on transient 5xx / network errors.",
    )
    retry_delay_seconds: float = Field(
        default=1.0,
        ge=0,
        description="Seconds to wait between retries.",
    )
    max_response_bytes: int = Field(
        default=512_000,
        ge=1,
        description="Maximum Serper response size in bytes before rejection.",
    )
    max_field_chars: int = Field(
        default=2_000,
        ge=1,
        description="Maximum text chars in a single field before sanitizer flags it.",
    )
    credit_warning_threshold: int = Field(
        default=500,
        ge=0,
        description="Emit a warning log when credits_remaining drops to or below this value.",
    )
    default_country: Optional[str] = Field(
        default="us",
        description="Default country code for results (ISO 3166-1 alpha-2).",
    )
    default_language: Optional[str] = Field(
        default="en",
        description="Default language for results (BCP 47).",
    )
    safe_search: Optional[str] = Field(
        default="active",
        description="Safe search setting: 'active', 'off', or None (Serper default).",
    )


class SearchConfig(BaseModel):
    """Top-level search configuration."""

    serper: SerperConfigSection = Field(
        default_factory=SerperConfigSection,
        description="Serper API integration settings.",
    )


# ---------------------------------------------------------------------------
# AppConfig — top-level configuration model
# ---------------------------------------------------------------------------


# ---------------------------------------------------------------------------
# CCConfig
# ---------------------------------------------------------------------------


class CCConfig(BaseModel):
    """Configuration for the Claude Code integration layer (piece 40.x).

    When ``enabled`` is False, all cc_* tools are unregistered at startup and
    this config is never consulted further.  This is the safe default so the
    integration is explicitly opted into.

    Security notes:
    - ``workspace_root`` must be an absolute path with a drive letter on Windows.
      A relative path or missing drive letter is rejected at startup, not silently
      resolved, because ``WorkspaceManager.validate_path`` depends on it being
      anchored.
    - ``claude_binary`` defaults to ``"claude"`` (assumes PATH).  Set a full path
      if CC is not globally accessible to the process user account.
    - ``exec_allowed_tools`` is the allowlist passed to CC via ``--allowedTools``.
      Unknown tool names here produce a startup warning (likely a typo); they do
      not prevent startup.
    """

    enabled: bool = Field(
        default=False,
        description="Whether the Claude Code integration is active.  Opt-in.",
    )
    workspace_root: str = Field(
        default="",
        description=(
            "Absolute path to the assistant's workspace directory.  "
            "Default is C:\\Users\\{assistant_name}\\.  "
            "Must be an absolute path; relative paths are rejected at startup."
        ),
    )
    assistant_name: str = Field(
        default="OpenRattler",
        description=(
            "Name of the assistant instance.  Used to derive the default "
            "workspace_root and as the prefix for project directories."
        ),
    )
    project_prefix: str = Field(
        default="or",
        description=(
            "Short prefix applied to all CC project directories.  "
            "Default is the first component of assistant_name lowercased."
        ),
    )
    git_author_name: str = Field(
        default="OpenRattler (Claude Code)",
        description="Git author name written into each workspace repo's local config.",
    )
    git_author_email: str = Field(
        default="openrattler@local",
        description="Git author email written into each workspace repo's local config.",
    )
    max_concurrent_sessions: int = Field(
        default=1,
        ge=1,
        description="Maximum number of CC subprocesses that may run simultaneously.",
    )
    session_timeout_seconds: int = Field(
        default=300,
        ge=10,
        description="Seconds before a CC subprocess is killed and the task fails.",
    )
    plan_review_enabled: bool = Field(
        default=True,
        description=(
            "Whether to run a read-only CC plan phase before execution.  "
            "If False, CC goes straight to the execution phase without a plan review."
        ),
    )
    plan_review_approval_level: int = Field(
        default=3,
        ge=1,
        le=5,
        description="Action level used for the plan review approval request.",
    )
    plan_review_timeout_seconds: int = Field(
        default=120,
        ge=10,
        description=(
            "Seconds the user has to approve or deny a plan review request.  "
            "Longer than the default 30s because users need time to read the plan."
        ),
    )
    exec_allowed_tools: list[str] = Field(
        default_factory=lambda: ["Read", "Write", "Glob", "Grep", "LS", "Bash"],
        description="CC tool names permitted during the execution phase.",
    )
    claude_binary: str = Field(
        default="claude",
        description=(
            "Path to the Claude Code CLI binary.  "
            "Use a full path if 'claude' is not on PATH for the process user."
        ),
    )

    @field_validator("workspace_root")
    @classmethod
    def _validate_workspace_root(cls, v: str) -> str:
        """Reject relative paths and (on Windows) paths without a drive letter.

        An empty string is allowed only when ``enabled`` is False.  The
        validator cannot access ``enabled`` (Pydantic validators are per-field),
        so the startup code re-checks this when wiring the integration.
        """
        if v == "":
            return v
        p = Path(v)
        if not p.is_absolute():
            raise ValueError(
                f"workspace_root must be an absolute path (got '{v}'). "
                "On Windows this means it must start with a drive letter, e.g. C:\\Users\\[assistant_name}\\."
            )
        return v


# ---------------------------------------------------------------------------
# GoogleConfig
# ---------------------------------------------------------------------------

#: OAuth 2.0 scopes for the 41.x Google Workspace integration.
_GOOGLE_WORKSPACE_SCOPES: list[str] = [
    "https://www.googleapis.com/auth/calendar.events",
    "https://www.googleapis.com/auth/tasks",
    "https://www.googleapis.com/auth/drive",
    "https://www.googleapis.com/auth/gmail.modify",
]


class GoogleConfig(BaseModel):
    """Configuration for the 41.x Google Workspace integration layer.

    One ``GoogleConfig`` section covers all four Google APIs (Calendar, Drive,
    Gmail, Tasks).  The ``credentials_file`` and ``token_file`` paths default
    to ``~/.openrattler/google/`` so they do not interfere with the existing
    ``google_auth`` section which uses the workspace-relative ``auth/`` path.

    Security notes:
    - ``credentials_file`` identifies the app to Google but does not grant
      access; keep it out of public repositories.
    - ``token_file`` stores OAuth 2.0 tokens — treat it like a password.
      Add ``~/.openrattler/google/token.json`` to ``.gitignore``.
    - When ``enabled=True``, ``credentials_file`` must exist on disk; the
      validator raises ``ValueError`` so misconfiguration is caught at startup.
    """

    enabled: bool = Field(
        default=False,
        description="Whether the Google Workspace integration is active.  Opt-in.",
    )
    credentials_file: str = Field(
        default=str(Path.home() / ".openrattler" / "google" / "credentials.json"),
        description=(
            "Path to the OAuth 2.0 client credentials JSON file downloaded from "
            "Google Cloud Console.  Must exist before running 'openrattler google-auth'."
        ),
    )
    token_file: str = Field(
        default=str(Path.home() / ".openrattler" / "google" / "token.json"),
        description=(
            "Path where the OAuth 2.0 token is stored after the auth flow.  "
            "Treat like a password and add to .gitignore."
        ),
    )
    user_email: str = Field(
        default="",
        description="Primary Google account email address for this integration.",
    )
    calendar_id: str = Field(
        default="primary",
        description=(
            "Google Calendar ID to use.  'primary' resolves to the signed-in user's "
            "main calendar.  All calendar tools accept a calendar_id parameter to "
            "override this per-call."
        ),
    )
    task_list_id: str = Field(
        default="@default",
        description=(
            "'@default' resolves to the signed-in user's primary task list.  "
            "Use tasks_list_tasklists to discover other task list IDs."
        ),
    )
    drive_upload_folder_id: Optional[str] = Field(
        default=None,
        description="Drive folder ID for default upload location.  None = Drive root.",
    )
    max_email_chars: int = Field(
        default=10000,
        ge=1,
        description="Email body truncation limit in characters.",
    )
    max_file_chars: int = Field(
        default=20000,
        ge=1,
        description="Drive file content truncation limit in characters.",
    )
    max_threads_per_query: int = Field(
        default=20,
        ge=1,
        description="Maximum Gmail threads returned per list query.",
    )
    max_events_per_query: int = Field(
        default=50,
        ge=1,
        description="Maximum Calendar events returned per list query.",
    )
    max_tasks_per_query: int = Field(
        default=100,
        ge=1,
        description="Maximum Tasks items returned per list query.",
    )
    max_file_bytes: int = Field(
        default=5_000_000,
        ge=1,
        description=(
            "Maximum Drive file size in bytes before refusing to read content.  "
            "Checked against file metadata before downloading."
        ),
    )

    @field_validator("credentials_file")
    @classmethod
    def _validate_credentials_file(cls, v: str) -> str:
        """Accept any path at model creation time; existence is checked at startup."""
        return v


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
    tools: ToolsConfig = Field(
        default_factory=ToolsConfig,
        description=(
            "Trust-level tool allowlist defaults. Tools listed here are merged "
            "into each agent's allowed_tools based on its trust level at startup."
        ),
    )
    heartbeat: HeartbeatConfig = Field(
        default_factory=HeartbeatConfig,
        description=(
            "Scheduled heartbeat check-in configuration. "
            "Controls whether and how often the agent runs background self-checks."
        ),
    )
    outbound_channels: OutboundChannelConfig = Field(
        default_factory=OutboundChannelConfig,
        description=(
            "Outbound channel tool configuration.  Controls which agent-initiated "
            "messaging tools are active and which recipients are permitted."
        ),
    )
    google_auth: GoogleAuthConfig = Field(
        default_factory=GoogleAuthConfig,
        description=(
            "Google OAuth 2.0 credential configuration.  Shared by Gmail, Drive, "
            "and Calendar tool integrations."
        ),
    )
    search: SearchConfig = Field(
        default_factory=SearchConfig,
        description=(
            "Search API configuration. Currently contains Serper settings. "
            "API key is read from SERPER_API_KEY environment variable, not stored here."
        ),
    )
    cc: CCConfig = Field(
        default_factory=CCConfig,
        description=(
            "Claude Code integration configuration (piece 40.x).  "
            "Disabled by default — set enabled=true to activate."
        ),
    )
    google: GoogleConfig = Field(
        default_factory=GoogleConfig,
        description=(
            "Google Workspace integration configuration (piece 41.x).  "
            "Disabled by default — set enabled=true to activate.  "
            "Covers Calendar, Drive, Gmail, and Tasks."
        ),
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
