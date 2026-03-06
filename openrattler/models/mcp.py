"""MCP (Model Context Protocol) data models.

These models define the trust hierarchy, permission manifests, and audit records
for MCP server integrations. Every external MCP server — bundled, user-installed,
or auto-discovered — is described by an MCPServerManifest before any tool execution
is permitted. The manifest is the security chokepoint: it declares exactly what
the server can access, what it costs, and which tools require approval.

Security notes:
- MCPServerManifest defaults to restrictive permissions (empty allowlists, no exec,
  no financial). Capabilities must be explicitly declared.
- MCPCallRecord stores param keys only (never values) to prevent secrets from
  appearing in audit logs.
- MCPSecurityConfig enforces timeout and size limits that cannot be overridden by
  an individual server manifest.
"""

from __future__ import annotations

import re
from typing import Any, Literal, Optional

from pydantic import BaseModel, Field, field_validator, model_validator

# Trust tier literals — matches ARCHITECTURE.md table
MCPTrustTier = Literal["bundled", "user_installed", "auto_discovered"]

# Regex for valid server IDs (lowercase, digits, hyphens, underscores; no dots, spaces)
_SERVER_ID_RE = re.compile(r"^[a-z0-9][a-z0-9_-]*$")


class MCPNetworkPermissions(BaseModel):
    """Network access permissions declared by an MCP server.

    Security notes:
    - allowed_domains is an allowlist; everything else is denied when
      deny_all_others=True (the default).
    - Domain entries must not contain path characters — domains only.
    - An empty allowlist with deny_all_others=True means no outbound network
      access is permitted (safest default for local/tool-only servers).
    """

    allowed_domains: list[str] = Field(
        default_factory=list,
        description="Allowlisted hostnames the server may contact",
    )
    deny_all_others: bool = Field(
        default=True,
        description="If True, all domains not in allowed_domains are blocked",
    )

    @field_validator("allowed_domains", mode="before")
    @classmethod
    def no_path_chars_in_domains(cls, v: list[Any]) -> list[Any]:
        """Reject domain entries containing path separators."""
        for entry in v:
            if isinstance(entry, str) and ("/" in entry or "\\" in entry):
                raise ValueError(
                    f"Domain entry {entry!r} must not contain path characters ('/' or '\\')"
                )
        return v


class MCPDataAccessPermissions(BaseModel):
    """Data access permissions declared by an MCP server.

    The read and write lists enumerate data field namespaces the server
    may access (e.g. "user.address", "user.phone").  The MCPToolBridge
    uses these lists to strip undeclared fields from tool call params.
    """

    read: list[str] = Field(
        default_factory=list,
        description="Data namespaces the server may read (e.g. 'user.address')",
    )
    write: list[str] = Field(
        default_factory=list,
        description="Data namespaces the server may write",
    )


class MCPFileSystemPermissions(BaseModel):
    """File system access permissions declared by an MCP server.

    Read and write lists are path prefixes.  The MCPToolBridge validates
    any file paths in tool arguments against these allowlists.
    """

    read: list[str] = Field(
        default_factory=list,
        description="Path prefixes the server may read",
    )
    write: list[str] = Field(
        default_factory=list,
        description="Path prefixes the server may write",
    )


class MCPToolManifestEntry(BaseModel):
    """A single tool declaration within a server manifest.

    Declares the tool's identity, cost profile, and whether it requires
    explicit human approval before execution.
    """

    name: str = Field(description="Tool name as declared by the MCP server")
    description: str = Field(default="", description="Human-readable tool description")
    requires_approval: bool = Field(
        default=False,
        description="If True, the MCPToolBridge will pause for human approval before calling this tool",
    )
    cost_estimate: str = Field(
        default="none",
        description="Estimated cost profile: 'none', 'low', 'variable', or 'high'",
    )
    side_effects: str = Field(
        default="none",
        description="Human-readable description of side effects (e.g. 'sends an SMS', 'posts to Twitter')",
    )


class MCPPermissions(BaseModel):
    """Full permission set declared by an MCP server manifest.

    All sub-permissions default to the most restrictive values.
    Capabilities must be explicitly granted; they are never assumed.

    Security notes:
    - exec=False means the server cannot spawn subprocesses via our framework.
    - financial=False means the server cannot initiate financial transactions.
    - max_cost_per_transaction=None means no single-transaction limit is enforced
      (use MCPSecurityConfig.financial_transaction_limit for the global cap).
    """

    network: MCPNetworkPermissions = Field(default_factory=MCPNetworkPermissions)
    data_access: MCPDataAccessPermissions = Field(default_factory=MCPDataAccessPermissions)
    file_system: MCPFileSystemPermissions = Field(default_factory=MCPFileSystemPermissions)
    exec: bool = Field(
        default=False,
        description="Whether the server may spawn subprocesses",
    )
    financial: bool = Field(
        default=False,
        description="Whether the server may initiate financial transactions",
    )
    max_cost_per_transaction: Optional[float] = Field(
        default=None,
        ge=0,
        description="Per-transaction cost cap in USD; None = no server-level cap (global cap still applies)",
    )


class MCPServerManifest(BaseModel):
    """Manifest declaring an MCP server's identity, permissions, and tools.

    Every MCP server — bundled, user-installed, or auto-discovered — must
    have a manifest. Bundled servers have manifests checked into the repo.
    User-installed servers provide manifests at install time for user review.
    Auto-discovered servers must supply manifests before any tool execution.

    Security notes:
    - server_id is restricted to lowercase alphanumerics, hyphens, and underscores.
      This keeps it safe for use as a tool name prefix ("mcp:{server_id}.{tool}")
      and in audit log field values without quoting or escaping concerns.
    - For stdio transport, the command must be set (no fallback to PATH lookup
      to prevent hijacking via PATH manipulation).
    - For streamable_http transport, the URL must be set.
    - Env vars in ``env`` are passed to the subprocess environment. They must
      never contain hardcoded credentials — use secret references that the
      runtime resolves at startup.
    """

    server_id: str = Field(
        description="Unique server identifier (lowercase, hyphens/underscores only)"
    )
    version: str = Field(description="Semver string, e.g. '1.2.0'")
    publisher: str = Field(description="Publisher name")
    verified: bool = Field(
        default=False,
        description="Whether the publisher identity has been verified",
    )
    trust_tier: MCPTrustTier = Field(
        default="user_installed",
        description="Trust tier: 'bundled', 'user_installed', or 'auto_discovered'",
    )
    permissions: MCPPermissions = Field(default_factory=MCPPermissions)
    tools: list[MCPToolManifestEntry] = Field(
        default_factory=list,
        description="Tools this server declares in its manifest",
    )
    transport: Literal["stdio", "streamable_http"] = Field(
        default="stdio",
        description="Transport protocol used to communicate with the server",
    )

    # Transport-specific config
    command: Optional[str] = Field(
        default=None,
        description="For stdio: executable to launch (must be an absolute path or venv-relative binary)",
    )
    args: list[str] = Field(
        default_factory=list,
        description="For stdio: command-line arguments (no shell expansion performed)",
    )
    env: dict[str, str] = Field(
        default_factory=dict,
        description="For stdio: environment variables injected into the subprocess (no credentials in values)",
    )
    url: Optional[str] = Field(
        default=None,
        description="For streamable_http: server base URL (no credential embedding)",
    )

    @field_validator("server_id")
    @classmethod
    def server_id_format(cls, v: str) -> str:
        """Enforce safe server_id format for use in tool name prefixes."""
        if not _SERVER_ID_RE.match(v):
            raise ValueError(
                f"server_id {v!r} must match ^[a-z0-9][a-z0-9_-]*$ "
                "(lowercase letters, digits, hyphens, underscores; start with alphanumeric)"
            )
        return v

    @model_validator(mode="after")
    def transport_config_required(self) -> "MCPServerManifest":
        """Ensure transport-specific config is present."""
        if self.transport == "stdio" and not self.command:
            raise ValueError("MCPServerManifest with transport='stdio' must set 'command'")
        if self.transport == "streamable_http" and not self.url:
            raise ValueError("MCPServerManifest with transport='streamable_http' must set 'url'")
        return self


class MCPSecurityConfig(BaseModel):
    """User-configurable MCP security settings.

    Applied globally across all MCP server connections.  Server manifests
    cannot override these limits — they are enforced by the MCPToolBridge
    before delegating to any server-specific logic.

    Security notes:
    - call_timeout_seconds is bounded [5, 300] to prevent both spin-loops
      (too short) and indefinite hangs (too long).
    - max_response_size_bytes limits memory impact from adversarial servers
      returning unbounded payloads.
    - financial_transaction_limit=0 effectively disables financial tools
      without requiring individual manifest changes.
    """

    allow_bundled: bool = Field(
        default=True,
        description="Allow connections to bundled (repo-checked) MCP servers",
    )
    allow_user_installed: bool = Field(
        default=True,
        description="Allow connections to user-installed MCP servers",
    )
    allow_auto_discovered: Literal["prompt", "deny", "allow"] = Field(
        default="deny",
        description="Policy for auto-discovered MCP servers: 'deny' blocks all, 'prompt' asks user, 'allow' accepts all",
    )
    require_multi_channel_auth_for_financial: bool = Field(
        default=True,
        description="Require a second confirmation channel for financial transactions",
    )
    financial_transaction_limit: float = Field(
        default=100.00,
        ge=0,
        description="Maximum USD value of any single financial transaction",
    )
    approve_every_tool_call: bool = Field(
        default=False,
        description="If True, require human approval for every MCP tool call (not just approval-required tools)",
    )
    network_isolation: Literal["strict", "moderate", "none"] = Field(
        default="strict",
        description="Network enforcement level: 'strict' blocks all undeclared domains, 'moderate' warns, 'none' allows all",
    )
    max_response_size_bytes: int = Field(
        default=100_000,
        description="Maximum response payload size in bytes (100 KB default)",
    )
    call_timeout_seconds: int = Field(
        default=30,
        ge=5,
        le=300,
        description="Maximum seconds to wait for a single MCP tool call",
    )


class MCPCallRecord(BaseModel):
    """Audit record for an MCP tool call.

    Security notes:
    - params_keys stores only the keys of the arguments dict, never the values.
      This ensures secrets or PII passed as arguments do not appear in audit logs.
    - suspicious_patterns lists matched pattern categories (not matched text)
      from the response scanner.
    """

    server_id: str = Field(description="MCP server that handled the call")
    tool_name: str = Field(description="Name of the tool invoked")
    trust_tier: MCPTrustTier = Field(description="Trust tier of the server at call time")
    params_keys: list[str] = Field(
        description="Argument keys only (values omitted to protect secrets and PII)"
    )
    required_approval: bool = Field(
        description="Whether this call required (and received) human approval"
    )
    approval_result: Optional[str] = Field(
        default=None,
        description="'approved', 'denied', or 'not_required'",
    )
    response_size_bytes: Optional[int] = Field(
        default=None,
        description="Size of the response payload in bytes",
    )
    suspicious_patterns: list[str] = Field(
        default_factory=list,
        description="Pattern categories matched in the response (e.g. 'credential_leak', 'prompt_injection')",
    )
    duration_ms: Optional[int] = Field(
        default=None,
        description="Wall-clock time for the call in milliseconds",
    )
    success: bool = Field(
        default=True,
        description="True if the call completed without error",
    )
    error: Optional[str] = Field(
        default=None,
        description="Error message if success=False",
    )
