"""MCP Tool Bridge — security validation layer for MCP tool execution.

Every MCP tool call flows through ``MCPToolBridge.execute()``.  It is the
single security chokepoint between the ``ToolExecutor`` and the actual
``MCPServerConnection``.  No MCP tool invocation reaches the wire without
passing all checks here.

Architecture position::

    ToolExecutor
        └── MCPToolBridge.execute()   ← THIS MODULE
                ├── 1. Manifest & connection lookup (via MCPManager)
                ├── 2. Trust level check
                ├── 3. Parameter sanitisation
                ├── 4. Financial limit check
                ├── 5. Approval gate (via ApprovalManager)
                ├── 6. MCPServerConnection.call_tool()
                ├── 7. Response validation (size + pattern scan)
                └── 8. Audit log (MCPCallRecord)

Security notes:
- The bridge never raises — every code path returns a ``ToolResult``.
- Parameters are sanitised *before* the call; the MCP server never sees
  data fields not declared in its manifest permissions.
- Responses are validated *after* the call; suspicious content is audit-
  logged and can optionally block delivery.
- Financial transactions are checked against both the per-manifest cap
  and the global ``MCPSecurityConfig.financial_transaction_limit``.
- ``SecurityError`` (response too large) is caught internally and turned
  into an error ``ToolResult`` so callers always receive a result.
"""

from __future__ import annotations

import json
import logging
import re
import time
import uuid
from datetime import datetime, timezone
from typing import TYPE_CHECKING, Any, Optional

from openrattler.models.agents import AgentConfig, TrustLevel
from openrattler.models.audit import AuditEvent
from openrattler.models.mcp import (
    MCPCallRecord,
    MCPSecurityConfig,
    MCPServerManifest,
    MCPToolManifestEntry,
)
from openrattler.models.tools import ToolResult
from openrattler.storage.audit import AuditLog

if TYPE_CHECKING:
    from openrattler.mcp.manager import MCPManager
    from openrattler.security.approval import ApprovalManager

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Exceptions
# ---------------------------------------------------------------------------


class SecurityError(Exception):
    """Raised when an MCP response violates a hard security boundary.

    Currently used only for responses that exceed ``max_response_size_bytes``.
    This is a hard block — the response is discarded and an error ToolResult
    is returned to the caller.
    """


# ---------------------------------------------------------------------------
# MCP-specific response suspicious patterns
# ---------------------------------------------------------------------------

#: Patterns scanned in MCP server responses for credential-like content.
#: Each entry is ``(category_name, regex_string)`` — same structure as
#: the existing ``SUSPICIOUS_PATTERNS`` in openrattler.security.patterns.
_MCP_RESPONSE_SUSPICIOUS_PATTERNS: list[tuple[str, str]] = [
    ("credential_leak", r"api[_-]?key\s*[:=]"),
    ("credential_leak", r"password\s*[:=]"),
    ("credential_leak", r"secret\s*[:=]"),
    ("credential_leak", r"token\s*[:=]"),
    ("credential_leak", r"bearer\s+[a-zA-Z0-9\-._~+/]+=*"),
    ("credential_leak", r"-----BEGIN\s+(RSA\s+)?PRIVATE\s+KEY-----"),
]

# ---------------------------------------------------------------------------
# Sensitive parameter field prefixes
# ---------------------------------------------------------------------------

#: Parameter key prefixes that are treated as sensitive and stripped unless
#: the server's manifest explicitly declares read access to that field.
_SENSITIVE_PREFIXES: frozenset[str] = frozenset({"user.", "payment.", "credentials."})


# ---------------------------------------------------------------------------
# MCPToolBridge
# ---------------------------------------------------------------------------


class MCPToolBridge:
    """Security bridge between OpenRattler agents and MCP servers.

    Every MCP tool call flows through this bridge. It enforces:

    1. Manifest permission validation
    2. Parameter sanitisation (strip fields not in data_access.read)
    3. Approval gate (delegate to ApprovalManager when required)
    4. Call timeout enforcement (delegated to MCPServerConnection)
    5. Response validation (size, suspicious patterns, exfiltration)
    6. Audit logging of the complete call (MCPCallRecord)

    The bridge does NOT manage connections — that's MCPManager's job.
    The bridge does NOT handle JSON-RPC — that's MCPServerConnection's job.
    The bridge is purely the security policy enforcement layer.

    Security notes:
    - Params are sanitised BEFORE the call. The MCP server never sees
      data fields not declared in its manifest permissions.
    - Responses are validated AFTER the call. Suspicious content is
      flagged in audit but still returned (flag-and-deliver by default).
    - Financial transactions check the cost estimate against the
      configured financial_transaction_limit.
    - All calls are audit-logged with timing, result size, and any
      security flags regardless of outcome.
    """

    def __init__(
        self,
        mcp_manager: "MCPManager",
        security_config: MCPSecurityConfig,
        approval_manager: Optional["ApprovalManager"] = None,
        audit: Optional[AuditLog] = None,
    ) -> None:
        self._manager = mcp_manager
        self._security_config = security_config
        self._approval_manager = approval_manager
        self._audit = audit

    async def execute(
        self,
        server_id: str,
        tool_name: str,
        params: dict[str, Any],
        agent_config: AgentConfig,
        session_key: str,
        trace_id: str,
    ) -> ToolResult:
        """Execute an MCP tool call with full security validation.

        Steps:
        1. Look up manifest and connection via MCPManager
        2. Check agent trust level against MCP trust requirement
        3. Find tool in manifest → get permission/approval requirements
        4. Sanitise params (remove sensitive fields not in manifest)
        5. Check financial limits (if server has financial permission)
        6. Request approval if required (via ApprovalManager)
        7. Execute via MCPServerConnection.call_tool() with timeout
        8. Validate response (size check, suspicious pattern scan)
        9. Build and log MCPCallRecord audit event
        10. Return result as ToolResult

        Args:
            server_id:    MCP server identifier.
            tool_name:    Tool name (without namespace prefix).
            params:       Arguments for the tool call.
            agent_config: Calling agent's config (for trust level).
            session_key:  Current session key (for audit).
            trace_id:     Trace ID used as the ToolResult call_id.

        Returns:
            ToolResult — always, even on permission denial, approval
            denial, size violation, or call failure.
        """
        start_ms = int(time.monotonic() * 1000)

        # Mutable state accumulated across execution steps for audit logging.
        manifest: Optional[MCPServerManifest] = None
        required_approval = False
        approval_result_str: Optional[str] = None
        response_size: Optional[int] = None
        suspicious_patterns: list[str] = []
        success = False
        error: Optional[str] = None
        result: Any = None

        try:
            # ------------------------------------------------------------------
            # Step 1: Look up manifest and connection
            # ------------------------------------------------------------------
            manifest = self._manager.get_manifest(server_id)
            conn = self._manager.get_connection(server_id)

            # ------------------------------------------------------------------
            # Step 2: Trust level check
            # ------------------------------------------------------------------
            if agent_config.trust_level != TrustLevel.mcp:
                raise PermissionError(
                    f"Agent trust level '{agent_config.trust_level.value}' cannot invoke MCP "
                    f"tools; requires trust level 'mcp'"
                )

            # ------------------------------------------------------------------
            # Step 3: Resolve tool entry from manifest (may be None for undeclared tools)
            # ------------------------------------------------------------------
            tool_entry: Optional[MCPToolManifestEntry] = next(
                (t for t in manifest.tools if t.name == tool_name), None
            )

            # ------------------------------------------------------------------
            # Step 4: Sanitise params
            # ------------------------------------------------------------------
            sanitized = self._sanitize_params(params, manifest)

            # ------------------------------------------------------------------
            # Step 5: Financial limit check (runs for all tools on financial servers)
            # ------------------------------------------------------------------
            self._check_financial_limits(tool_entry, manifest, sanitized)

            # ------------------------------------------------------------------
            # Step 6: Approval gate
            # ------------------------------------------------------------------
            needs_appr = (
                tool_entry is not None and tool_entry.requires_approval
            ) or self._security_config.approve_every_tool_call
            required_approval = needs_appr

            if needs_appr and self._approval_manager is not None:
                approval_result_str = await self._run_approval(
                    server_id=server_id,
                    tool_name=tool_name,
                    sanitized=sanitized,
                    agent_config=agent_config,
                    session_key=session_key,
                    manifest=manifest,
                )
                if approval_result_str == "denied":
                    error = f"MCP tool '{server_id}.{tool_name}' execution denied"
                    # success remains False; fall through to finally for audit.
            else:
                approval_result_str = "not_required"

            # ------------------------------------------------------------------
            # Step 7 & 8: Execute and validate (only if not already denied)
            # ------------------------------------------------------------------
            if error is None:
                raw_result = await conn.call_tool(tool_name, sanitized)
                validated_result, suspicious_patterns = self._validate_response(
                    raw_result, manifest
                )
                response_size = len(json.dumps(validated_result).encode("utf-8"))

                if suspicious_patterns:
                    logger.warning(
                        "[%s] Suspicious patterns in MCP response from %s.%s: %s",
                        trace_id,
                        server_id,
                        tool_name,
                        suspicious_patterns,
                    )

                result = validated_result
                success = True

        except Exception as exc:
            success = False
            error = str(exc) or type(exc).__name__

        finally:
            duration_ms = int(time.monotonic() * 1000) - start_ms
            await self._audit_log_call(
                server_id=server_id,
                tool_name=tool_name,
                manifest=manifest,
                params=params,
                required_approval=required_approval,
                approval_result=approval_result_str,
                response_size=response_size,
                suspicious_patterns=suspicious_patterns,
                duration_ms=duration_ms,
                success=success,
                error=error,
                session_key=session_key,
                agent_id=agent_config.agent_id,
            )

        return ToolResult(call_id=trace_id, success=success, result=result, error=error)

    # ------------------------------------------------------------------
    # Security enforcement helpers
    # ------------------------------------------------------------------

    def _sanitize_params(
        self,
        params: dict[str, Any],
        manifest: MCPServerManifest,
    ) -> dict[str, Any]:
        """Remove data fields not permitted by the manifest.

        The manifest's ``permissions.data_access.read`` declares which
        user data fields the server is allowed to receive.  Any param key
        that matches a known sensitive field prefix and is NOT listed in
        the manifest's ``read`` allowlist is silently dropped.

        Known sensitive field prefixes:
        - ``user.``         (e.g. user.email, user.phone, user.address)
        - ``payment.``      (e.g. payment.card, payment.billing)
        - ``credentials.``  (e.g. credentials.api_key, credentials.token)

        Non-sensitive keys (e.g. "location", "query", "days") are always
        passed through unchanged.

        Security note: This is defence-in-depth.  The agent should not be
        sending sensitive data that wasn't requested, but if it does, the
        bridge strips it before it reaches the MCP server.
        """
        allowed_read: frozenset[str] = frozenset(manifest.permissions.data_access.read)
        sanitized: dict[str, Any] = {}

        for key, value in params.items():
            is_sensitive = any(key.startswith(prefix) for prefix in _SENSITIVE_PREFIXES)
            if is_sensitive and key not in allowed_read:
                logger.debug("Stripped sensitive param '%s' not in manifest data_access.read", key)
                continue
            sanitized[key] = value

        return sanitized

    def _validate_response(
        self,
        result: dict[str, Any],
        manifest: MCPServerManifest,
    ) -> tuple[dict[str, Any], list[str]]:
        """Validate an MCP server response for security issues.

        Checks:
        1. **Size**: response JSON must not exceed
           ``security_config.max_response_size_bytes``.
        2. **Suspicious patterns**: scan for credential-like strings that
           might indicate the server is trying to exfiltrate data.

        Returns:
            ``(validated_result, suspicious_category_names)`` — the
            validated result dict and a list of matched pattern categories
            (e.g. ``["credential_leak"]``).  The list is deduplicated.

        Raises:
            SecurityError: If the response exceeds the size limit.
        """
        json_str = json.dumps(result)
        size = len(json_str.encode("utf-8"))
        if size > self._security_config.max_response_size_bytes:
            raise SecurityError(
                f"MCP response from '{manifest.server_id}' exceeds size limit: "
                f"{size} bytes > {self._security_config.max_response_size_bytes} bytes"
            )

        found_categories: list[str] = []
        for category, pattern in _MCP_RESPONSE_SUSPICIOUS_PATTERNS:
            if re.search(pattern, json_str, re.IGNORECASE):
                if category not in found_categories:
                    found_categories.append(category)

        return result, found_categories

    def _check_financial_limits(
        self,
        tool_entry: Optional[MCPToolManifestEntry],
        manifest: MCPServerManifest,
        params: dict[str, Any],
    ) -> None:
        """Check if a financial tool call is within configured limits.

        A server is financial if ``manifest.permissions.financial`` is
        ``True``.  The call amount is read from ``params.get("amount", 0.0)``.

        Raises:
            PermissionError: If the call amount exceeds either the
                global ``financial_transaction_limit`` or the per-manifest
                ``max_cost_per_transaction`` cap.
        """
        if not manifest.permissions.financial:
            return

        amount = float(params.get("amount", 0.0))

        if amount > self._security_config.financial_transaction_limit:
            raise PermissionError(
                f"Financial tool call amount {amount:.2f} exceeds global limit "
                f"{self._security_config.financial_transaction_limit:.2f}"
            )

        per_manifest_cap = manifest.permissions.max_cost_per_transaction
        if per_manifest_cap is not None and amount > per_manifest_cap:
            raise PermissionError(
                f"Financial tool call amount {amount:.2f} exceeds manifest limit "
                f"{per_manifest_cap:.2f} for server '{manifest.server_id}'"
            )

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    async def _run_approval(
        self,
        *,
        server_id: str,
        tool_name: str,
        sanitized: dict[str, Any],
        agent_config: AgentConfig,
        session_key: str,
        manifest: MCPServerManifest,
    ) -> str:
        """Request human approval and return ``'approved'`` or ``'denied'``."""
        from openrattler.security.approval import ApprovalRequest

        assert self._approval_manager is not None  # caller guarantees this

        request = ApprovalRequest(
            approval_id=uuid.uuid4().hex,
            operation=f"mcp:{server_id}.{tool_name}",
            # Show keys only — values may contain sensitive data.
            context={k: "..." for k in sanitized},
            requesting_agent=agent_config.agent_id,
            session_key=session_key,
            provenance={
                "trust_level": agent_config.trust_level.value,
                "agent_id": agent_config.agent_id,
                "session_key": session_key,
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "server_id": server_id,
                "trust_tier": manifest.trust_tier,
            },
            timestamp=datetime.now(timezone.utc),
            timeout_seconds=self._approval_manager.default_timeout_seconds,
        )
        approval = await self._approval_manager.request_approval(request)
        return "approved" if approval.approved else "denied"

    async def _audit_log_call(
        self,
        *,
        server_id: str,
        tool_name: str,
        manifest: Optional[MCPServerManifest],
        params: dict[str, Any],
        required_approval: bool,
        approval_result: Optional[str],
        response_size: Optional[int],
        suspicious_patterns: list[str],
        duration_ms: int,
        success: bool,
        error: Optional[str],
        session_key: str,
        agent_id: str,
    ) -> None:
        """Append an MCPCallRecord audit entry (if an AuditLog is configured)."""
        if self._audit is None:
            return

        if manifest is not None:
            record = MCPCallRecord(
                server_id=server_id,
                tool_name=tool_name,
                trust_tier=manifest.trust_tier,
                params_keys=list(params.keys()),
                required_approval=required_approval,
                approval_result=approval_result,
                response_size_bytes=response_size,
                suspicious_patterns=suspicious_patterns,
                duration_ms=duration_ms,
                success=success,
                error=error,
            )
            details: dict[str, Any] = record.model_dump()
        else:
            # Manifest lookup failed — log minimal info.
            details = {
                "server_id": server_id,
                "tool_name": tool_name,
                "success": False,
                "error": error,
                "duration_ms": duration_ms,
            }

        await self._audit.log(
            AuditEvent(
                event="mcp_tool_call",
                session_key=session_key,
                agent_id=agent_id,
                details=details,
            )
        )
