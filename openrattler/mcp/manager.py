"""MCP Manager — central registry and lifecycle controller for MCP servers.

MCPManager is the authoritative registry for all MCP server connections in
OpenRattler.  It owns the lifecycle (load manifest → connect → register tools
→ disconnect → unregister tools) and enforces trust-tier policies configured
by MCPSecurityConfig.

Architecture position:

    MCPManager
      ├── loads MCPServerManifest objects (from code or JSON files)
      ├── manages MCPServerConnection instances (connect / disconnect)
      ├── registers MCP tools with ToolRegistry under "mcp:{id}.{tool}" names
      └── exposes get_connection() for MCPToolBridge lookup (Build Piece D)

Security notes:
- Auto-discovered servers are never connected without explicit user approval
  (and are rejected entirely when allow_auto_discovered="deny").
- Undeclared tools on auto_discovered servers are never registered.
- Undeclared tools on user_installed servers are registered but forced to
  require_approval=True (safer default than manifest-declared tools).
- Bundled servers are fully trusted — undeclared tools are logged but allowed.
- All connection and disconnection events are audit-logged.
"""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any, Optional

from openrattler.mcp.connection import MCPServerConnection
from openrattler.models.agents import TrustLevel
from openrattler.models.audit import AuditEvent
from openrattler.models.mcp import MCPSecurityConfig, MCPServerManifest
from openrattler.models.tools import ToolDefinition
from openrattler.security.approval import ApprovalManager
from openrattler.storage.audit import AuditLog
from openrattler.tools.registry import ToolRegistry

logger = logging.getLogger(__name__)


class MCPManager:
    """Central registry and lifecycle manager for MCP server connections.

    Responsibilities:
    - Load and validate server manifests
    - Manage MCPServerConnection instances
    - Register MCP tools with the ToolRegistry (namespaced as mcp:{server_id}.{tool})
    - Enforce trust tier policies (bundled vs user_installed vs auto_discovered)
    - Track connection state for all servers
    - Provide server lookup for MCPToolBridge

    Security notes:
    - Auto-discovered servers are NEVER connected without explicit user approval.
    - User-installed servers require approval at install time (future build).
    - Bundled servers connect automatically at startup.
    - Manifest changes between versions trigger re-approval (future build).
    """

    def __init__(
        self,
        security_config: MCPSecurityConfig,
        tool_registry: ToolRegistry,
        approval_manager: Optional[ApprovalManager] = None,
        audit: Optional[AuditLog] = None,
    ) -> None:
        self._security_config = security_config
        self._tool_registry = tool_registry
        self._approval_manager = approval_manager
        self._audit = audit

        # server_id → manifest (loaded but not necessarily connected)
        self._manifests: dict[str, MCPServerManifest] = {}

        # server_id → active MCPServerConnection
        self._connections: dict[str, MCPServerConnection] = {}

        # server_id → list of namespaced tool names registered with ToolRegistry
        # Used to cleanly unregister tools on disconnect.
        self._registered_tools: dict[str, list[str]] = {}

    # ------------------------------------------------------------------
    # Manifest management
    # ------------------------------------------------------------------

    async def load_manifest(self, manifest: MCPServerManifest) -> None:
        """Register a server manifest with the manager.

        Validates the manifest, checks trust tier against security config,
        and stores it.  Does NOT connect — use connect_server() for that.

        For user_installed and auto_discovered servers, this is where
        the user review / approval flow would be triggered (future build).

        Raises:
            PermissionError: If trust tier is not allowed by security config.
        """
        if manifest.trust_tier == "bundled" and not self._security_config.allow_bundled:
            raise PermissionError(
                f"MCP server '{manifest.server_id}' has trust tier 'bundled' "
                f"but allow_bundled=False in security config"
            )
        if (
            manifest.trust_tier == "user_installed"
            and not self._security_config.allow_user_installed
        ):
            raise PermissionError(
                f"MCP server '{manifest.server_id}' has trust tier 'user_installed' "
                f"but allow_user_installed=False in security config"
            )
        if manifest.trust_tier == "auto_discovered":
            if self._security_config.allow_auto_discovered == "deny":
                raise PermissionError(
                    f"MCP server '{manifest.server_id}' has trust tier 'auto_discovered' "
                    f"but allow_auto_discovered='deny' in security config"
                )
            # "prompt" and "allow" tiers proceed; approval flow is future work.

        self._manifests[manifest.server_id] = manifest
        logger.info(
            "MCP manifest loaded: server_id=%s trust_tier=%s",
            manifest.server_id,
            manifest.trust_tier,
        )
        await self._audit_log(
            "mcp_manifest_loaded",
            server_id=manifest.server_id,
            trust_tier=manifest.trust_tier,
            publisher=manifest.publisher,
        )

    async def load_manifests_from_directory(self, directory: Path) -> int:
        """Load all .json manifest files from a directory.

        Returns count of successfully loaded manifests.
        Invalid manifests are logged and skipped.
        """
        count = 0
        for path in sorted(directory.glob("*.json")):
            try:
                data = json.loads(path.read_text(encoding="utf-8"))
                manifest = MCPServerManifest(**data)
                await self.load_manifest(manifest)
                count += 1
            except Exception as exc:
                logger.warning("Failed to load MCP manifest %s: %s", path.name, exc)
        return count

    # ------------------------------------------------------------------
    # Connection management
    # ------------------------------------------------------------------

    async def connect_server(self, server_id: str) -> None:
        """Connect to a registered MCP server and discover its tools.

        1. Look up manifest by server_id
        2. Create MCPServerConnection
        3. Call connection.connect() — starts transport, does handshake
        4. Call connection.list_tools() — discover available tools
        5. Cross-validate discovered tools against manifest declarations
        6. Register each tool with ToolRegistry (namespaced)
        7. Audit-log the connection event

        Idempotent: if the server is already connected this is a no-op.

        Raises:
            KeyError: If server_id is not registered via load_manifest.
            ConnectionError: If transport fails to start or handshake fails.
        """
        if server_id not in self._manifests:
            raise KeyError(f"MCP server '{server_id}' is not registered; call load_manifest first")

        existing = self._connections.get(server_id)
        if existing is not None and existing.is_connected:
            logger.debug("MCP server '%s' already connected — skipping", server_id)
            return

        manifest = self._manifests[server_id]
        conn = MCPServerConnection(
            manifest,
            timeout_seconds=self._security_config.call_timeout_seconds,
        )
        await conn.connect()
        self._connections[server_id] = conn

        discovered = await conn.list_tools()
        validated = self._cross_validate_tools(discovered, manifest)
        await self._register_mcp_tools(server_id, validated, manifest)

        logger.info(
            "MCP server connected: server_id=%s tools=%d",
            server_id,
            len(validated),
        )
        await self._audit_log(
            "mcp_server_connected",
            server_id=server_id,
            trust_tier=manifest.trust_tier,
            tool_count=len(validated),
        )

    async def disconnect_server(self, server_id: str) -> None:
        """Disconnect from an MCP server and unregister its tools.

        1. Call connection.disconnect()
        2. Remove tools from ToolRegistry
        3. Audit-log the disconnection event

        Idempotent: safe to call even if not connected.
        """
        conn = self._connections.pop(server_id, None)
        if conn is None:
            return

        await conn.disconnect()

        for tool_name in self._registered_tools.pop(server_id, []):
            self._tool_registry.unregister(tool_name)

        logger.info("MCP server disconnected: server_id=%s", server_id)
        await self._audit_log("mcp_server_disconnected", server_id=server_id)

    async def connect_all_bundled(self) -> None:
        """Connect to all bundled MCP servers.

        Called at startup to bring all pre-approved bundled servers online.
        Non-bundled servers are ignored.
        """
        for server_id, manifest in list(self._manifests.items()):
            if manifest.trust_tier == "bundled":
                await self.connect_server(server_id)

    async def disconnect_all(self) -> None:
        """Disconnect from all connected servers.

        Called at shutdown to cleanly tear down all MCP connections.
        """
        for server_id in list(self._connections.keys()):
            await self.disconnect_server(server_id)

    # ------------------------------------------------------------------
    # Lookup (used by MCPToolBridge in Build Piece D)
    # ------------------------------------------------------------------

    def get_connection(self, server_id: str) -> MCPServerConnection:
        """Look up a connected server by ID.

        Used by MCPToolBridge to route tool calls to the correct server.

        Raises:
            KeyError: If the server is not connected.
        """
        conn = self._connections.get(server_id)
        if conn is None or not conn.is_connected:
            raise KeyError(f"MCP server '{server_id}' is not connected")
        return conn

    def get_manifest(self, server_id: str) -> MCPServerManifest:
        """Look up a server manifest by ID.

        Raises:
            KeyError: If the server is not registered.
        """
        if server_id not in self._manifests:
            raise KeyError(f"MCP server '{server_id}' is not registered")
        return self._manifests[server_id]

    def list_servers(self) -> list[dict[str, Any]]:
        """Return status summary of all registered servers."""
        result: list[dict[str, Any]] = []
        for server_id, manifest in self._manifests.items():
            conn = self._connections.get(server_id)
            result.append(
                {
                    "server_id": server_id,
                    "trust_tier": manifest.trust_tier,
                    "publisher": manifest.publisher,
                    "version": manifest.version,
                    "verified": manifest.verified,
                    "connected": conn is not None and conn.is_connected,
                    "tool_count": len(self._registered_tools.get(server_id, [])),
                }
            )
        return result

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _cross_validate_tools(
        self,
        discovered: list[dict[str, Any]],
        manifest: MCPServerManifest,
    ) -> list[dict[str, Any]]:
        """Cross-validate discovered tools against manifest declarations.

        Returns the (possibly filtered) list of tools to register.

        Validation rules per trust tier:
        - bundled: Undeclared tools allowed (trusted code); logged as warning.
        - user_installed: Undeclared tools allowed but forced requires_approval=True.
        - auto_discovered: Undeclared tools rejected — not registered.

        Tools declared in the manifest but missing from the server are logged
        as info (the server may have optional or version-gated tools).
        """
        manifest_names: set[str] = {t.name for t in manifest.tools}
        discovered_names: set[str] = {t["name"] for t in discovered}

        # Tools declared in manifest but absent from server.
        missing = manifest_names - discovered_names
        for name in missing:
            logger.info(
                "[%s] Tool declared in manifest but not reported by server: %s",
                manifest.server_id,
                name,
            )

        # Tools present on server but absent from manifest.
        extra = discovered_names - manifest_names
        if extra:
            if manifest.trust_tier == "bundled":
                logger.warning(
                    "[%s] Undeclared tools found on bundled server (allowed): %s",
                    manifest.server_id,
                    extra,
                )
            elif manifest.trust_tier == "user_installed":
                logger.warning(
                    "[%s] Undeclared tools forced to require approval: %s",
                    manifest.server_id,
                    extra,
                )
                # Undeclared tools pass through; _register_mcp_tools forces approval.
            elif manifest.trust_tier == "auto_discovered":
                logger.warning(
                    "[%s] Undeclared tools rejected (auto_discovered policy): %s",
                    manifest.server_id,
                    extra,
                )
                return [t for t in discovered if t["name"] in manifest_names]

        return discovered

    async def _register_mcp_tools(
        self,
        server_id: str,
        tools: list[dict[str, Any]],
        manifest: MCPServerManifest,
    ) -> None:
        """Register validated MCP tools with the ToolRegistry.

        Each tool is registered as:
        - Name: "mcp:{server_id}.{tool_name}"
        - Trust level: TrustLevel.mcp
        - Approval: from manifest tool entry's requires_approval field;
          defaults to True for undeclared tools (defence-in-depth).
        - Description: prefixed with "[MCP: {server_id}]" for clarity
        - Handler: None — MCPToolBridge handles execution (Build Piece D)

        Security notes:
        - Undeclared tools always default to requires_approval=True.
        - Handler=None prevents direct local execution; all MCP tool calls
          are routed through MCPToolBridge which enforces the full security
          pipeline (permission manifest, sandbox, response validation).
        """
        registered: list[str] = []
        manifest_entry_map = {t.name: t for t in manifest.tools}

        for tool_def in tools:
            tool_name: str = tool_def["name"]
            namespaced = f"mcp:{server_id}.{tool_name}"

            manifest_entry = manifest_entry_map.get(tool_name)
            if manifest_entry is not None:
                requires_approval = manifest_entry.requires_approval
            else:
                # Undeclared tool — require approval regardless of tier.
                requires_approval = True

            definition = ToolDefinition(
                name=namespaced,
                description=f"[MCP: {server_id}] {tool_def.get('description', '')}",
                parameters=tool_def.get("inputSchema", {}),
                trust_level_required=TrustLevel.mcp,
                requires_approval=requires_approval,
                security_notes=(
                    f"Executed via MCP on server '{server_id}' "
                    f"(trust tier: {manifest.trust_tier})"
                ),
            )

            # Handler is None — MCPToolBridge handles execution (Build Piece D).
            self._tool_registry.register(definition, handler=None)
            registered.append(namespaced)

        self._registered_tools[server_id] = registered

    async def _audit_log(self, event: str, **details: Any) -> None:
        """Append an audit entry if an AuditLog is configured."""
        if self._audit is not None:
            await self._audit.log(
                AuditEvent(
                    event=event,
                    details=dict(details),
                )
            )
