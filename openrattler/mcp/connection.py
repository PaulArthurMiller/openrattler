"""MCP server connection lifecycle management.

MCPServerConnection wraps the MCP Python SDK's ClientSession to manage a
single MCP server connection. It handles:

- Transport setup: stdio subprocess or Streamable HTTP
- MCP initialize handshake (capabilities exchange)
- Tool discovery (tools/list)
- Tool execution (tools/call)
- Clean shutdown (idempotent)

This module does NOT handle security validation — that is MCPToolBridge's
responsibility.  This module is the "plumbing" that speaks JSON-RPC to the
server.

Security notes:
- Stdio subprocess receives ONLY a filtered subset of the parent environment:
  a minimal safe base plus the env vars explicitly declared in the manifest.
  OpenRattler credentials (API keys, tokens) are never included in the safe
  base, so MCP servers cannot read them via os.environ.
- HTTP connections use the manifest URL with no credential embedding.
- Connection timeout is enforced at the asyncio.wait_for level.
- Secrets must be passed to MCP servers via manifest.env references (resolved
  at runtime by the secret manager), never in command args or tool params.
"""

from __future__ import annotations

import asyncio
import os
from typing import Any

from mcp import ClientSession
from mcp.client.stdio import StdioServerParameters, stdio_client
from mcp.client.streamable_http import streamablehttp_client

from openrattler.models.mcp import MCPServerManifest

# ---------------------------------------------------------------------------
# Environment filtering
# ---------------------------------------------------------------------------

# Minimal set of env vars passed through to stdio subprocess servers.
# Anything not in this set (or not explicitly declared in manifest.env)
# is stripped.  OpenRattler secrets are intentionally absent.
_SAFE_ENV_KEYS: frozenset[str] = frozenset(
    {
        "PATH",
        "HOME",
        "USER",
        "LANG",
        "TERM",
        "PYTHONPATH",
        "VIRTUAL_ENV",
        # Windows platform vars
        "SystemRoot",
        "COMSPEC",
        # Temp dirs (cross-platform)
        "TMPDIR",
        "TMP",
        "TEMP",
    }
)


def _build_safe_env(manifest_env: dict[str, str]) -> dict[str, str]:
    """Build a filtered environment dict for an MCP stdio subprocess.

    Starts with a minimal safe subset of the current process environment,
    then overlays only the env vars explicitly declared in the manifest.

    OpenRattler credentials (OPENAI_API_KEY, ANTHROPIC_API_KEY, etc.) are
    never in the safe set — MCP servers cannot access them unless the user
    explicitly grants access via manifest.env.

    Args:
        manifest_env: Key-value pairs from MCPServerManifest.env.

    Returns:
        Filtered environment dict safe to pass to a subprocess.
    """
    safe: dict[str, str] = {k: os.environ[k] for k in _SAFE_ENV_KEYS if k in os.environ}
    safe.update(manifest_env)
    return safe


# ---------------------------------------------------------------------------
# MCPServerConnection
# ---------------------------------------------------------------------------


class MCPServerConnection:
    """Manages the lifecycle and communication with a single MCP server.

    Wraps the MCP Python SDK's ClientSession. Handles:
    - Transport setup (stdio subprocess or Streamable HTTP)
    - MCP initialize handshake
    - Tool discovery (tools/list)
    - Tool execution (tools/call)
    - Clean shutdown

    This class does NOT handle security validation — that is MCPToolBridge's
    job.  This class is the "plumbing" that speaks JSON-RPC to the server.

    Security notes:
    - Server credentials (API keys, tokens) must be passed ONLY via env vars
      to stdio subprocesses (manifest.env), never in command args or params.
    - The subprocess receives a filtered environment — only the safe base
      set plus manifest-declared vars.  OpenRattler secrets are excluded.
    - HTTP connections use the manifest URL with no credential embedding.
    - Connection timeout is enforced via asyncio.wait_for.
    """

    def __init__(
        self,
        manifest: MCPServerManifest,
        timeout_seconds: int = 30,
    ) -> None:
        self._manifest = manifest
        self._timeout = timeout_seconds

        # Set by _run_stdio / _run_http once the session is initialized.
        self._session: Any = None

        # Background task holding the transport context managers open.
        self._connect_task: asyncio.Task[None] | None = None

        # Signaled by _run_* once session.initialize() completes.
        self._initialized: asyncio.Event = asyncio.Event()

        # Set by disconnect() to trigger graceful shutdown in _run_*.
        self._disconnect_event: asyncio.Event = asyncio.Event()

        # If initialization raises, the exception is stored here and
        # re-raised as ConnectionError from connect().
        self._init_error: BaseException | None = None

    # ------------------------------------------------------------------
    # Properties
    # ------------------------------------------------------------------

    @property
    def server_id(self) -> str:
        """Unique server identifier from the manifest."""
        return self._manifest.server_id

    @property
    def is_connected(self) -> bool:
        """True while the MCP session is active and ready for calls."""
        return self._session is not None

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    async def connect(self) -> None:
        """Start the transport and perform the MCP initialize handshake.

        For stdio: starts the subprocess with a filtered environment and
        opens read/write streams.  For Streamable HTTP: creates an HTTP
        client session.  Then sends the MCP initialize request and waits
        for the server to report its capabilities.

        Idempotent: calling connect() on an already-connected server is a
        no-op.

        Raises:
            ConnectionError: If transport fails to start or handshake fails.
            TimeoutError: If initialization exceeds timeout_seconds.
        """
        if self._session is not None:
            return  # Already connected — idempotent

        # Fresh events for this connection attempt.
        self._initialized = asyncio.Event()
        self._disconnect_event = asyncio.Event()
        self._init_error = None

        if self._manifest.transport == "stdio":
            self._connect_task = asyncio.create_task(self._run_stdio())
        else:
            self._connect_task = asyncio.create_task(self._run_http())

        try:
            await asyncio.wait_for(self._initialized.wait(), timeout=self._timeout)
        except asyncio.TimeoutError:
            # Cancel the background task — it may be blocked inside the SDK.
            if self._connect_task and not self._connect_task.done():
                self._connect_task.cancel()
                try:
                    await self._connect_task
                except (asyncio.CancelledError, Exception):
                    pass
            raise TimeoutError(
                f"MCP server '{self._manifest.server_id}' initialization timed out "
                f"after {self._timeout}s"
            )

        if self._init_error is not None:
            err = self._init_error
            raise ConnectionError(
                f"MCP server '{self._manifest.server_id}' initialization failed: {err}"
            ) from err

    async def disconnect(self) -> None:
        """Clean shutdown of the MCP server connection.

        For stdio: signals the background task to exit the subprocess context
        manager, which closes streams and terminates the process.
        For Streamable HTTP: closes the HTTP client.

        Safe to call multiple times (idempotent).
        """
        if self._connect_task is None or self._connect_task.done():
            return  # Already disconnected — idempotent

        self._disconnect_event.set()
        try:
            await self._connect_task
        except (asyncio.CancelledError, Exception):
            pass
        self._connect_task = None

    async def list_tools(self) -> list[dict[str, Any]]:
        """Discover tools offered by the connected MCP server.

        Calls tools/list and returns the raw tool definitions as plain dicts.
        These are used by MCPManager to register tools with the ToolRegistry.

        Returns:
            List of tool definition dicts with keys: name, description,
            inputSchema.

        Raises:
            ConnectionError: If not connected.
        """
        if self._session is None:
            raise ConnectionError(f"MCP server '{self._manifest.server_id}' is not connected")
        result = await self._session.list_tools()
        return [
            {
                "name": tool.name,
                "description": tool.description or "",
                "inputSchema": tool.inputSchema,
            }
            for tool in result.tools
        ]

    async def call_tool(
        self,
        tool_name: str,
        arguments: dict[str, Any],
    ) -> dict[str, Any]:
        """Execute a tool on the MCP server.

        Sends a tools/call JSON-RPC request and returns the result as a plain
        dict.  Timeout is enforced via asyncio.wait_for.

        This method does NOT validate permissions, sanitize params, or check
        approval — that is MCPToolBridge's responsibility.  This method only
        handles the wire protocol.

        Args:
            tool_name: Name of the tool to call (as declared by the server).
            arguments: Arguments matching the tool's inputSchema.

        Returns:
            Result dict from the server's response (serialized CallToolResult).

        Raises:
            ConnectionError: If not connected.
            TimeoutError: If the call exceeds timeout_seconds.
            RuntimeError: If the server returns a JSON-RPC error result
                (isError=True in the response).
        """
        if self._session is None:
            raise ConnectionError(f"MCP server '{self._manifest.server_id}' is not connected")
        try:
            result = await asyncio.wait_for(
                self._session.call_tool(tool_name, arguments),
                timeout=self._timeout,
            )
        except asyncio.TimeoutError:
            raise TimeoutError(
                f"MCP tool '{tool_name}' on server '{self._manifest.server_id}' "
                f"timed out after {self._timeout}s"
            )

        if result.isError:
            error_parts = [getattr(c, "text", str(c)) for c in result.content if hasattr(c, "text")]
            raise RuntimeError(
                f"MCP tool '{tool_name}' on server '{self._manifest.server_id}' "
                f"returned an error: " + ("; ".join(error_parts) or "unknown error")
            )

        return result.model_dump()  # type: ignore[no-any-return]

    # ------------------------------------------------------------------
    # Background transport tasks
    # ------------------------------------------------------------------

    async def _run_stdio(self) -> None:
        """Hold the stdio transport open until disconnect is requested.

        Runs as a background asyncio Task created by connect().
        Signals _initialized when the MCP handshake completes.
        Stores any initialization exception in _init_error.
        """
        try:
            assert self._manifest.command is not None  # validated by MCPServerManifest
            server_params = StdioServerParameters(
                command=self._manifest.command,
                args=self._manifest.args,
                env=_build_safe_env(self._manifest.env),
            )
            async with stdio_client(server_params) as (read, write):
                async with ClientSession(read, write) as session:
                    await session.initialize()
                    self._session = session
                    self._initialized.set()
                    # Hold the connection open until disconnect() is called.
                    await self._disconnect_event.wait()
        except Exception as exc:
            self._init_error = exc
            self._initialized.set()
        finally:
            self._session = None

    async def _run_http(self) -> None:
        """Hold the Streamable HTTP transport open until disconnect is requested.

        Runs as a background asyncio Task created by connect().
        Signals _initialized when the MCP handshake completes.
        Stores any initialization exception in _init_error.
        """
        try:
            assert self._manifest.url is not None  # validated by MCPServerManifest
            async with streamablehttp_client(url=self._manifest.url) as (read, write, _):
                async with ClientSession(read, write) as session:
                    await session.initialize()
                    self._session = session
                    self._initialized.set()
                    # Hold the connection open until disconnect() is called.
                    await self._disconnect_event.wait()
        except Exception as exc:
            self._init_error = exc
            self._initialized.set()
        finally:
            self._session = None
