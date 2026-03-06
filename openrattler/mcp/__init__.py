"""MCP (Model Context Protocol) client framework.

OpenRattler acts as an MCP *client* — it connects to MCP servers, discovers
their tools, and executes those tools on behalf of agents. This package wraps
the official MCP Python SDK with OpenRattler's security architecture:

- Trust tiers (bundled / user_installed / auto_discovered)
- Permission manifests (network, data, filesystem, exec, financial)
- Sandbox isolation and response validation
- Human-in-the-loop approval gates
- Audit logging of every tool call

Architecture::

    Agent Runtime
        ↓ ToolCall: name="mcp:weather-mcp.get_forecast"
    Tool Executor  (routes mcp:-prefixed calls here)
        ↓
    MCPToolBridge  (security chokepoint: validation, approval, audit)
        ↓
    MCPServerConnection  (MCP SDK wrapper: transport, JSON-RPC)
        ↓ stdio or Streamable HTTP
    External MCP Server
"""
