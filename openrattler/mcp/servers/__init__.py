"""Bundled MCP server implementations for OpenRattler.

Each module in this package is a self-contained MCP server that runs as a
subprocess via stdio transport.  They have no access to OpenRattler internals
at runtime — they are isolated processes that communicate only via JSON-RPC.
"""
