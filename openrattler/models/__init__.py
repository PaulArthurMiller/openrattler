"""OpenRattler data models."""

from openrattler.models.mcp import (
    MCPCallRecord,
    MCPDataAccessPermissions,
    MCPFileSystemPermissions,
    MCPNetworkPermissions,
    MCPPermissions,
    MCPSecurityConfig,
    MCPServerManifest,
    MCPToolManifestEntry,
    MCPTrustTier,
)
from openrattler.models.agents import (
    AgentConfig,
    AgentCreationRequest,
    AgentSpawnLimits,
    TaskTemplate,
    TrustLevel,
)
from openrattler.models.audit import AuditEvent
from openrattler.models.errors import ErrorCode
from openrattler.models.messages import (
    UniversalMessage,
    create_error,
    create_message,
    create_response,
)
from openrattler.models.sessions import Peer, Session, SessionKey
from openrattler.models.tools import ToolCall, ToolDefinition, ToolResult

__all__ = [
    # messages
    "UniversalMessage",
    "create_message",
    "create_response",
    "create_error",
    # errors
    "ErrorCode",
    # agents
    "TrustLevel",
    "AgentConfig",
    "TaskTemplate",
    "AgentCreationRequest",
    "AgentSpawnLimits",
    # sessions
    "SessionKey",
    "Session",
    "Peer",
    # tools
    "ToolDefinition",
    "ToolCall",
    "ToolResult",
    # audit
    "AuditEvent",
    # mcp
    "MCPTrustTier",
    "MCPNetworkPermissions",
    "MCPDataAccessPermissions",
    "MCPFileSystemPermissions",
    "MCPToolManifestEntry",
    "MCPPermissions",
    "MCPServerManifest",
    "MCPSecurityConfig",
    "MCPCallRecord",
]
