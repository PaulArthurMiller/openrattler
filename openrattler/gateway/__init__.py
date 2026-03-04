"""OpenRattler gateway layer — session routing and WebSocket server.

Public API::

    from openrattler.gateway import Gateway, TokenAuth
"""

from openrattler.gateway.auth import TokenAuth
from openrattler.gateway.server import (
    CURRENT_PROTOCOL_VERSION,
    MIN_PROTOCOL_VERSION,
    ConnectionInfo,
    ConnectionRateLimiter,
    Gateway,
)

__all__ = [
    "TokenAuth",
    "Gateway",
    "ConnectionInfo",
    "ConnectionRateLimiter",
    "MIN_PROTOCOL_VERSION",
    "CURRENT_PROTOCOL_VERSION",
]
