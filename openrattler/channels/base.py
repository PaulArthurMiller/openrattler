"""Abstract base class for OpenRattler channel adapters.

A *channel adapter* is the bridge between an external communication channel
(CLI, Telegram, Discord, SMS, …) and the rest of the OpenRattler system.
Every adapter translates channel-native I/O into ``UniversalMessage`` objects
so the gateway, agent runtime, and security layers never see raw channel data.

INTERFACE
---------
Implementors must provide:

- ``channel_name``       — A short identifier (e.g. ``"cli"``, ``"telegram"``).
- ``receive()``          — Wait for incoming input and return a UniversalMessage.
- ``send()``             — Translate a UniversalMessage to channel output and send.
- ``connect()``          — Establish channel connection (no-op for always-on channels).
- ``disconnect()``       — Clean up the connection.
- ``get_session_key()``  — Derive a session key from channel-specific peer info.

SECURITY NOTES
--------------
- Channel adapters are the first trust boundary.  They must set
  ``trust_level`` correctly on every inbound message — never let the
  channel control this value.
- ``get_session_key`` must produce a validated ``agent:``-prefixed key so
  the router can never be tricked into routing to an arbitrary path.
- Adapters must not retain or log message content beyond what is needed for
  I/O.  Full logging is handled downstream by the audit layer.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any

from openrattler.models.messages import UniversalMessage


class ChannelAdapter(ABC):
    """Abstract interface for all OpenRattler channel adapters.

    Concrete subclasses implement this interface for each external channel
    (CLI, Telegram, Discord, SMS, etc.).  The gateway uses ``receive()`` to
    pull inbound messages and ``send()`` to deliver responses, while
    ``connect()`` / ``disconnect()`` manage the channel lifecycle.

    Security notes:
    - ``receive()`` is responsible for setting ``trust_level`` and
      ``session_key`` correctly — these fields must reflect the channel's
      trust posture, not any value supplied by the remote sender.
    - Implementations should call ``get_session_key`` to derive the session
      key from verified peer information, not from user-supplied data.
    """

    # ------------------------------------------------------------------
    # Identity
    # ------------------------------------------------------------------

    @property
    @abstractmethod
    def channel_name(self) -> str:
        """Short identifier for this channel (e.g. ``"cli"``, ``"telegram"``)."""

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    @abstractmethod
    async def connect(self) -> None:
        """Establish the channel connection.

        For always-available channels (e.g. CLI stdin/stdout) this is a
        no-op.  For network channels (e.g. Telegram) this authenticates
        and opens the connection.
        """

    @abstractmethod
    async def disconnect(self) -> None:
        """Clean up the channel connection.

        Called when the adapter is shutting down.  Should be idempotent —
        calling it on an already-disconnected adapter must not raise.
        """

    # ------------------------------------------------------------------
    # I/O
    # ------------------------------------------------------------------

    @abstractmethod
    async def receive(self) -> UniversalMessage:
        """Wait for an inbound message and return it as a UniversalMessage.

        Blocks until a message is available.  Raises ``EOFError`` when the
        channel is closed (e.g. stdin EOF) or ``KeyboardInterrupt`` on
        Ctrl+C — callers should handle these to exit cleanly.

        Security notes:
        - ``trust_level`` must be set by the adapter, not derived from
          anything the remote sender controls.
        - ``session_key`` must be derived via ``get_session_key`` from
          verified peer info.
        """

    @abstractmethod
    async def send(self, message: UniversalMessage) -> None:
        """Translate *message* to the channel's native format and deliver it.

        Args:
            message: The UniversalMessage to deliver.  Typically a
                     ``type="response"`` or ``type="error"`` message.
        """

    # ------------------------------------------------------------------
    # Routing
    # ------------------------------------------------------------------

    @abstractmethod
    def get_session_key(self, peer_info: dict[str, Any]) -> str:
        """Derive a validated session key from channel-specific peer info.

        Args:
            peer_info: Channel-specific dict identifying the sender
                       (e.g. ``{"user_id": 12345}`` for Telegram).

        Returns:
            A validated ``agent:``-prefixed session key string.

        Security notes:
        - The returned key must always begin with ``"agent:"`` so the
          router can never be given a key that escapes the session namespace.
        - Implementations should not let user-controlled data in *peer_info*
          dictate arbitrary key values — derive the key from a verified
          identifier such as a user ID, not from a user-supplied string.
        """
