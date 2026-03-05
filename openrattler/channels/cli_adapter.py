"""CLI channel adapter — wraps stdin/stdout as an OpenRattler channel.

``CLIAdapter`` bridges the command-line interface to the UniversalMessage
protocol.  Inbound messages are created from typed text; outbound messages
are rendered as plain-text lines on stdout.

The session key for CLI interaction is always ``"agent:main:main"`` — the
personal DM session — so the user's keyboard input always reaches the main
agent in the main context.

SECURITY NOTES
--------------
- ``trust_level`` is always ``"main"`` for CLI input.  The keyboard operator
  is the system owner; no lower trust level is appropriate.
- ``get_session_key`` ignores *peer_info* entirely and returns the fixed
  constant — the CLI has exactly one session and there is no peer lookup
  that could be manipulated.
- ``_text_to_message`` is exposed (not private) so ``CLIChat`` and tests can
  create well-formed messages from text without going through blocking I/O.
"""

from __future__ import annotations

import asyncio
import sys
from typing import Any

from openrattler.channels.base import ChannelAdapter
from openrattler.models.messages import UniversalMessage, create_message

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

#: Fixed session key for all CLI interactions.
CLI_SESSION_KEY: str = "agent:main:main"

#: Prompt shown to the user when waiting for input.
_INPUT_PROMPT: str = "You: "

#: Prefix printed before agent responses.
_RESPONSE_PREFIX: str = "Assistant: "


# ---------------------------------------------------------------------------
# CLIAdapter
# ---------------------------------------------------------------------------


class CLIAdapter(ChannelAdapter):
    """Channel adapter wrapping stdin/stdout for CLI interaction.

    Usage::

        adapter = CLIAdapter()
        await adapter.connect()          # no-op for CLI
        msg = await adapter.receive()    # reads a line from stdin
        await adapter.send(response)     # prints to stdout
        await adapter.disconnect()       # no-op for CLI

    For unit tests, call ``text_to_message(text)`` directly instead of
    ``receive()`` to avoid blocking I/O.

    Security notes:
    - ``trust_level`` is hardcoded to ``"main"`` — not derived from user input.
    - ``get_session_key`` always returns ``CLI_SESSION_KEY`` regardless of
      *peer_info*, so there is no injection surface in the session key path.
    """

    # ------------------------------------------------------------------
    # ChannelAdapter identity
    # ------------------------------------------------------------------

    @property
    def channel_name(self) -> str:
        """Identifier for this channel."""
        return "cli"

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    async def connect(self) -> None:
        """No-op — stdin/stdout are always available."""

    async def disconnect(self) -> None:
        """No-op — no connection to clean up."""

    # ------------------------------------------------------------------
    # I/O
    # ------------------------------------------------------------------

    async def receive(self) -> UniversalMessage:
        """Read one line from stdin and return it as a UniversalMessage.

        Prints the prompt (``"You: "``) then waits for the user to press
        Enter.  I/O is offloaded to a thread so the event loop is not
        blocked.

        Raises:
            EOFError:         stdin is closed (Ctrl+D / piped input exhausted).
            KeyboardInterrupt: user pressed Ctrl+C.

        Security notes:
        - ``trust_level`` and ``session_key`` are set by this method, never
          by the content of the typed text.
        """
        # run_in_executor keeps the event loop non-blocking.
        loop = asyncio.get_event_loop()
        text: str = await loop.run_in_executor(None, self._read_line)
        return self.text_to_message(text.strip())

    async def send(self, message: UniversalMessage) -> None:
        """Print *message* to stdout.

        Handles ``type="response"`` (normal output) and ``type="error"``
        (formatted error string).  Any other type is printed as-is from
        ``params["content"]``.

        Args:
            message: UniversalMessage to render.
        """
        text = self._format_response(message)
        # asyncio.to_thread is not strictly necessary here (print is fast)
        # but keeps the I/O pattern symmetric with receive().
        print(f"{_RESPONSE_PREFIX}{text}\n", file=sys.stdout)

    # ------------------------------------------------------------------
    # Routing
    # ------------------------------------------------------------------

    def get_session_key(self, peer_info: dict[str, Any]) -> str:
        """Return the fixed CLI session key regardless of *peer_info*.

        Security notes:
        - *peer_info* is intentionally ignored.  There is only one CLI
          session and it must not be influenced by external input.
        """
        return CLI_SESSION_KEY

    # ------------------------------------------------------------------
    # Message helpers (public for testing)
    # ------------------------------------------------------------------

    def text_to_message(self, text: str) -> UniversalMessage:
        """Wrap *text* in a ``user_message`` UniversalMessage.

        This is the canonical way to produce an inbound CLI message.
        ``receive()`` calls this internally; tests can call it directly
        to avoid blocking on stdin.

        Args:
            text: Plain text typed by the user.

        Returns:
            A ``type="request"`` UniversalMessage with ``operation="user_message"``,
            ``trust_level="main"``, and ``session_key="agent:main:main"``.

        Security notes:
        - ``trust_level`` and ``session_key`` are always set here, never
          derived from *text* itself.
        """
        return create_message(
            from_agent="channel:cli",
            to_agent=CLI_SESSION_KEY,
            session_key=CLI_SESSION_KEY,
            type="request",
            operation="user_message",
            trust_level="main",
            params={"content": text},
            channel="cli",
        )

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _read_line() -> str:
        """Blocking stdin read — run inside a thread executor."""
        return input(_INPUT_PROMPT)

    @staticmethod
    def _format_response(message: UniversalMessage) -> str:
        """Extract printable text from a UniversalMessage."""
        if message.type == "response":
            return str(message.params.get("content", ""))
        if message.type == "error":
            error = message.error or {}
            return f"[Error: {error.get('message', 'unknown error')}]"
        # event or unexpected type — fall back to content if present
        return str(message.params.get("content", str(message.params)))
