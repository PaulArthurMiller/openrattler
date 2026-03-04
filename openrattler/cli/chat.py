"""CLI channel adapter — keyboard input to agent turns.

``CLIChat`` is the first channel adapter in OpenRattler.  It follows the
same pattern that all future channel adapters will use:

1. Translate external input (keyboard line) → ``UniversalMessage``
2. Pass to ``AgentRuntime.process_message``
3. Translate ``UniversalMessage`` response → external output (print)

The session key for direct CLI interaction is always ``"agent:main:main"``
(the personal DM session).

COMPONENT WIRING
----------------
``CLIChat`` owns:
- ``TranscriptStore``    — persists conversation history
- ``MemoryStore``        — persists agent memory
- ``AuditLog``           — records security-relevant events
- ``ToolRegistry``       — discovers available tools
- ``ToolExecutor``       — runs tool calls on behalf of the agent
- ``AgentRuntime``       — orchestrates LLM turns

All components are built in ``open()`` so the constructor stays lightweight
and can accept an injected ``LLMProvider`` for testing.

SECURITY NOTES
--------------
- The provider is built from ``ANTHROPIC_API_KEY`` / ``OPENAI_API_KEY``
  environment variables — never from config files — so secrets are not
  stored on disk.
- ``send()`` uses ``trust_level="main"`` for CLI input because direct
  keyboard interaction is always from the trusted owner.
- Slash commands that show session history or audit events are read-only;
  they never modify state.
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Optional

from openrattler.agents.providers.base import LLMProvider
from openrattler.agents.providers.anthropic_provider import AnthropicProvider
from openrattler.agents.providers.openai_provider import OpenAIProvider
from openrattler.agents.runtime import AgentRuntime
from openrattler.config.loader import DEFAULT_CONFIG_PATH, AppConfig, load_config
from openrattler.models.agents import AgentConfig, TrustLevel
from openrattler.models.messages import create_message
from openrattler.models.sessions import Session
from openrattler.storage.audit import AuditLog
from openrattler.storage.memory import MemoryStore
from openrattler.storage.transcripts import TranscriptStore
from openrattler.tools.executor import ToolExecutor
from openrattler.tools.registry import ToolRegistry

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

#: Session key used for all CLI interactions (personal DM session).
CLI_SESSION_KEY: str = "agent:main:main"

#: Default workspace directory.
DEFAULT_WORKSPACE: Path = Path.home() / ".openrattler"

#: Default agent config used when no agent is defined in the config file.
_DEFAULT_AGENT_CONFIG = AgentConfig(
    agent_id="agent:main:main",
    name="Main",
    description="OpenRattler personal assistant",
    model="anthropic/claude-sonnet-4-6",
    trust_level=TrustLevel.main,
    system_prompt=(
        "You are OpenRattler, a helpful, concise personal AI assistant. "
        "Answer questions accurately and directly."
    ),
)

_HELP_TEXT = """\
Available commands:
  /quit, /exit       — end the session
  /session           — show current session key
  /history [n]       — show last N messages (default 10)
  /audit [n]         — show last N audit events (default 5)
  /help              — show this help
"""


# ---------------------------------------------------------------------------
# Provider auto-detection
# ---------------------------------------------------------------------------


def _build_provider_from_env() -> LLMProvider:
    """Build an LLM provider from environment variables.

    Checks ``ANTHROPIC_API_KEY`` first, then ``OPENAI_API_KEY``.

    Raises:
        RuntimeError: If neither key is set.

    Security notes:
    - Keys are read from environment variables, never from disk or config
      files, so they are not persisted alongside other config data.
    """
    anthropic_key = os.environ.get("ANTHROPIC_API_KEY")
    if anthropic_key:
        return AnthropicProvider(api_key=anthropic_key)

    openai_key = os.environ.get("OPENAI_API_KEY")
    if openai_key:
        return OpenAIProvider(api_key=openai_key)

    raise RuntimeError(
        "No LLM API key found. "
        "Set ANTHROPIC_API_KEY or OPENAI_API_KEY before running 'openrattler chat'."
    )


# ---------------------------------------------------------------------------
# Config helpers
# ---------------------------------------------------------------------------


def _get_agent_config(config: AppConfig) -> AgentConfig:
    """Return the main agent config from *config*, or the default if absent."""
    return config.agents.get("main", _DEFAULT_AGENT_CONFIG)


# ---------------------------------------------------------------------------
# CLIChat
# ---------------------------------------------------------------------------


class CLIChat:
    """Interactive command-line chat interface (CLI channel adapter).

    Lifecycle::

        chat = CLIChat(workspace_dir=tmp_path, provider=mock_provider)
        await chat.open()          # build components, init session
        response = await chat.send("Hello!")   # process one turn
        await chat.start()         # full interactive loop (calls open() first)

    ``open()`` and ``send()`` are the testable surface.  ``start()`` is the
    production entry point.

    Args:
        workspace_dir: Root directory for sessions, memory, and audit storage.
                       Defaults to ``~/.openrattler``.
        config_path:   Path to the JSON config file.  Defaults to
                       ``~/.openrattler/config.json``.
        provider:      Optional injected LLM provider.  If ``None``,
                       ``open()`` will auto-detect from environment variables.

    Security notes:
    - All user input goes through ``AgentRuntime.process_message``, which
      runs tool permission checks and audit-logs every turn.
    - The session key ``"agent:main:main"`` is hardcoded for CLI sessions;
      it can never be overridden by user input.
    """

    def __init__(
        self,
        workspace_dir: Path = DEFAULT_WORKSPACE,
        config_path: Path = DEFAULT_CONFIG_PATH,
        provider: Optional[LLMProvider] = None,
    ) -> None:
        self._workspace_dir = workspace_dir
        self._config_path = config_path
        self._injected_provider = provider

        # Populated by open()
        self._runtime: Optional[AgentRuntime] = None
        self._session: Optional[Session] = None
        self._audit_log: Optional[AuditLog] = None

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    async def open(self) -> None:
        """Build all components and initialise the session.

        Creates the workspace subdirectories if they do not exist.  Must be
        called before ``send()``.

        Security notes:
        - Storage directories are created with default OS permissions.  The
          workspace root itself should be created by ``init_workspace`` with
          restricted permissions (``0o700``).
        - The provider is built from environment variables, not the config
          file, so API keys are never written to disk.
        """
        sessions_dir = self._workspace_dir / "sessions"
        memory_dir = self._workspace_dir / "memory"
        audit_dir = self._workspace_dir / "audit"
        audit_path = audit_dir / "audit.jsonl"

        for d in (sessions_dir, memory_dir, audit_dir):
            d.mkdir(parents=True, exist_ok=True)

        transcript_store = TranscriptStore(sessions_dir)
        memory_store = MemoryStore(memory_dir)
        audit_log = AuditLog(audit_path)
        registry = ToolRegistry()
        executor = ToolExecutor(registry, audit_log)

        provider = self._injected_provider or _build_provider_from_env()

        config = load_config(self._config_path)
        agent_config = _get_agent_config(config)

        self._runtime = AgentRuntime(
            config=agent_config,
            provider=provider,
            tool_executor=executor,
            transcript_store=transcript_store,
            memory_store=memory_store,
            audit_log=audit_log,
        )
        self._session = await self._runtime.initialize_session(CLI_SESSION_KEY)
        self._audit_log = audit_log

    # ------------------------------------------------------------------
    # Message processing
    # ------------------------------------------------------------------

    async def send(self, text: str) -> str:
        """Process one user turn and return the assistant's response text.

        Args:
            text: The user's input string.

        Returns:
            The assistant's response as a plain string.  Returns an
            ``[Error: ...]`` string if the runtime returns an error message
            so the caller always receives something printable.

        Raises:
            RuntimeError: If ``open()`` has not been called.

        Security notes:
        - ``trust_level`` is always ``"main"`` for CLI input.
        - The ``from_agent`` is ``"channel:cli"`` so audit logs identify
          the origin correctly.
        """
        if self._runtime is None or self._session is None:
            raise RuntimeError("CLIChat.open() must be called before send()")

        user_msg = create_message(
            from_agent="channel:cli",
            to_agent=CLI_SESSION_KEY,
            session_key=CLI_SESSION_KEY,
            type="request",
            operation="user_message",
            trust_level="main",
            params={"content": text},
        )
        response = await self._runtime.process_message(self._session, user_msg)

        if response.type == "response":
            return str(response.params.get("content", ""))
        # Error response — return a readable string rather than raising
        error = response.error or {}
        return f"[Error: {error.get('message', 'unknown error')}]"

    # ------------------------------------------------------------------
    # Interactive loop
    # ------------------------------------------------------------------

    async def start(self) -> None:
        """Run the full interactive chat loop.

        Initialises all components via ``open()``, then loops reading lines
        from stdin until the user types ``/quit`` or presses Ctrl+C / Ctrl+D.
        """
        await self.open()
        print("OpenRattler CLI — type /help for commands, /quit to exit.\n")

        while True:
            try:
                text = input("You: ").strip()
            except (EOFError, KeyboardInterrupt):
                print("\nGoodbye!")
                break

            if not text:
                continue

            if text.startswith("/"):
                if await self._handle_command(text) == "quit":
                    break
                continue

            response = await self.send(text)
            print(f"Assistant: {response}\n")

    # ------------------------------------------------------------------
    # Slash-command handler
    # ------------------------------------------------------------------

    async def _handle_command(self, cmd: str) -> str:
        """Process a slash command.  Returns ``"quit"`` to exit, ``""`` to continue."""
        parts = cmd.split()
        name = parts[0].lower()

        if name in ("/quit", "/exit"):
            print("Goodbye!")
            return "quit"

        if name == "/help":
            print(_HELP_TEXT)

        elif name == "/session":
            print(f"Session: {CLI_SESSION_KEY}")

        elif name == "/history":
            n = int(parts[1]) if len(parts) > 1 else 10
            if self._session:
                msgs = self._session.history[-n:]
                for msg in msgs:
                    role = "You" if msg.type == "request" else "Assistant"
                    content = msg.params.get("content", "")
                    print(f"{role}: {content}")
            else:
                print("(no session)")

        elif name == "/audit":
            n = int(parts[1]) if len(parts) > 1 else 5
            if self._audit_log:
                events = await self._audit_log.query(limit=n)
                for ev in events:
                    print(f"[{ev.timestamp.isoformat()}] {ev.event} — {ev.agent_id}")
            else:
                print("(no audit log)")

        else:
            print(f"Unknown command: {name!r}  (type /help for commands)")

        return ""
