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

import logging
import os
import sys
from pathlib import Path
from typing import Optional

from openrattler.agents.creator import AgentCreator
from openrattler.agents.providers.base import LLMProvider
from openrattler.agents.providers.anthropic_provider import AnthropicProvider
from openrattler.agents.providers.openai_provider import OpenAIProvider
from openrattler.agents.runtime import AgentRuntime
from openrattler.channels.cli_adapter import CLIAdapter
from openrattler.config.loader import DEFAULT_CONFIG_PATH, AppConfig, load_config
from openrattler.identity.loader import IdentityLoader, populate_identity_dir
from openrattler.mcp.bridge import MCPToolBridge
from openrattler.mcp.manager import MCPManager
from openrattler.models.agents import AgentConfig, AgentSpawnLimits, TrustLevel
from openrattler.models.sessions import Session
from openrattler.security.memory_security import MemorySecurityAgent
from openrattler.storage.audit import AuditLog
from openrattler.storage.memory import MemoryStore
from openrattler.storage.session_lifecycle import SessionLifecycleStore
from openrattler.storage.transcripts import TranscriptStore
from openrattler.tools.builtin.memory_tools import NarrativeMemoryTools
from openrattler.tools.builtin.research_tools import ResearchTools
from openrattler.tools.executor import ToolExecutor
from openrattler.tools.registry import ToolRegistry

logger = logging.getLogger(__name__)

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
  /shutdown          — ask Corvus to update memory then exit
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
        self._mcp_manager: Optional[MCPManager] = None
        self._adapter: CLIAdapter = CLIAdapter()
        self._lifecycle_store: Optional[SessionLifecycleStore] = None

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
        usage_dir = self._workspace_dir / "usage"
        identity_dir = self._workspace_dir / "identity"
        audit_path = audit_dir / "audit.jsonl"

        for d in (sessions_dir, memory_dir, audit_dir, usage_dir, identity_dir):
            d.mkdir(parents=True, exist_ok=True)

        # Ensure template and runtime identity files exist (idempotent).
        populate_identity_dir(identity_dir)

        transcript_store = TranscriptStore(sessions_dir)
        memory_store = MemoryStore(memory_dir)
        audit_log = AuditLog(audit_path)
        registry = ToolRegistry()

        config = load_config(self._config_path)
        agent_config = _get_agent_config(config)

        # Resolve trust-level tool defaults into allowed_tools so permission
        # checks match what the full server would grant the assistant.
        from openrattler.startup import _resolve_agent_tools

        agent_config = _resolve_agent_tools(agent_config, config.tools)

        # --- File and session tools ----------------------------------------
        # Registered explicitly so they are in the registry regardless of import
        # order (the @tool decorator runs at import time, but Python's module cache
        # means it may have already run before configure_default_registry was called).
        # configure_allowed_directories locks file_* to the workspace only;
        # configure_transcript_store wires sessions_history to the live store.
        from openrattler.tools.builtin.file_ops import (
            configure_allowed_directories,
            file_list,
            file_read,
            file_write,
        )
        from openrattler.tools.builtin.session_tools import (
            configure_transcript_store,
            sessions_history,
        )

        configure_allowed_directories([self._workspace_dir])
        configure_transcript_store(transcript_store)
        for _fn in (file_read, file_write, file_list, sessions_history):
            registry.register(_fn._tool_definition, _fn)  # type: ignore[union-attr]

        # --- MCP framework setup -------------------------------------------
        mcp_security = config.mcp.security
        mcp_manager = MCPManager(
            security_config=mcp_security,
            tool_registry=registry,
            audit=audit_log,
        )
        bundled_dir = Path(__file__).parent.parent / "mcp" / "manifests"
        if bundled_dir.is_dir():
            try:
                await mcp_manager.load_manifests_from_directory(bundled_dir)
                await mcp_manager.connect_all_bundled()
            except Exception:
                logger.warning(
                    "MCP bundled server startup failed; continuing without MCP", exc_info=True
                )
        mcp_bridge = MCPToolBridge(
            mcp_manager=mcp_manager,
            security_config=mcp_security,
            audit=audit_log,
        )
        self._mcp_manager = mcp_manager

        # --- Narrative memory tools ----------------------------------------
        # MemorySecurityAgent is required by NarrativeMemoryTools to review
        # writes before they touch disk.
        mem_security_agent = MemorySecurityAgent(
            ["command_injection", "instruction_override", "exfiltration"],
            audit_log,
        )
        NarrativeMemoryTools(
            identity_dir=identity_dir,
            memory_config=config.memory,
            security_agent=mem_security_agent,
            audit=audit_log,
            memory_store=memory_store,
            on_security_alert=None,  # CLI mode: no channel adapters to dispatch alerts
        ).register_all(registry)

        # --- AgentCreator + ResearchTools ----------------------------------
        # Provider is built first so it can be forwarded to AgentCreator for
        # real LLM synthesis inside ResearchAgent.
        provider = self._injected_provider or _build_provider_from_env()

        agent_registry: dict[str, AgentConfig] = {agent_config.agent_id: agent_config}
        creator = AgentCreator(
            config=agent_config,
            spawn_limits=AgentSpawnLimits(),
            agent_registry=agent_registry,
            audit_log=audit_log,
            tool_registry=registry,
            provider=provider,  # Forwarded to ResearchAgent for real LLM synthesis
        )
        ResearchTools(creator=creator, audit=audit_log).register_all(registry)

        # --- Google Workspace tools ----------------------------------------
        # Registered only when config.google.enabled is True.
        # Mirrors the same block in startup.build_application() (step 10e) so the
        # CLI path exposes exactly the same tool set as the full server.
        if config.google.enabled:
            from openrattler.integrations.google.auth import GoogleAuthManager
            from openrattler.integrations.google.client import GoogleClientFactory
            from openrattler.integrations.google.sanitizer import GoogleContentSanitizer
            from openrattler.tools.builtin.calendar_tools import (
                CalendarToolHandler,
                register_calendar_tools,
            )
            from openrattler.tools.builtin.drive_tools import (
                DriveToolHandler,
                register_drive_tools,
            )
            from openrattler.tools.builtin.gmail_tools import (
                GmailToolHandler,
                register_gmail_tools,
            )
            from openrattler.tools.builtin.tasks_tools import (
                TasksToolHandler,
                register_tasks_tools,
            )

            google_auth_manager = GoogleAuthManager(config.google)
            google_client_factory = GoogleClientFactory(google_auth_manager)
            google_sanitizer = GoogleContentSanitizer(config=config.google, audit=audit_log)
            calendar_handler = CalendarToolHandler(
                client=google_client_factory,
                config=config.google,
                audit=audit_log,
            )
            register_calendar_tools(registry, calendar_handler)
            drive_handler = DriveToolHandler(
                client=google_client_factory,
                sanitizer=google_sanitizer,
                config=config.google,
                audit=audit_log,
            )
            register_drive_tools(registry, drive_handler)
            gmail_handler = GmailToolHandler(
                client=google_client_factory,
                sanitizer=google_sanitizer,
                config=config.google,
                audit=audit_log,
            )
            register_gmail_tools(registry, gmail_handler)
            tasks_handler = TasksToolHandler(
                client=google_client_factory,
                sanitizer=google_sanitizer,
                config=config.google,
                audit=audit_log,
            )
            register_tasks_tools(registry, tasks_handler)
            logger.info(
                "Google Workspace integration enabled; "
                "Calendar, Drive, Gmail, and Tasks tools registered."
            )

        # --- UsageStore + SessionLifecycleStore ----------------------------
        from openrattler.storage.usage import UsageStore

        usage_store = UsageStore(usage_dir / "usage_log.jsonl")
        self._lifecycle_store = SessionLifecycleStore(usage_dir / "session_lifecycle.jsonl")

        # --- Runtime -------------------------------------------------------
        executor = ToolExecutor(registry, audit_log, mcp_bridge=mcp_bridge)

        self._runtime = AgentRuntime(
            config=agent_config,
            provider=provider,
            tool_executor=executor,
            transcript_store=transcript_store,
            memory_store=memory_store,
            audit_log=audit_log,
            identity_loader=IdentityLoader(
                identity_dir=identity_dir,
                agent_config=agent_config,
                tool_registry=registry,
                config=config,
            ),
            usage_store=usage_store,
        )
        self._session = await self._runtime.initialize_session(CLI_SESSION_KEY)
        self._audit_log = audit_log

    async def close(self) -> None:
        """Disconnect all MCP servers and clean up resources.

        Safe to call even if ``open()`` was never called.
        """
        if self._mcp_manager is not None:
            await self._mcp_manager.disconnect_all()

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

        user_msg = self._adapter.text_to_message(text)
        response = await self._runtime.process_message(self._session, user_msg)
        return self._adapter._format_response(response)

    # ------------------------------------------------------------------
    # Interactive loop
    # ------------------------------------------------------------------

    async def start(self) -> None:
        """Run the full interactive chat loop.

        Initialises all components via ``open()``, then loops reading lines
        from stdin (via CLIAdapter) until the user types ``/quit`` or presses
        Ctrl+C / Ctrl+D.
        """
        # Ensure stdout uses UTF-8 on Windows (default is cp1252 which cannot
        # encode many Unicode characters including emoji).
        if hasattr(sys.stdout, "reconfigure"):
            sys.stdout.reconfigure(encoding="utf-8", errors="replace")

        await self.open()
        assert self._runtime is not None
        assert self._session is not None
        await self._adapter.connect()
        print("OpenRattler CLI — type /help for commands, /quit to exit.\n")

        # Emit lifecycle open event for the interactive CLI session.
        if self._lifecycle_store is not None:
            try:
                await self._lifecycle_store.emit_open(CLI_SESSION_KEY, "interactive")
            except Exception as lc_exc:
                logger.warning("CLIChat: lifecycle open event failed: %s", lc_exc)

        try:
            while True:
                try:
                    msg = await self._adapter.receive()
                except (EOFError, KeyboardInterrupt):
                    print("\nGoodbye!")
                    break

                text = msg.params.get("content", "").strip()
                if not text:
                    continue

                if text.startswith("/"):
                    if await self._handle_command(text) == "quit":
                        break
                    continue

                response = await self._runtime.process_message(self._session, msg)
                await self._adapter.send(response)
        finally:
            # Emit lifecycle close event before disconnecting.
            if self._lifecycle_store is not None:
                try:
                    await self._lifecycle_store.emit_close(CLI_SESSION_KEY, "disconnect")
                except Exception as lc_exc:
                    logger.warning("CLIChat: lifecycle close event failed: %s", lc_exc)
            await self._adapter.disconnect()
            await self.close()

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

        if name == "/shutdown":
            print("Asking Corvus to update memory before shutdown...")
            if self._runtime and self._session:
                shutdown_msg = self._adapter.text_to_message(
                    "This session is ending. Please update your memory (MEMORY.md) and"
                    " heartbeat with any important notes from our conversation, then"
                    " confirm you are ready to close."
                )
                response = await self._runtime.process_message(self._session, shutdown_msg)
                print(f"\n{self._adapter._format_response(response)}\n")
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
