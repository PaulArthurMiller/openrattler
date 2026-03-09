"""Application factory — wires all OpenRattler components for production use.

``build_application`` constructs every component in the correct order and returns
an ``ApplicationContext`` that owns the full system.  The context's
``run_until_interrupted()`` method is the production entry point.

COMPONENT WIRING ORDER
----------------------
1.  Load config
2.  Create workspace subdirectories
3.  AuditLog
4.  TranscriptStore + MemoryStore
5.  MemorySecurityAgent
6.  SocialStore (with security agent)
7.  ToolRegistry + configure_default_registry
8.  MCPManager — load manifests + connect bundled servers
9.  MCPToolBridge + ToolExecutor
10. SocialTools registered into registry
11. LLM provider (injectable or from env)
12. AgentRuntime
13. Social Secretary processor + scheduler (if enabled)
14. Gateway + TokenAuth (if enabled)
15. Channel adapters (enabled ones only)

SECURITY NOTES
--------------
- The WS secret is read from ``OPENRATTLER_WS_SECRET``.  If not set, a
  development default is used and a warning is emitted.
- Channel adapters are built lazily and never started if disabled in config.
- MCP connection failures are non-fatal: the application continues without
  MCP tools rather than aborting startup.
"""

from __future__ import annotations

import asyncio
import logging
import os
import signal
from pathlib import Path
from typing import Optional

from openrattler.agents.providers.anthropic_provider import AnthropicProvider
from openrattler.agents.providers.base import LLMProvider
from openrattler.agents.providers.openai_provider import OpenAIProvider
from openrattler.agents.runtime import AgentRuntime
from openrattler.channels.base import ChannelAdapter
from openrattler.config.loader import DEFAULT_CONFIG_PATH, AppConfig, ChannelConfig, load_config
from openrattler.gateway.auth import TokenAuth
from openrattler.gateway.scheduler import ProcessorScheduler
from openrattler.gateway.server import Gateway
from openrattler.mcp.bridge import MCPToolBridge
from openrattler.mcp.manager import MCPManager
from openrattler.models.agents import AgentConfig, TrustLevel
from openrattler.models.audit import AuditEvent
from openrattler.models.messages import UniversalMessage
from openrattler.models.sessions import Session
from openrattler.processors.social_secretary import SocialSecretaryProcessor
from openrattler.security.memory_security import MemorySecurityAgent
from openrattler.storage.audit import AuditLog
from openrattler.storage.memory import MemoryStore
from openrattler.storage.social import SocialStore
from openrattler.storage.transcripts import TranscriptStore
from openrattler.tools.executor import ToolExecutor
from openrattler.tools.registry import ToolRegistry, configure_default_registry
from openrattler.tools.social_tools import SocialTools

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

#: Default workspace directory (same as CLIChat uses).
DEFAULT_WORKSPACE: Path = Path.home() / ".openrattler"

#: Session key for the main runtime session.
_MAIN_SESSION_KEY: str = "agent:main:main"

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

#: Development fallback WS secret — triggers a warning if used.
_DEV_WS_SECRET = "dev-secret-changeme"


# ---------------------------------------------------------------------------
# Helper functions
# ---------------------------------------------------------------------------


def build_provider_from_env() -> LLMProvider:
    """Build an LLM provider from environment variables.

    Checks ``ANTHROPIC_API_KEY`` first, then ``OPENAI_API_KEY``.

    Raises:
        RuntimeError: If neither key is set.

    Security notes:
    - Keys are read from environment variables, never from disk.
    """
    anthropic_key = os.environ.get("ANTHROPIC_API_KEY")
    if anthropic_key:
        return AnthropicProvider(api_key=anthropic_key)

    openai_key = os.environ.get("OPENAI_API_KEY")
    if openai_key:
        return OpenAIProvider(api_key=openai_key)

    raise RuntimeError(
        "No LLM API key found. "
        "Set ANTHROPIC_API_KEY or OPENAI_API_KEY before running 'openrattler run'."
    )


def _build_channel_adapters(
    config: AppConfig,
    audit: AuditLog,
) -> list[ChannelAdapter]:
    """Build enabled channel adapters from ``config.channels``.

    Unknown channel names are logged and skipped.  Disabled channels are
    also skipped.

    Args:
        config: Application configuration.
        audit:  Audit log instance passed to each adapter.

    Returns:
        List of constructed ``ChannelAdapter`` instances (may be empty).
    """
    from openrattler.channels.email_adapter import EmailAdapter
    from openrattler.channels.slack_adapter import SlackAdapter
    from openrattler.channels.sms_adapter import SMSAdapter

    _FACTORY: dict[str, type[ChannelAdapter]] = {
        "slack": SlackAdapter,
        "email": EmailAdapter,
        "sms": SMSAdapter,
    }

    adapters: list[ChannelAdapter] = []
    for name, cfg in config.channels.items():
        if not cfg.enabled:
            continue
        factory = _FACTORY.get(name)
        if factory is None:
            logger.warning("Unknown channel %r — skipping", name)
            continue
        adapters.append(factory(cfg, audit=audit))  # type: ignore[call-arg]

    return adapters


# ---------------------------------------------------------------------------
# ApplicationContext
# ---------------------------------------------------------------------------


class ApplicationContext:
    """Holds all wired components for a running OpenRattler instance.

    Created exclusively by ``build_application``.  Callers should use
    ``run_until_interrupted()`` for the standard production lifecycle.

    Args:
        config:           Validated application configuration.
        audit:            Shared audit log.
        runtime:          Wired agent runtime.
        mcp_manager:      MCP connection registry.
        adapters:         List of active channel adapters.
        scheduler:        Optional processor scheduler (Social Secretary).
        gateway:          Optional WebSocket gateway.
        social_processor: Optional Social Secretary processor.
    """

    def __init__(
        self,
        config: AppConfig,
        audit: AuditLog,
        runtime: AgentRuntime,
        mcp_manager: MCPManager,
        adapters: list[ChannelAdapter],
        scheduler: Optional[ProcessorScheduler] = None,
        gateway: Optional[Gateway] = None,
        social_processor: Optional[SocialSecretaryProcessor] = None,
    ) -> None:
        self._config = config
        self._audit = audit
        self._runtime = runtime
        self._mcp_manager = mcp_manager
        self._adapters = adapters
        self._scheduler = scheduler
        self._gateway = gateway
        self._social_processor = social_processor

        # Session cache — keyed by session_key string.
        self._sessions: dict[str, Session] = {}
        # asyncio tasks for channel adapter loops.
        self._channel_tasks: list[asyncio.Task[None]] = []

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    async def start(self) -> None:
        """Start all components and kick off channel adapter tasks.

        Order:
        1. Social Secretary processor connect (validates MCP links).
        2. ProcessorScheduler start.
        3. Gateway — wire runtime then start TCP listener.
        4. Channel adapter asyncio tasks.
        5. Audit ``application_started``.
        """
        if self._social_processor is not None:
            await self._social_processor.connect()

        if self._scheduler is not None:
            await self._scheduler.start()

        if self._gateway is not None:
            main_session = await self._get_or_create_session(_MAIN_SESSION_KEY)
            self._gateway.set_runtime(self._runtime, main_session)
            await self._gateway.start()

        for adapter in self._adapters:
            task = asyncio.create_task(self._channel_loop(adapter))
            self._channel_tasks.append(task)

        await self._audit.log(
            AuditEvent(
                event="application_started",
                agent_id="startup",
                details={"adapters": len(self._adapters), "gateway": self._gateway is not None},
            )
        )

    async def stop(self) -> None:
        """Stop all components in reverse start order.

        Safe to call even if ``start()`` was never called.
        """
        # Cancel channel tasks.
        for task in self._channel_tasks:
            task.cancel()
        if self._channel_tasks:
            await asyncio.gather(*self._channel_tasks, return_exceptions=True)
        self._channel_tasks.clear()

        if self._scheduler is not None:
            await self._scheduler.stop()

        if self._social_processor is not None:
            await self._social_processor.disconnect()

        if self._gateway is not None:
            await self._gateway.stop()

        await self._mcp_manager.disconnect_all()

        await self._audit.log(
            AuditEvent(
                event="application_stopped",
                agent_id="startup",
                details={},
            )
        )

    async def run_until_interrupted(self) -> None:
        """Start, block until Ctrl+C or SIGTERM, then stop cleanly."""
        await self.start()
        loop = asyncio.get_running_loop()
        stop_future: asyncio.Future[None] = loop.create_future()

        def _signal_handler() -> None:
            if not stop_future.done():
                stop_future.set_result(None)

        # SIGTERM handler — not available on Windows (NotImplementedError guard).
        try:
            loop.add_signal_handler(signal.SIGTERM, _signal_handler)
        except NotImplementedError:
            pass  # Windows — rely on KeyboardInterrupt from asyncio.run

        try:
            await stop_future
        except asyncio.CancelledError:
            pass
        finally:
            await self.stop()

    # ------------------------------------------------------------------
    # Session management
    # ------------------------------------------------------------------

    async def _get_or_create_session(self, session_key: str) -> Session:
        """Return a cached ``Session`` or initialise one via the runtime."""
        if session_key not in self._sessions:
            self._sessions[session_key] = await self._runtime.initialize_session(session_key)
        return self._sessions[session_key]

    # ------------------------------------------------------------------
    # Channel adapter loop
    # ------------------------------------------------------------------

    async def _channel_loop(self, adapter: ChannelAdapter) -> None:
        """Connect the adapter then relay messages through the runtime until cancelled."""
        try:
            await adapter.connect()
            while True:
                msg: UniversalMessage = await adapter.receive()
                session_key = msg.session_key or _MAIN_SESSION_KEY
                session = await self._get_or_create_session(session_key)
                response = await self._runtime.process_message(session, msg)
                await adapter.send(response)
        except asyncio.CancelledError:
            pass
        except Exception:
            logger.exception("Channel adapter %r crashed", adapter)
        finally:
            try:
                await adapter.disconnect()
            except Exception:
                logger.exception("Error disconnecting adapter %r", adapter)


# ---------------------------------------------------------------------------
# build_application
# ---------------------------------------------------------------------------


async def build_application(
    workspace_dir: Path = DEFAULT_WORKSPACE,
    config_path: Path = DEFAULT_CONFIG_PATH,
    *,
    provider: Optional[LLMProvider] = None,
    mcp_manifests_dir: Optional[Path] = None,
    gateway_host: str = "127.0.0.1",
    gateway_port: int = 8765,
    start_gateway: bool = True,
) -> ApplicationContext:
    """Build and wire all OpenRattler components.

    Args:
        workspace_dir:    Root workspace directory (default: ``~/.openrattler``).
        config_path:      Config file path (default: ``~/.openrattler/config.json``).
        provider:         Injected LLM provider (for tests).  If ``None``, built
                          from environment variables.
        mcp_manifests_dir: Directory to scan for MCP manifests.  ``None`` uses
                          the bundled manifests directory inside the package.
        gateway_host:     Host to bind the WebSocket Gateway on.
        gateway_port:     Port to bind the WebSocket Gateway on.
        start_gateway:    Whether to create a ``Gateway`` instance.  Set to
                          ``False`` in tests to avoid binding a real TCP port.

    Returns:
        A fully-wired ``ApplicationContext`` (not yet started).

    Security notes:
    - MCP connection failures are non-fatal; a WARNING is logged and the
      context is returned without MCP tools rather than raising.
    - The WS secret comes from ``OPENRATTLER_WS_SECRET``.  A dev default
      is used with a WARNING if the variable is not set.
    """
    # 1. Load config.
    config = load_config(config_path)

    # 2. Create workspace subdirectories.
    for subdir in ("sessions", "memory", "audit", "social"):
        (workspace_dir / subdir).mkdir(parents=True, exist_ok=True)

    # 3. AuditLog.
    audit = AuditLog(workspace_dir / "audit" / "audit.jsonl")

    # 4. TranscriptStore + MemoryStore.
    transcript_store = TranscriptStore(workspace_dir / "sessions")
    memory_store = MemoryStore(workspace_dir / "memory")

    # 5. MemorySecurityAgent.
    mem_security_agent = MemorySecurityAgent(
        ["command_injection", "instruction_override", "exfiltration"],
        audit,
    )

    # 6. SocialStore.
    social_store = SocialStore(
        workspace_dir / "social",
        security_agent=mem_security_agent,
        audit=audit,
    )

    # 7. ToolRegistry.
    registry = ToolRegistry()
    configure_default_registry(registry)

    # 8. MCPManager — load manifests + connect.
    mcp_security = config.mcp.security
    mcp_manager = MCPManager(
        security_config=mcp_security,
        tool_registry=registry,
        audit=audit,
    )
    bundled_dir = mcp_manifests_dir or (Path(__file__).parent / "mcp" / "manifests")
    if bundled_dir.is_dir():
        try:
            await mcp_manager.load_manifests_from_directory(bundled_dir)
            await mcp_manager.connect_all_bundled()
        except Exception:
            logger.warning(
                "MCP bundled server startup failed; continuing without MCP",
                exc_info=True,
            )

    # 9. MCPToolBridge + ToolExecutor.
    mcp_bridge = MCPToolBridge(
        mcp_manager=mcp_manager,
        security_config=mcp_security,
        audit=audit,
    )
    executor = ToolExecutor(registry, audit, mcp_bridge=mcp_bridge)

    # 10. SocialTools.
    SocialTools(social_store, audit).register_all(registry)

    # 11. LLM provider.
    llm_provider = provider or build_provider_from_env()

    # 12. AgentRuntime.
    agent_config = config.agents.get("main", _DEFAULT_AGENT_CONFIG)
    runtime = AgentRuntime(
        config=agent_config,
        provider=llm_provider,
        tool_executor=executor,
        transcript_store=transcript_store,
        memory_store=memory_store,
        audit_log=audit,
        social_store=social_store,
    )

    # 13. Social Secretary processor + scheduler (if enabled).
    scheduler: Optional[ProcessorScheduler] = None
    social_processor: Optional[SocialSecretaryProcessor] = None

    ss_config = config.social_secretary
    if ss_config.enabled:
        social_processor = SocialSecretaryProcessor(
            config=ss_config,
            social_store=social_store,
            mcp_manager=mcp_manager,
            provider=llm_provider,
            audit=audit,
        )
        scheduler = ProcessorScheduler(audit=audit)
        scheduler.register_processor(social_processor, ss_config.cycle_interval_minutes)

    # 14. Gateway (optional).
    gateway: Optional[Gateway] = None
    if start_gateway:
        ws_secret = os.environ.get("OPENRATTLER_WS_SECRET", _DEV_WS_SECRET)
        if ws_secret == _DEV_WS_SECRET:
            logger.warning(
                "OPENRATTLER_WS_SECRET not set — using development default. "
                "Set a strong secret before production use."
            )
        auth = TokenAuth(secret=ws_secret, expiry_seconds=3600)
        gateway = Gateway(
            host=gateway_host,
            port=gateway_port,
            config=config,
            audit_log=audit,
            auth=auth,
        )

    # 15. Channel adapters.
    adapters = _build_channel_adapters(config, audit)

    return ApplicationContext(
        config=config,
        audit=audit,
        runtime=runtime,
        mcp_manager=mcp_manager,
        adapters=adapters,
        scheduler=scheduler,
        gateway=gateway,
        social_processor=social_processor,
    )
