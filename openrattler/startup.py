"""Application factory — wires all OpenRattler components for production use.

``build_application`` constructs every component in the correct order and returns
an ``ApplicationContext`` that owns the full system.  The context's
``run_until_interrupted()`` method is the production entry point.

COMPONENT WIRING ORDER
----------------------
1.  Load config
2.  Create workspace subdirectories (including identity/)
3.  AuditLog
4.  TranscriptStore + MemoryStore
5.  MemorySecurityAgent
6.  SocialStore (with security agent)
7.  ToolRegistry + configure_default_registry
8.  MCPManager — load manifests + connect bundled servers
9.  MCPToolBridge + ToolExecutor
10. SocialTools registered into registry
10b.NarrativeMemoryTools registered into registry (with MemoryStore + alert callback)
11. LLM provider (injectable or from env)
11b.Resolve agent config — merge trust-level tool defaults into allowed_tools
11c.IdentityLoader
12. AgentRuntime (receives IdentityLoader)
13. Scheduler + processors (heartbeat always if enabled; SS if enabled)
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
import re
import shutil
import signal
import sys
from pathlib import Path
from typing import Awaitable, Callable, Optional

from openrattler.agents.providers.anthropic_provider import AnthropicProvider
from openrattler.agents.providers.base import LLMProvider
from openrattler.agents.providers.openai_provider import OpenAIProvider
from openrattler.agents.runtime import AgentRuntime
from openrattler.channels.base import ChannelAdapter
from openrattler.config.loader import (
    DEFAULT_CONFIG_PATH,
    AppConfig,
    ChannelConfig,
    ToolsConfig,
    load_config,
)
from openrattler.identity.loader import RUNTIME_FILES, TEMPLATE_FILES, IdentityLoader
from openrattler.tools.builtin.memory_tools import NarrativeMemoryTools
from openrattler.gateway.auth import TokenAuth
from openrattler.gateway.scheduler import ProcessorScheduler
from openrattler.gateway.server import Gateway
from openrattler.mcp.bridge import MCPToolBridge
from openrattler.mcp.manager import MCPManager
from openrattler.models.agents import AgentConfig, TrustLevel
from openrattler.models.audit import AuditEvent
from openrattler.models.messages import UniversalMessage, create_message
from openrattler.models.sessions import Session
from openrattler.processors.heartbeat import HEARTBEAT_SESSION_KEY, HeartbeatProcessor
from openrattler.processors.social_secretary import SocialSecretaryProcessor
from openrattler.security.memory_security import MemorySecurityAgent
from openrattler.storage.audit import AuditLog
from openrattler.storage.memory import MemoryStore
from openrattler.storage.social import SocialStore
from openrattler.storage.transcripts import TranscriptStore
from openrattler.auth.google_oauth import GoogleCredentialManager
from openrattler.tools.builtin.channel_tools import OutboundChannelTools
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

#: Regex that matches any character NOT allowed in a sanitized tool name.
_TOOL_NAME_UNSAFE_RE: re.Pattern[str] = re.compile(r"[^a-zA-Z0-9_.]")

#: Maximum length for a sanitized tool name included in alert messages.
_TOOL_NAME_MAX_LEN: int = 64


# ---------------------------------------------------------------------------
# Helper functions
# ---------------------------------------------------------------------------


def _build_alert_adapters_list(adapters: dict[str, ChannelAdapter]) -> list[ChannelAdapter]:
    """Return adapters that are connected and have ``send()`` available.

    Iterates *adapters* and includes each adapter whose ``_connected``
    attribute is ``True`` and whose ``send`` attribute is callable.
    Skipped adapters are logged at DEBUG level.

    Args:
        adapters: Mapping of adapter name → ``ChannelAdapter`` instance.

    Returns:
        Filtered list of eligible adapters for alert dispatch.
    """
    result: list[ChannelAdapter] = []
    for name, adapter in adapters.items():
        connected: bool = getattr(adapter, "_connected", False)
        has_send: bool = callable(getattr(adapter, "send", None))
        if connected and has_send:
            result.append(adapter)
        else:
            logger.debug(
                "_build_alert_adapters_list: skipping adapter %r (connected=%s, has_send=%s)",
                name,
                connected,
                has_send,
            )
    return result


async def _dispatch_to_channels(
    message: UniversalMessage,
    adapters: list[ChannelAdapter],
    audit: AuditLog,
) -> bool:
    """Dispatch *message* to all *adapters* concurrently.

    Uses ``asyncio.gather`` with ``return_exceptions=True`` so a failure
    in one adapter never blocks the others.  Each per-adapter failure is
    audit-logged as ``alert_dispatch_failed``.  When every adapter fails,
    an additional ``alert_dispatch_total_failure`` event is written and
    ``False`` is returned so the caller can activate its print fallback.

    Args:
        message:  The alert message to deliver.
        adapters: Pre-filtered list of connected adapters.
        audit:    Shared audit log for failure recording.

    Returns:
        ``True`` if at least one adapter succeeded, ``False`` if all failed
        or *adapters* is empty.
    """
    if not adapters:
        return False

    results = await asyncio.gather(
        *[adapter.send(message) for adapter in adapters],
        return_exceptions=True,
    )

    failure_count = 0
    for adapter, result in zip(adapters, results):
        if isinstance(result, BaseException):
            failure_count += 1
            await audit.log(
                AuditEvent(
                    event="alert_dispatch_failed",
                    agent_id="startup",
                    details={
                        "adapter_name": adapter.channel_name,
                        "error": str(result),
                    },
                )
            )

    if failure_count == len(adapters):
        await audit.log(
            AuditEvent(
                event="alert_dispatch_total_failure",
                agent_id="startup",
                details={"adapter_count": len(adapters)},
            )
        )
        return False

    return True


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


def _populate_identity_dir(identity_dir: Path) -> None:
    """Ensure the runtime identity directory contains the expected files.

    - Template files (SOUL.md, IDENTITY.md, BOOTSTRAP.md, HEARTBEAT.md) are
      copied from the package templates directory if they do not yet exist in
      ``identity_dir``.  Existing user-customised copies are never overwritten.
    - Runtime files (USER.md, MEMORY.md) are created as empty files if absent.
      They are never overwritten or populated from a template.
    - ``.init_date`` is written once on first population with the current UTC
      date.  It is never overwritten on subsequent starts.

    Security notes:
    - USER.md is never created with content here — it is always populated
      through the ``update_user_profile`` tool (which runs the security review
      gate) after the bootstrap flow.
    - Existing identity files are never overwritten — user customisations are
      preserved across restarts.
    """
    from datetime import datetime, timezone

    from openrattler.identity.loader import _TEMPLATES_DIR

    for filename in TEMPLATE_FILES:
        dest = identity_dir / filename
        if not dest.exists():
            src = _TEMPLATES_DIR / filename
            if src.exists():
                shutil.copy(src, dest)
            else:
                logger.warning("_populate_identity_dir: template %s not found", src)

    for filename in RUNTIME_FILES:
        runtime_path = identity_dir / filename
        if not runtime_path.exists():
            runtime_path.write_text("", encoding="utf-8")

    init_date_path = identity_dir / ".init_date"
    if not init_date_path.exists():
        init_date_path.write_text(datetime.now(timezone.utc).strftime("%Y-%m-%d"), encoding="utf-8")


# ---------------------------------------------------------------------------
# ApplicationContext
# ---------------------------------------------------------------------------


class ApplicationContext:
    """Holds all wired components for a running OpenRattler instance.

    Created exclusively by ``build_application``.  Callers should use
    ``run_until_interrupted()`` for the standard production lifecycle.

    Args:
        config:               Validated application configuration.
        audit:                Shared audit log.
        runtime:              Wired agent runtime.
        mcp_manager:          MCP connection registry.
        adapters:             List of active channel adapters.
        scheduler:            Optional processor scheduler (Social Secretary).
        gateway:              Optional WebSocket gateway.
        social_processor:     Optional Social Secretary processor.
        alert_adapters_ref:   Shared mutable list populated by ``start()`` with
                              connected adapters eligible for alert dispatch.
                              The same list object is closed over by the alert
                              callbacks so they always see the current contents.
        on_security_alert:    The ``_on_security_alert`` closure from
                              ``build_application``, stored here so tests can
                              invoke it directly via ``ctx._security_alert_cb``.
        google_credentials:   Optional ``GoogleCredentialManager`` instance.
                              ``None`` if ``client_secrets.json`` is absent or
                              Google tools are not configured.
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
        alert_adapters_ref: Optional[list[ChannelAdapter]] = None,
        on_security_alert: Optional[Callable[[str, str], Awaitable[None]]] = None,
        google_credentials: Optional[GoogleCredentialManager] = None,
    ) -> None:
        self._config = config
        self._audit = audit
        self._runtime = runtime
        self._mcp_manager = mcp_manager
        self._adapters = adapters
        self._scheduler = scheduler
        self._gateway = gateway
        self._social_processor = social_processor
        #: Shared Google credential manager — None if client_secrets.json is absent.
        self.google_credentials: Optional[GoogleCredentialManager] = google_credentials

        # Shared mutable list for alert dispatch — populated in start().
        # The same object is closed over by the urgent/security alert callbacks.
        self._alert_adapters: list[ChannelAdapter] = (
            alert_adapters_ref if alert_adapters_ref is not None else []
        )
        # Security alert callback exposed for test access.
        self._security_alert_cb: Optional[Callable[[str, str], Awaitable[None]]] = on_security_alert

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
        5. Build alert adapters list (captured once; callbacks close over it).
        6. Audit ``application_started``.
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

        # Populate the shared alert adapters list once at startup.
        # The callbacks close over the same list object, so they always see
        # the contents set here without re-evaluating on every alert.
        alert_dict = {a.channel_name: a for a in self._adapters}
        built = _build_alert_adapters_list(alert_dict)
        self._alert_adapters.clear()
        self._alert_adapters.extend(built)

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
# _resolve_agent_tools
# ---------------------------------------------------------------------------


def _resolve_agent_tools(agent_config: AgentConfig, tools_config: ToolsConfig) -> AgentConfig:
    """Return a copy of *agent_config* with trust-level tool defaults merged in.

    Looks up the trust-level defaults from *tools_config* for the agent's
    trust level, then unions them with the agent's explicit ``allowed_tools``
    list.  The defaults come first so they establish a baseline; per-agent
    entries follow, allowing extensions without repetition.  Duplicate names
    are silently deduplicated (first occurrence wins).

    Args:
        agent_config:  The agent configuration to augment.
        tools_config:  The tools configuration containing ``trust_defaults``.

    Returns:
        A new ``AgentConfig`` with the resolved ``allowed_tools`` list.

    Security notes:
    - This helper only adds tools; it never removes entries from the agent's
      explicit ``allowed_tools`` list.
    - The resulting list is still subject to the full permission check
      (allowlist + trust-level) at call time — adding a tool name here does
      not bypass ``check_permission``.
    """
    trust_key = agent_config.trust_level.value
    defaults = tools_config.trust_defaults.get(trust_key, [])
    seen: set[str] = set()
    merged: list[str] = []
    for tool_name in list(defaults) + list(agent_config.allowed_tools):
        if tool_name not in seen:
            seen.add(tool_name)
            merged.append(tool_name)
    return agent_config.model_copy(update={"allowed_tools": merged})


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

    # 2. Create workspace subdirectories (including identity/).
    for subdir in ("sessions", "memory", "audit", "social", "identity"):
        (workspace_dir / subdir).mkdir(parents=True, exist_ok=True)

    # 2b. Populate identity directory.
    #     Copy any missing template files from the package so the user has
    #     editable local copies.  Runtime files (USER.md, MEMORY.md) are
    #     created as empty files if absent — never overwritten if they exist.
    identity_dir = workspace_dir / "identity"
    _populate_identity_dir(identity_dir)

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

    # 10b. NarrativeMemoryTools — with MemoryStore and out-of-band security alert.
    # Shared mutable list — populated by ApplicationContext.start().
    # The closures below close over this object; start() modifies it in-place so
    # the callbacks always see the current connected adapter set without
    # re-evaluating on every alert.
    _shared_alert_adapters: list[ChannelAdapter] = []

    async def _on_security_alert(tool_name: str, reason: str) -> None:
        # Sanitize tool_name before including in the alert message to prevent
        # a crafted tool name from injecting content.
        safe_name = _TOOL_NAME_UNSAFE_RE.sub("", tool_name)[:_TOOL_NAME_MAX_LEN]
        alert_msg = create_message(
            from_agent="startup",
            to_agent="broadcast",
            session_key="system",
            type="alert",
            operation="security_alert",
            trust_level="security",
            params={"tool_name": safe_name, "reason": reason, "severity": "high"},
        )
        dispatched = (
            await _dispatch_to_channels(alert_msg, _shared_alert_adapters, audit)
            if _shared_alert_adapters
            else False
        )
        if not dispatched:
            # Fallback: print to stderr so the alert is never silently lost.
            print(
                f"\n[SECURITY ALERT] Write to {tool_name} was blocked by the memory "
                f"security agent.\nReason: {reason}\n",
                file=sys.stderr,
                flush=True,
            )
        logger.warning(
            "SECURITY ALERT: write to %s was blocked by the memory security agent. Reason: %s",
            tool_name,
            reason,
        )

    NarrativeMemoryTools(
        identity_dir=identity_dir,
        memory_config=config.memory,
        security_agent=mem_security_agent,
        audit=audit,
        memory_store=memory_store,
        on_security_alert=_on_security_alert,
    ).register_all(registry)

    # 11. LLM provider.
    llm_provider = provider or build_provider_from_env()

    # 11b. Resolve agent config — merge trust-level tool defaults into allowed_tools.
    raw_agent_config = config.agents.get("main", _DEFAULT_AGENT_CONFIG)
    agent_config = _resolve_agent_tools(raw_agent_config, config.tools)

    # 11c. IdentityLoader.
    identity_loader = IdentityLoader(
        identity_dir=identity_dir,
        agent_config=agent_config,
        tool_registry=registry,
        config=config,
    )

    # 12. AgentRuntime.
    runtime = AgentRuntime(
        config=agent_config,
        provider=llm_provider,
        tool_executor=executor,
        transcript_store=transcript_store,
        memory_store=memory_store,
        audit_log=audit,
        social_store=social_store,
        identity_loader=identity_loader,
    )

    # 13. Scheduler + processors.
    #     The scheduler is created whenever at least one processor is enabled.
    #     Heartbeat is on by default; Social Secretary requires explicit config.
    scheduler: Optional[ProcessorScheduler] = None
    social_processor: Optional[SocialSecretaryProcessor] = None

    heartbeat_cfg = config.heartbeat
    ss_config = config.social_secretary

    if heartbeat_cfg.enabled or ss_config.enabled:

        async def _on_urgent_alert(msg: UniversalMessage) -> None:
            dispatched = (
                await _dispatch_to_channels(msg, _shared_alert_adapters, audit)
                if _shared_alert_adapters
                else False
            )
            if not dispatched:
                # Fallback: original stdout print so the alert is never silently lost.
                operation = msg.operation
                params = msg.params
                if operation == "heartbeat_response":
                    content = params.get("content", params.get("summary", ""))
                    if content:
                        print(f"\n[HEARTBEAT] {content}\n", flush=True)
                else:
                    summary = params.get("summary", "")
                    person = params.get("person", "")
                    label = f"{person}: " if person else ""
                    print(f"\n[ALERT] {label}{summary}\n", flush=True)
            logger.info("Urgent alert dispatched: operation=%s", msg.operation)

        scheduler = ProcessorScheduler(audit=audit, on_urgent_alert=_on_urgent_alert)

        if heartbeat_cfg.enabled:
            heartbeat_processor = HeartbeatProcessor(
                runtime=runtime,
                identity_loader=identity_loader,
                session_key=HEARTBEAT_SESSION_KEY,
                audit=audit,
            )
            scheduler.register_processor(heartbeat_processor, heartbeat_cfg.interval_minutes)

        if ss_config.enabled:
            social_processor = SocialSecretaryProcessor(
                config=ss_config,
                social_store=social_store,
                mcp_manager=mcp_manager,
                provider=llm_provider,
                audit=audit,
            )
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

    # 10c. OutboundChannelTools — registered after channel adapters are built so
    #      register_all() can check which adapters are actually present.
    #      Tools are added to the existing registry that the runtime already holds.
    OutboundChannelTools(
        adapters={a.channel_name: a for a in adapters},
        audit=audit,
        config=config.outbound_channels,
    ).register_all(registry)

    # 10d. GoogleCredentialManager — instantiated only if client_secrets.json exists.
    #      Non-fatal if absent: Google tools will be unavailable but everything else works.
    google_credentials: Optional[GoogleCredentialManager] = None
    google_auth_cfg = config.google_auth
    creds_dir = workspace_dir / google_auth_cfg.credentials_path
    client_secrets = creds_dir / google_auth_cfg.client_secrets_file
    if client_secrets.exists():
        google_credentials = GoogleCredentialManager(
            credentials_path=creds_dir,
            scopes=google_auth_cfg.scopes,
            audit=audit,
            token_file=google_auth_cfg.token_file,
            callback_port=google_auth_cfg.oauth_callback_port,
        )
        logger.info("GoogleCredentialManager initialised (client_secrets.json found).")
    else:
        logger.info(
            "client_secrets.json not found at %s; Google tools will be unavailable.", client_secrets
        )

    return ApplicationContext(
        config=config,
        audit=audit,
        runtime=runtime,
        mcp_manager=mcp_manager,
        adapters=adapters,
        scheduler=scheduler,
        gateway=gateway,
        social_processor=social_processor,
        alert_adapters_ref=_shared_alert_adapters,
        on_security_alert=_on_security_alert,
        google_credentials=google_credentials,
    )
