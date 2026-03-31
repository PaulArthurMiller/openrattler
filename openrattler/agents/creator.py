"""Agent Creator — the security chokepoint for all subagent spawning.

``AgentCreator`` is the only component authorised to create subagents.  Every
creation request flows through the ``CreatorSecurityValidator`` before any
``AgentConfig`` is built, registered, or timed out.

CREATION FLOW
--------------
1. Security validation (authorisation + spawn limits + tool checks)
2. Template lookup
3. Model selection (custom override > template suggestion)
4. Build ``AgentConfig`` with isolated session key
5. Register in ``agent_registry``
6. Write audit log entry
7. Schedule timeout task
8. Return ``AgentConfig``

RESEARCH AGENT FLOW (create_research_agent)
--------------------------------------------
1. Validate operation == "research_query"
2. Validate trust level >= main
3. Parse UM params as ResearchRequest
4. Validate model override against APPROVED_RESEARCH_MODELS allowlist
5. Build ResearchAgentConfig
6. Write audit log entry
7. Return ResearchAgent instance (session is ephemeral — no transcript written)

DESIGN DECISIONS
-----------------
- ``agent_registry`` is a plain ``dict[str, AgentConfig]`` owned by the
  caller.  The creator mutates it in place; no separate registry class is
  needed for this build piece.
- Timeout enforcement uses ``asyncio.create_task`` to schedule a kill after
  ``max_runtime_seconds``.  Tasks are stored in ``_timeout_tasks`` so they
  can be cancelled when an agent is explicitly killed early.
- Session keys for subagents follow the pattern
  ``{parent_session_key}:sub:{uuid4_hex8}`` to keep them traceable and
  isolated.

SECURITY NOTES
--------------
- ``create_agent`` raises ``SecurityError`` if the validator rejects the
  request.  Callers must handle this exception.
- Trust level of the created agent is capped at the parent's trust level;
  it is never escalated.
- ``kill_agent`` removes the config from the registry and cancels its timeout
  so resource consumption halts immediately.
- ``create_research_agent`` validates the model override against
  ``APPROVED_RESEARCH_MODELS``; arbitrary model strings are rejected.
"""

from __future__ import annotations

import asyncio
import uuid
from typing import TYPE_CHECKING, Optional

from pydantic import ValidationError

from openrattler.agents.creator_validator import (
    AUTHORIZED_SPAWNERS,
    CreatorSecurityValidator,
    SecurityError,
    SpawnLimitError,
)
from openrattler.agents.research.config import APPROVED_RESEARCH_MODELS, ResearchAgentConfig
from openrattler.agents.research.models import ResearchRequest
from openrattler.agents.templates import TASK_TEMPLATES
from openrattler.models.agents import (
    AgentConfig,
    AgentCreationRequest,
    AgentSpawnLimits,
    TrustLevel,
)
from openrattler.models.audit import AuditEvent
from openrattler.models.messages import UniversalMessage
from openrattler.storage.audit import AuditLog
from openrattler.tools.registry import ToolRegistry

if TYPE_CHECKING:
    from openrattler.agents.research.agent import ResearchAgent

# ---------------------------------------------------------------------------
# Trust levels that may request research_query spawns (>= main)
# ---------------------------------------------------------------------------

_RESEARCH_ALLOWED_TRUST_LEVELS: frozenset[str] = frozenset({"main", "local", "security", "mcp"})

# ---------------------------------------------------------------------------
# Trust level ordering (lower index = lower privilege)
# ---------------------------------------------------------------------------

_TRUST_ORDER: list[TrustLevel] = [
    TrustLevel.public,
    TrustLevel.main,
    TrustLevel.local,
    TrustLevel.security,
    TrustLevel.mcp,
]


def _min_trust(a: TrustLevel, b: TrustLevel) -> TrustLevel:
    """Return the less-privileged of *a* and *b*."""
    ia = _TRUST_ORDER.index(a) if a in _TRUST_ORDER else 0
    ib = _TRUST_ORDER.index(b) if b in _TRUST_ORDER else 0
    return _TRUST_ORDER[min(ia, ib)]


# ---------------------------------------------------------------------------
# AgentCreator
# ---------------------------------------------------------------------------


class AgentCreator:
    """Creates, tracks, and terminates specialised subagents.

    Args:
        config:         ``AgentConfig`` describing the Creator itself.
        spawn_limits:   System-wide spawn constraints.
        agent_registry: Shared mutable dict of ``agent_id → AgentConfig``.
        audit_log:      Audit log for recording all creation / kill events.
        tool_registry:  Available tools (passed to validator for future
                        tool-task alignment checks).

    Security notes:
    - All creation flows through ``CreatorSecurityValidator``.
    - The creator itself must be registered in ``AUTHORIZED_SPAWNERS`` and
      have ``can_spawn_subagents=False`` to prevent meta-spawning.
    - Audit log entries are written for every creation, kill, and retry.
    """

    def __init__(
        self,
        config: AgentConfig,
        spawn_limits: AgentSpawnLimits,
        agent_registry: dict[str, AgentConfig],
        audit_log: AuditLog,
        tool_registry: ToolRegistry,
    ) -> None:
        self._config = config
        self._spawn_limits = spawn_limits
        self._registry = agent_registry
        self._audit_log = audit_log
        self._tool_registry = tool_registry
        self._validator = CreatorSecurityValidator(spawn_limits, agent_registry)
        # Maps agent_id → running asyncio.Task (the timeout watchdog)
        self._timeout_tasks: dict[str, asyncio.Task] = {}  # type: ignore[type-arg]

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    async def create_agent(self, request: AgentCreationRequest) -> AgentConfig:
        """Run the full creation pipeline and return the new ``AgentConfig``.

        Raises:
            SecurityError: If the validator rejects the request.
            ValueError:    If *request.template* is unknown.
        """
        # Step 1: Security validation
        approved, reason = await self._validator.validate_agent_request(request)
        if not approved:
            await self._audit_log.log(
                AuditEvent(
                    event="subagent_creation_denied",
                    agent_id=request.from_agent,
                    session_key=request.session_key,
                    details={"reason": reason, "task": request.task},
                )
            )
            raise SecurityError(f"Agent creation denied: {reason}")

        # Step 2: Template lookup
        template = TASK_TEMPLATES.get(request.template)
        if template is None:
            raise ValueError(f"Unknown task template: {request.template!r}")

        # Step 3: Model selection (custom override > template suggestion)
        model = request.custom_model or template.suggested_model

        # Step 4: Build AgentConfig with isolated session key
        subagent_id = f"agent:{request.template}:sub:{uuid.uuid4().hex[:8]}"
        # Session key inherits parent's prefix so it remains traceable
        session_key = f"{request.session_key}:sub:{uuid.uuid4().hex[:8]}"

        # Trust level is capped at the requester's current level (never escalated)
        requester_config = self._registry.get(request.from_agent)
        requester_trust = (
            requester_config.trust_level
            if isinstance(requester_config, AgentConfig)
            else TrustLevel.public
        )
        capped_trust = _min_trust(requester_trust, TrustLevel.main)

        can_spawn = request.depth < self._spawn_limits.max_depth - 1

        new_config = AgentConfig(
            agent_id=subagent_id,
            name=f"{template.name.title()} Specialist",
            description=f"{template.description}: {request.task[:100]}",
            model=model,
            model_selection="adaptive",
            fallback_models=["anthropic/claude-haiku-4-5-20251001", "openai/gpt-4o-mini"],
            allowed_tools=template.required_tools + list(request.custom_tools),
            denied_tools=[],
            trust_level=capped_trust,
            can_spawn_subagents=can_spawn,
            max_cost_per_turn=request.max_cost_per_turn or template.suggested_cost_limit,
            session_key=session_key,
            system_prompt=template.system_prompt,
            memory_files=["AGENTS.md"],
        )

        # Step 5: Register agent
        self._registry[subagent_id] = new_config

        # Step 6: Audit log
        self._validator._record_spawn()
        await self._audit_log.log(
            AuditEvent(
                event="subagent_created",
                agent_id=subagent_id,
                session_key=request.session_key,
                details={
                    "created_by": request.from_agent,
                    "template": request.template,
                    "task": request.task,
                    "tools": new_config.allowed_tools,
                    "model": model,
                    "depth": request.depth,
                    "original_user_message": request.original_user_message,
                },
            )
        )

        # Step 7: Schedule timeout
        timeout_task = asyncio.create_task(
            self._enforce_timeout(subagent_id, request.max_runtime_seconds)
        )
        self._timeout_tasks[subagent_id] = timeout_task

        return new_config

    async def kill_agent(self, agent_id: str, reason: str) -> None:
        """Terminate *agent_id*: remove from registry and cancel its timeout.

        Raises:
            ValueError: If *agent_id* is not in the registry.
        """
        if agent_id not in self._registry:
            raise ValueError(f"Agent {agent_id!r} not found in registry")

        # Cancel scheduled timeout
        task = self._timeout_tasks.pop(agent_id, None)
        if task and not task.done():
            task.cancel()

        # Remove from registry
        del self._registry[agent_id]

        await self._audit_log.log(
            AuditEvent(
                event="subagent_killed",
                agent_id=agent_id,
                session_key=None,
                details={"reason": reason},
            )
        )

    async def list_agents(self, session_key: Optional[str] = None) -> list[AgentConfig]:
        """Return all registered subagents, optionally filtered by session_key prefix.

        Args:
            session_key: If given, only return agents whose ``session_key``
                         starts with this prefix.
        """
        results: list[AgentConfig] = []
        for config in self._registry.values():
            if not isinstance(config, AgentConfig):
                continue
            # Skip the creator's own config
            if config.agent_id == self._config.agent_id:
                continue
            if session_key is None:
                results.append(config)
            elif config.session_key and config.session_key.startswith(session_key):
                results.append(config)
        return results

    async def handle_retry(self, request: AgentCreationRequest) -> AgentConfig:
        """Kill any previous attempts for this task, then create a fresh agent.

        If ``request.is_retry`` is ``False``, this is identical to
        ``create_agent``.
        """
        if request.is_retry:
            # Kill the specific previous agent if provided
            if request.previous_agent_id and request.previous_agent_id in self._registry:
                await self.kill_agent(
                    request.previous_agent_id,
                    reason="Superseded by retry",
                )
            # Kill all agents sharing the same task_id
            elif request.task_id:
                to_kill = [
                    cfg.agent_id
                    for cfg in self._registry.values()
                    if isinstance(cfg, AgentConfig)
                    and cfg.session_key
                    and cfg.session_key.startswith(request.session_key)
                    and cfg.agent_id != self._config.agent_id
                    # In a future piece we will store task_id on AgentConfig
                    # so we can filter precisely.  For now we kill all subagents
                    # in the same session as a conservative fallback.
                ]
                for agent_id in to_kill:
                    await self.kill_agent(
                        agent_id,
                        reason=f"Retry — killing previous attempt for task {request.task_id!r}",
                    )

        return await self.create_agent(request)

    # ------------------------------------------------------------------
    # Research agent creation
    # ------------------------------------------------------------------

    async def create_research_agent(
        self,
        message: UniversalMessage,
        audit: AuditLog,
    ) -> "ResearchAgent":
        """Validate a research_query UM and return a configured ResearchAgent.

        This is the authorised pathway for spawning a ResearchAgent.  It
        validates trust level, parses the params block as a ResearchRequest,
        and checks any model override against the approved allowlist before
        returning an agent instance ready to execute.

        Args:
            message: ``UniversalMessage`` with ``operation="research_query"``
                     and a ``params`` block that parses as ``ResearchRequest``.
                     An optional ``"model"`` key in ``message.metadata`` can
                     override the default model.
            audit:   ``AuditLog`` passed to the spawned ``ResearchAgent``.

        Returns:
            A ``ResearchAgent`` instance.  Session is ephemeral — the caller
            must not write its output to a persistent transcript.

        Raises:
            ValueError:    If ``message.operation != "research_query"`` or the
                           params block fails ``ResearchRequest`` validation.
            SecurityError: If the trust level is below ``main`` or the model
                           override is not in the approved allowlist.
        """
        # 1. Operation check
        if message.operation != "research_query":
            raise ValueError(
                f"create_research_agent requires operation='research_query'; "
                f"got {message.operation!r}"
            )

        # 2. Trust level check (>= main)
        if message.trust_level not in _RESEARCH_ALLOWED_TRUST_LEVELS:
            await self._audit_log.log(
                AuditEvent(
                    event="research_agent_spawn_denied",
                    agent_id=message.from_agent,
                    session_key=message.session_key,
                    trace_id=message.trace_id,
                    details={
                        "reason": f"trust level {message.trust_level!r} below minimum 'main'",
                    },
                )
            )
            raise SecurityError(
                f"research_query requires trust level >= 'main'; " f"got {message.trust_level!r}"
            )

        # 3. Parse params as ResearchRequest
        try:
            ResearchRequest(**message.params)
        except (ValidationError, TypeError) as exc:
            raise ValueError(f"Invalid ResearchRequest params: {exc}") from exc

        # 4. Validate model override
        model_override: Optional[str] = message.metadata.get("model")
        if model_override is not None and model_override not in APPROVED_RESEARCH_MODELS:
            raise SecurityError(
                f"Model {model_override!r} is not in the approved research model allowlist. "
                f"Approved models: {sorted(APPROVED_RESEARCH_MODELS)}"
            )

        # 5. Build config (apply model override when present)
        if model_override is not None:
            config = ResearchAgentConfig(model=model_override)
        else:
            config = ResearchAgentConfig()

        # 6. Audit log
        await self._audit_log.log(
            AuditEvent(
                event="research_agent_spawned",
                agent_id=message.from_agent,
                session_key=message.session_key,
                trace_id=message.trace_id,
                details={
                    "query": message.params.get("query", ""),
                    "model": config.model,
                    "trust_level": message.trust_level,
                },
            )
        )

        # 7. Instantiate and return (import here to avoid top-level circular deps)
        from openrattler.agents.research.agent import ResearchAgent

        return ResearchAgent(config=config, audit=audit)

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    async def _enforce_timeout(self, agent_id: str, timeout_seconds: int) -> None:
        """Wait *timeout_seconds* then kill *agent_id* if still registered."""
        await asyncio.sleep(timeout_seconds)
        if agent_id in self._registry:
            await self.kill_agent(
                agent_id,
                reason=f"Timeout after {timeout_seconds}s",
            )
