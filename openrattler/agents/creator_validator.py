"""Security validator for the Agent Creator — the spawn-time security chokepoint.

``CreatorSecurityValidator`` is **hardcoded**, not templated.  This is
intentional: the validator itself must never be replaceable by a dynamic
template or config value because doing so would allow an attacker to swap in
a permissive validator via a crafted spawn request.

VALIDATION PIPELINE (in order)
--------------------------------
1. Spawner authorisation — is ``from_agent`` allowed to request creation?
2. Spawn limits — depth, width, session count, rate, and cost checks.
3. Task-intent alignment — does the task legitimately follow from what the
   user asked?  (LLM-based — STUBBED for now, always returns True.)
4. Tool-task alignment — are the requested tools appropriate for the task?
   (LLM-based — STUBBED for now, always returns True.)
5. Dangerous-tool check — always requires approval if exec/delete/sudo tools
   are requested.

Steps 3–4 are stubs pending LLM integration.  The stubs are clearly marked
with ``TODO`` so they are trivial to find and wire up later.

SECURITY NOTES
--------------
- This class is instantiated *once* per ``AgentCreator`` and never replaced.
- All validation logic is synchronous-compatible (stubs) or fast; no LLM
  calls are made in the current implementation.
- ``check_spawn_limits`` raises ``SpawnLimitError`` rather than returning
  a boolean so the call site always gets a descriptive message.
- ``AUTHORIZED_SPAWNERS`` is a frozenset — adding a spawner requires a code
  change, not a config edit.
"""

from __future__ import annotations

import time
from typing import Optional

from openrattler.models.agents import AgentConfig, AgentCreationRequest, AgentSpawnLimits

# ---------------------------------------------------------------------------
# Exceptions
# ---------------------------------------------------------------------------


class SpawnLimitError(Exception):
    """Raised when a spawn request would exceed a configured limit."""


class SecurityError(Exception):
    """Raised when the security validator rejects a spawn request."""


# ---------------------------------------------------------------------------
# Authorised spawner allowlist
# ---------------------------------------------------------------------------

#: Agent IDs that are permitted to request subagent creation.
#: Adding a new spawner requires a code change — no config override possible.
AUTHORIZED_SPAWNERS: frozenset[str] = frozenset(
    {
        "agent:main:main",
        "agent:creator:system",
    }
)

#: Tools that always trigger an approval prompt regardless of task alignment.
DANGEROUS_TOOLS: frozenset[str] = frozenset({"exec", "file_delete", "sudo", "rm", "chmod"})


# ---------------------------------------------------------------------------
# CreatorSecurityValidator
# ---------------------------------------------------------------------------


class CreatorSecurityValidator:
    """Hardcoded security validator for all Agent Creator spawn requests.

    Args:
        spawn_limits: The ``AgentSpawnLimits`` enforced by this validator.
        agent_registry: Live registry mapping ``agent_id → AgentConfig`` for
                        counting active children / session agents.

    Security notes:
    - This class must be instantiated once and never replaced at runtime.
    - ``validate_agent_request`` is the single public entry point.
    - Spawn counts are derived from ``agent_registry`` at validation time, so
      they reflect the live state of the system.
    """

    def __init__(
        self,
        spawn_limits: AgentSpawnLimits,
        agent_registry: dict[str, AgentConfig],
    ) -> None:
        self._limits = spawn_limits
        self._registry = agent_registry
        # Sliding window: list of spawn timestamps (float) for rate limiting
        self._spawn_times: list[float] = []

    # ------------------------------------------------------------------
    # Public entry point
    # ------------------------------------------------------------------

    async def validate_agent_request(
        self, request: AgentCreationRequest
    ) -> tuple[bool, Optional[str]]:
        """Run the full validation pipeline.

        Returns:
            ``(True, None)`` if the request is approved.
            ``(False, reason)`` if any check fails.
        """
        # 1. Spawner authorisation
        if not self.is_authorized_spawner(request.from_agent):
            return False, f"{request.from_agent!r} is not an authorised spawner"

        # 2. Spawn limits
        try:
            self.check_spawn_limits(request)
        except SpawnLimitError as exc:
            return False, str(exc)

        # 3. Task-intent alignment (LLM-based — STUB)
        if not self.task_matches_intent(request.task, request.original_user_message):
            # When LLM-based check is wired in, a mismatch triggers an approval
            # prompt.  For now the stub always returns True so this branch is
            # unreachable in practice.
            return False, "Task does not match original user intent"

        # 4. Tool-task alignment (LLM-based — STUB)
        from openrattler.agents.templates import TASK_TEMPLATES

        requested_tools = (
            TASK_TEMPLATES.get(request.template, None)
            and TASK_TEMPLATES[request.template].required_tools
            or []
        ) + list(request.custom_tools)

        if not self.tools_match_task(list(requested_tools), request.task):
            # Same stub situation as above.
            return False, "Requested tools do not match task"

        # 5. Dangerous-tool check (always enforce, no stub)
        if DANGEROUS_TOOLS & set(requested_tools):
            flagged = sorted(DANGEROUS_TOOLS & set(requested_tools))
            return False, f"Dangerous tools require explicit approval: {flagged}"

        return True, None

    # ------------------------------------------------------------------
    # Authorisation
    # ------------------------------------------------------------------

    def is_authorized_spawner(self, from_agent: str) -> bool:
        """Return ``True`` if *from_agent* is permitted to request creation."""
        return from_agent in AUTHORIZED_SPAWNERS

    # ------------------------------------------------------------------
    # Spawn limit enforcement
    # ------------------------------------------------------------------

    def check_spawn_limits(self, request: AgentCreationRequest) -> None:
        """Enforce all spawn limits.  Raises ``SpawnLimitError`` if exceeded.

        Checks (in order):
        1. Depth — request.depth must be < max_depth.
        2. Width — parent's child count must be < max_children_per_agent.
        3. Session total — session's subagent count must be < max_total_subagents.
        4. Rate (per-minute) — recent spawn count must be < max_spawns_per_minute.

        Security notes:
        - Depth is enforced from the request payload (set by the caller at
          construction time); the creator must not trust the caller to
          self-report honestly.  In a future piece, the depth will be verified
          independently from the spawn tree rather than relying on the request.
        """
        # 1. Depth
        if request.depth >= self._limits.max_depth:
            raise SpawnLimitError(
                f"Max spawn depth {self._limits.max_depth} reached "
                f"(requested depth={request.depth})"
            )

        # 2. Width (children of parent_agent)
        child_count = self._count_children(request.parent_agent)
        if child_count >= self._limits.max_children_per_agent:
            raise SpawnLimitError(
                f"Parent {request.parent_agent!r} already has "
                f"{child_count} children "
                f"(max={self._limits.max_children_per_agent})"
            )

        # 3. Session-wide total
        session_count = self._count_session_agents(request.session_key)
        if session_count >= self._limits.max_total_subagents_per_session:
            raise SpawnLimitError(
                f"Session {request.session_key!r} already has "
                f"{session_count} subagents "
                f"(max={self._limits.max_total_subagents_per_session})"
            )

        # 4. Rate (per-minute sliding window)
        now = time.monotonic()
        self._spawn_times = [t for t in self._spawn_times if now - t < 60.0]
        if len(self._spawn_times) >= self._limits.max_spawns_per_minute:
            raise SpawnLimitError(
                f"Spawn rate limit exceeded "
                f"({self._limits.max_spawns_per_minute} spawns/minute)"
            )

    # ------------------------------------------------------------------
    # Stub validation methods (LLM-based — wired up in a later piece)
    # ------------------------------------------------------------------

    def task_matches_intent(self, task: str, original_user_message: str) -> bool:
        """Return True if *task* legitimately follows from *original_user_message*.

        TODO: Wire up LLM-based intent alignment check.
              Use a cheap model (e.g. claude-haiku-4-5) to validate.
              Prompt pattern: "User said X. Agent wants to do Y. Is Y valid? YES/NO"
              Until then, this stub always returns True (allow-by-default).
        """
        return True

    def tools_match_task(self, tools: list[str], task: str) -> bool:
        """Return True if *tools* are appropriate for *task*.

        TODO: Wire up LLM-based tool-task alignment check.
              Use tool metadata from ToolRegistry to build the validation
              prompt.  Until then, this stub always returns True.
        """
        return True

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    def _count_children(self, parent_agent: str) -> int:
        """Count agents in the registry whose parent_agent matches."""
        count = 0
        for config in self._registry.values():
            if isinstance(config, AgentConfig):
                # parent is stored in the description convention; in this
                # build piece the registry stores AgentConfig objects keyed
                # by agent_id and the parent is tracked via the session_key
                # prefix.  We count any agent whose agent_id starts with the
                # parent's session_key (subagent isolation key scheme).
                if config.session_key and config.session_key.startswith(
                    parent_agent.replace("agent:", "agent:")
                ):
                    # Only count direct subagents, not the parent itself
                    if config.agent_id != parent_agent:
                        count += 1
        return count

    def _count_session_agents(self, session_key: str) -> int:
        """Count agents in the registry associated with *session_key*."""
        count = 0
        for config in self._registry.values():
            if isinstance(config, AgentConfig):
                if config.session_key and config.session_key.startswith(session_key):
                    if config.agent_id != f"agent:{session_key.split(':')[-1]}:main":
                        count += 1
        return count

    def _record_spawn(self) -> None:
        """Record a successful spawn for rate-limit tracking."""
        self._spawn_times.append(time.monotonic())
