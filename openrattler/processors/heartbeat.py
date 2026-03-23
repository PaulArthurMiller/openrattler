"""HeartbeatProcessor — scheduled background check-in for the main agent.

Runs a brief LLM turn on a configurable schedule, injecting HEARTBEAT.md
into the system prompt so the agent knows it is in background check-in mode
rather than responding to a direct user message.

WHAT IT DOES
------------
Each cycle:
1. Loads the HEARTBEAT.md section from the IdentityLoader.
2. Initialises a fresh heartbeat session (separate from the user's CLI
   conversation so there is no race condition or history contamination).
3. Appends the heartbeat section to the session's system prompt.
4. Sends a synthetic ``heartbeat_trigger`` event to the runtime.
5. If the agent produces a non-trivial response, stores it as a
   ``HeartbeatOutput`` with ``urgency="immediate"`` so the scheduler's
   urgent-alert dispatch surfaces it to the user.

OUTPUT FORMAT
-------------
``HeartbeatOutput`` exposes the same ``urgency``, ``operation``, and
``params`` attributes that ``ProcessorScheduler._dispatch_urgent_alerts``
reads generically, so no scheduler changes are needed to forward heartbeat
responses.

SECURITY NOTES
--------------
- The heartbeat session key is ``"agent:main:heartbeat"`` — isolated from
  the user's direct-message session so tool calls in heartbeat turns never
  interleave with live conversation turns.
- The synthetic trigger message uses ``trust_level="main"`` so all main-trust
  tools remain available during heartbeat turns.
- HeartbeatProcessor never communicates with the user directly; output is
  stored as pending ``HeartbeatOutput`` items and surfaced by the scheduler's
  ``on_urgent_alert`` callback.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any, Optional
from uuid import uuid4

from openrattler.models.messages import create_message
from openrattler.processors.base import ProactiveProcessor

if TYPE_CHECKING:
    from openrattler.agents.runtime import AgentRuntime
    from openrattler.identity.loader import IdentityLoader
    from openrattler.storage.audit import AuditLog

logger = logging.getLogger(__name__)

#: Session key used for all heartbeat turns — separate from the user's
#: direct-message session to avoid history contamination and race conditions.
HEARTBEAT_SESSION_KEY: str = "agent:main:heartbeat"

#: Operation name embedded in HeartbeatOutput.params and the dispatched
#: UniversalMessage so downstream handlers can distinguish heartbeat
#: responses from social alerts.
HEARTBEAT_OPERATION: str = "heartbeat_response"


# ---------------------------------------------------------------------------
# HeartbeatOutput
# ---------------------------------------------------------------------------


@dataclass
class HeartbeatOutput:
    """A single scheduled check-in response from the main agent.

    Designed to be read generically by ``ProcessorScheduler._dispatch_urgent_alerts``:

    - ``urgency = "immediate"`` causes the scheduler to dispatch it.
    - ``operation`` and ``params`` are read via ``getattr`` and forwarded in
      the dispatched ``UniversalMessage``, allowing downstream handlers to
      distinguish heartbeat responses from social alerts.
    """

    summary: str
    id: str = field(default_factory=lambda: f"heartbeat_{uuid4().hex[:8]}")
    urgency: str = "immediate"
    operation: str = HEARTBEAT_OPERATION

    @property
    def params(self) -> dict[str, Any]:
        """Parameters forwarded to the on_urgent_alert callback."""
        return {"summary": self.summary, "content": self.summary}


# ---------------------------------------------------------------------------
# HeartbeatProcessor
# ---------------------------------------------------------------------------


class HeartbeatProcessor(ProactiveProcessor):
    """Scheduled background check-in for the main agent.

    Args:
        runtime:          The main agent runtime — used to initialise a session
                          and process the synthetic heartbeat trigger.
        identity_loader:  Provides HEARTBEAT.md content via
                          ``load_heartbeat_section()``.
        session_key:      Session key for heartbeat turns. Defaults to
                          ``HEARTBEAT_SESSION_KEY`` (``"agent:main:heartbeat"``).
        audit:            Optional audit log (not currently used; reserved for
                          future cycle-level audit events).

    Security notes:
    - The heartbeat session key is always different from the user's direct-
      message session so concurrent heartbeat and user turns never race.
    - ``connect()`` and ``disconnect()`` are no-ops — no external connections
      are required; all data comes from the runtime and identity files.
    - The synthetic trigger message uses ``trust_level="main"`` so the agent
      has access to its normal tool set during heartbeat turns.
    """

    @property
    def processor_name(self) -> str:
        """Machine-readable name used for audit logging and scheduler registration."""
        return "heartbeat"

    def __init__(
        self,
        runtime: "AgentRuntime",
        identity_loader: "IdentityLoader",
        session_key: str = HEARTBEAT_SESSION_KEY,
        audit: Optional["AuditLog"] = None,
    ) -> None:
        self._runtime = runtime
        self._identity_loader = identity_loader
        self._session_key = session_key
        self._audit = audit
        self._pending: list[HeartbeatOutput] = []

    # ------------------------------------------------------------------
    # ProactiveProcessor lifecycle
    # ------------------------------------------------------------------

    async def connect(self) -> None:
        """No-op — heartbeat requires no external connections."""

    async def disconnect(self) -> None:
        """No-op — nothing to release."""

    # ------------------------------------------------------------------
    # Processing cycle
    # ------------------------------------------------------------------

    async def run_cycle(self) -> int:
        """Execute one heartbeat turn.

        Loads HEARTBEAT.md, initialises a fresh session, injects the
        heartbeat section into the system prompt, then processes a synthetic
        trigger.  If the agent returns non-trivial content, stores it as a
        ``HeartbeatOutput`` for dispatch.

        Returns:
            ``1`` if the agent produced a non-empty response, ``0`` otherwise.
        """
        self._pending = []

        try:
            heartbeat_section = await self._identity_loader.load_heartbeat_section()
            session = await self._runtime.initialize_session(self._session_key)
            # Clear accumulated transcript history so each cycle runs with a
            # fresh context.  Without this, the heartbeat session history grows
            # unboundedly and Corvus eventually sees dozens of identical prior
            # triggers, causing it to flag the pattern as a loop.
            session.history = []

            if heartbeat_section:
                session.system_prompt = session.system_prompt + "\n\n" + heartbeat_section

            trigger = create_message(
                from_agent="scheduler:heartbeat",
                to_agent=self._session_key,
                session_key=self._session_key,
                type="request",
                operation="heartbeat_trigger",
                trust_level="main",
                params={
                    "content": "Scheduled heartbeat check-in. Please run your heartbeat tasks now."
                },
            )

            response = await self._runtime.process_message(session, trigger)
            content: str = response.params.get("content", "") or ""

            if content.strip():
                self._pending = [HeartbeatOutput(summary=content.strip())]
                logger.debug("HeartbeatProcessor: cycle produced output (%d chars)", len(content))
                return 1

            logger.debug("HeartbeatProcessor: cycle produced no output — nothing urgent")
            return 0

        except Exception as exc:
            logger.warning("HeartbeatProcessor: cycle error: %s", exc)
            return 0

    # ------------------------------------------------------------------
    # Output access
    # ------------------------------------------------------------------

    async def get_pending_output(self) -> list[HeartbeatOutput]:
        """Return pending heartbeat outputs from the last cycle."""
        return list(self._pending)
