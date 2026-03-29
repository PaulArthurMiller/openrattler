"""HeartbeatProcessor — scheduled background check-in for the main agent.

Runs a brief LLM turn on a configurable schedule, injecting HEARTBEAT.md
into the system prompt so the agent knows it is in background check-in mode
rather than responding to a direct user message.

WHAT IT DOES
------------
Each cycle:
1. Generates a unique per-cycle session key (``agent:main:heartbeat:{cycle_id}``).
2. Loads recent heartbeat log entries and builds a context block.
3. Loads the HEARTBEAT.md section from the IdentityLoader.
4. Initialises a fresh session (no prior history — ephemeral scratch-pad).
5. Appends the heartbeat section + log context to the session's system prompt.
6. Sends a synthetic ``heartbeat_trigger`` event to the runtime.
7. Records the cycle outcome in ``heartbeat_log.jsonl``.
8. If the agent produces a non-trivial response, stores it as a
   ``HeartbeatOutput`` with ``urgency="immediate"`` so the scheduler's
   urgent-alert dispatch surfaces it to the user.

PER-CYCLE SESSION ISOLATION
----------------------------
``run_cycle()`` creates a new session key each call so no prior heartbeat
transcript is ever re-injected as conversational context.  This prevents the
compounding echo-chamber where each cycle riffs on the previous one.
Cross-cycle awareness is provided exclusively by ``heartbeat_log.jsonl``,
which the agent reads as structured markdown — never as raw transcript history.

OUTPUT FORMAT
-------------
``HeartbeatOutput`` exposes the same ``urgency``, ``operation``, and
``params`` attributes that ``ProcessorScheduler._dispatch_urgent_alerts``
reads generically, so no scheduler changes are needed to forward heartbeat
responses.

SECURITY NOTES
--------------
- Each heartbeat session is ephemeral and isolated from the user's direct-
  message session so tool calls in heartbeat turns never interleave with live
  conversation turns.
- The synthetic trigger message uses ``trust_level="main"`` so all main-trust
  tools remain available during heartbeat turns.
- HeartbeatProcessor never communicates with the user directly; output is
  stored as pending ``HeartbeatOutput`` items and surfaced by the scheduler's
  ``on_urgent_alert`` callback.
- ``heartbeat_log.jsonl`` context is injected as read-only markdown; it does
  not include raw session transcripts.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import TYPE_CHECKING, Any, Optional
from uuid import uuid4

from openrattler.models.messages import create_message
from openrattler.processors.base import ProactiveProcessor
from openrattler.processors.heartbeat_log import HeartbeatLog, HeartbeatLogEntry

if TYPE_CHECKING:
    from openrattler.agents.runtime import AgentRuntime
    from openrattler.config.loader import AppConfig
    from openrattler.identity.loader import IdentityLoader
    from openrattler.storage.audit import AuditLog

logger = logging.getLogger(__name__)

# HEARTBEAT_SESSION_KEY is retained for legacy references only.
# run_cycle() now generates per-cycle session keys. See BUILD_PIECE_20_1.md.
HEARTBEAT_SESSION_KEY: str = "agent:main:heartbeat"  # deprecated — do not use in run_cycle()

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
# Helper stubs
# ---------------------------------------------------------------------------


def extract_one_sentence_summary(text: str) -> str:
    """Return first sentence of text, truncated to 120 chars."""
    # Split on first sentence-ending punctuation followed by whitespace or end.
    for sep in (".", "!", "?"):
        idx = text.find(sep)
        if idx != -1:
            sentence = text[: idx + 1].strip()
            if len(sentence) > 120:
                return sentence[:117] + "..."
            return sentence
    # No sentence boundary found — return the whole text (HeartbeatLogEntry will cap it).
    return text.strip()


def extract_topic_labels(text: str) -> list[str]:
    """Return empty list. Stub for future NLP-based topic extraction."""
    return []


def extract_predictions(output: Optional[HeartbeatOutput]) -> list[dict[str, Any]]:
    """Return empty list. Stub for future prediction parsing."""
    return []


# ---------------------------------------------------------------------------
# UTC timestamp helper
# ---------------------------------------------------------------------------


def _utcnow_iso() -> str:
    """Return the current UTC time as a compact ISO8601 string with microseconds.

    Microseconds ensure cycle IDs are unique even when consecutive cycles run
    within the same second (e.g. in tests or burst scheduling scenarios).
    """
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


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
        identity_dir:     Path to the identity directory; used to locate
                          ``heartbeat_log.jsonl``.
        config:           Full application config, read on each cycle so
                          ``log_context_entries`` and ``log_max_retained``
                          changes take effect without restart.
        session_key:      Ignored in active use; retained for backward
                          compatibility with tests that pass it explicitly.
                          ``run_cycle()`` always generates per-cycle keys.
        audit:            Optional audit log (reserved for future cycle-level
                          audit events).

    Security notes:
    - Per-cycle session keys prevent heartbeat transcript accumulation and
      the resulting echo-chamber where the agent riffs on its own prior output.
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
        identity_dir: Optional[Any] = None,
        config: Optional["AppConfig"] = None,
        session_key: str = HEARTBEAT_SESSION_KEY,
        audit: Optional["AuditLog"] = None,
    ) -> None:
        self._runtime = runtime
        self._identity_loader = identity_loader
        self._config = config
        # Derive identity dir from config or fall back to a safe default.
        from pathlib import Path

        if identity_dir is not None:
            _identity_dir = Path(identity_dir)
        else:
            import os

            _identity_dir = Path(os.path.expanduser("~/.openrattler/identity"))

        log_context_entries = config.heartbeat.log_context_entries if config is not None else 7
        self._heartbeat_log = HeartbeatLog(
            log_path=_identity_dir / "heartbeat_log.jsonl",
            max_context_entries=log_context_entries,
        )
        # Retained for backward compat — not used in run_cycle().
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
        """Execute one heartbeat turn with per-cycle session isolation.

        Each call generates a unique session key so no prior heartbeat
        transcript is ever re-injected as conversation context.  The
        heartbeat log provides structured cross-cycle awareness instead.

        Returns:
            ``1`` if the agent produced a non-empty response, ``0`` otherwise.
        """
        self._pending = []

        # 1. Generate per-cycle identifiers.
        cycle_id = f"hb_{_utcnow_iso()}"
        session_key = f"agent:main:heartbeat:{cycle_id}"

        log_max_retained = (
            self._config.heartbeat.log_max_retained if self._config is not None else 100
        )
        log_context_entries = (
            self._config.heartbeat.log_context_entries if self._config is not None else 7
        )

        try:
            # 2. Load recent log entries for context injection.
            recent_entries = await self._heartbeat_log.read_recent(log_context_entries)

            # 3. Load HEARTBEAT.md and build the full system prompt addition.
            heartbeat_section = await self._identity_loader.load_heartbeat_section()

            session = await self._runtime.initialize_session(session_key)
            # Fresh session — no prior history.  This is intentional: the
            # heartbeat session is an ephemeral scratch-pad, not a conversation.
            session.history = []

            # Append HEARTBEAT.md content first, then the log context block.
            context_block = self._heartbeat_log.build_context_block(recent_entries)
            if heartbeat_section:
                session.system_prompt = (
                    session.system_prompt + "\n\n" + heartbeat_section + "\n\n" + context_block
                )
            else:
                session.system_prompt = session.system_prompt + "\n\n" + context_block

            # 4. TODO (Build Piece: CalibrationAgent)
            # Spawn CalibrationAgent subagent here before generating new output.
            #
            # Expected inputs to CalibrationAgent:
            #   - recent_entries (list[HeartbeatLogEntry]) — log entries with open predictions
            #   - cli_session_excerpts — recent turns from "agent:main:main" since last cycle
            #     (requires session lookup tool — see BUILD_GUIDE.md backlog item)
            #   - calibration_state — current contents of calibration_state.json
            #
            # Expected return from CalibrationAgent:
            #   - updated_weights: dict  — revised confidence values for urgency/topic priors
            #   - outcome_updates: list[dict]  — {cycle_id, outcomes} pairs to persist
            #   - proposed_heartbeat_revision: str | None  — if agent proposes HEARTBEAT.md
            #     change; routes to MemorySecurityAgent review pipeline, not applied directly
            #
            # On return:
            #   - Write updated_weights to calibration_state.json
            #   - Call self._heartbeat_log.update_outcomes() for each outcome_updates entry
            #   - Queue proposed_heartbeat_revision for approval (if present)
            #   - Set calibration_applied = True on the current cycle's log entry
            #
            # Until this subagent exists: calibration_applied = False on all entries.
            calibration_applied = False  # remove this line when CalibrationAgent is wired in

            # 5. Session is already initialised fresh above (step 4 of the spec).

            # 6. Send synthetic heartbeat_trigger event, run agent turn.
            trigger = create_message(
                from_agent="scheduler:heartbeat",
                to_agent=session_key,
                session_key=session_key,
                type="request",
                operation="heartbeat_trigger",
                trust_level="main",
                params={
                    "content": "Scheduled heartbeat check-in. Please run your heartbeat tasks now."
                },
            )

            response = await self._runtime.process_message(session, trigger)
            content: str = response.params.get("content", "") or ""

            # 7. Determine cycle outcome.
            output: Optional[HeartbeatOutput] = None
            if content.strip():
                output = HeartbeatOutput(summary=content.strip())
                urgency = output.urgency  # "immediate" when content present
                summary = extract_one_sentence_summary(output.params["summary"])
                flagged_topics = extract_topic_labels(output.params["summary"])
                delivered_to_user = True
                self._pending = [output]
                logger.debug(
                    "HeartbeatProcessor: cycle %s produced output (%d chars)",
                    cycle_id,
                    len(content),
                )
            else:
                urgency = "low"
                summary = "No significant activity detected."
                flagged_topics = []
                delivered_to_user = False
                logger.debug(
                    "HeartbeatProcessor: cycle %s produced no output — nothing urgent",
                    cycle_id,
                )

            # 8. Build predictions list (stub — always empty until extraction wired in).
            predictions = extract_predictions(output)

            # 9. Construct and append log entry, then prune.
            entry = HeartbeatLogEntry(
                cycle_id=cycle_id,
                run_at=_utcnow_iso(),
                urgency=urgency,
                flagged_topics=flagged_topics,
                delivered_to_user=delivered_to_user,
                summary=summary,
                predictions=predictions,
                outcomes=[],
                calibration_applied=calibration_applied,
            )
            await self._heartbeat_log.append(entry)
            await self._heartbeat_log.prune(log_max_retained)

            # 10. Store output as pending HeartbeatOutput (existing behaviour, unchanged).
            return 1 if delivered_to_user else 0

        except Exception as exc:
            logger.warning("HeartbeatProcessor: cycle error: %s", exc)
            return 0

    # ------------------------------------------------------------------
    # Output access
    # ------------------------------------------------------------------

    async def get_pending_output(self) -> list[HeartbeatOutput]:
        """Return pending heartbeat outputs from the last cycle."""
        return list(self._pending)
