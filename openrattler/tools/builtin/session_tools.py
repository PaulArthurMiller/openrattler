"""Built-in session tools: sessions_history, session_read_self, session_lookup.

SECURITY MODEL
--------------
* sessions_history (DEPRECATED) — cross-session read; requires_approval=True.
* session_read_self — reads the CALLER's own session transcript since a
  given timestamp.  The session key comes from agent_config (runtime-injected),
  so the LLM cannot supply a different session key through this tool.
  trust_level_required=main, action_level=5.
* session_lookup — cross-session read with explicit session_key param.
  Handler-level scope enforcement further restricts CalibrationAgent sessions
  (agent:main:heartbeat:*) to reading only agent:main:main within a 72h window,
  even after the executor approval gate passes.
  trust_level_required=main, action_level=3.

All three tools require a configured TranscriptStore.  session_read_self and
session_lookup optionally invoke a SummarizerAgent when summarize=True.
Call configure_transcript_store(), configure_summarizer_agent(), and
configure_audit_log() at startup before any tool is invoked.
"""

from __future__ import annotations

import logging
import uuid
from datetime import datetime, timedelta, timezone
from typing import Any, Optional, TYPE_CHECKING

from openrattler.models.agents import AgentConfig, TrustLevel
from openrattler.models.audit import AuditEvent
from openrattler.models.messages import create_message
from openrattler.storage.audit import AuditLog
from openrattler.storage.transcripts import TranscriptStore
from openrattler.tools.registry import tool

if TYPE_CHECKING:
    from openrattler.agents.summarizer.agent import SummarizerAgent

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Module-level configuration
# ---------------------------------------------------------------------------

_transcript_store: Optional[TranscriptStore] = None
_summarizer_agent: Optional["SummarizerAgent"] = None
_audit_log: Optional[AuditLog] = None


def configure_transcript_store(store: Optional[TranscriptStore]) -> None:
    """Set the ``TranscriptStore`` instance used by all session tools.

    Args:
        store: A configured ``TranscriptStore``, or ``None`` to disable access.

    Security note:
        The default is ``None`` (disabled).  Production startup code must call
        this with the application-wide store before the tools can be invoked.
    """
    global _transcript_store
    _transcript_store = store


def configure_summarizer_agent(agent: Optional["SummarizerAgent"]) -> None:
    """Set the ``SummarizerAgent`` used by session_read_self and session_lookup.

    Args:
        agent: A configured ``SummarizerAgent``, or ``None`` to disable
               summarization (tools will fall back to returning raw messages).

    Security note:
        When ``None``, summarize=True requests fall back gracefully to raw
        message lists rather than erroring, so the tool remains usable in
        environments without a provider.
    """
    global _summarizer_agent
    _summarizer_agent = agent


def configure_audit_log(audit: Optional[AuditLog]) -> None:
    """Set the ``AuditLog`` used for business-level session access events.

    Args:
        audit: A configured ``AuditLog``, or ``None`` to disable audit writing
               (not recommended outside tests).

    Security note:
        Business-level events (session_read_own, session_lookup_read,
        session_lookup_scope_violation) are written here.  The executor always
        writes its own tool_execution events separately.
    """
    global _audit_log
    _audit_log = audit


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def _messages_to_text(messages: list[Any]) -> str:
    """Serialize a list of UniversalMessages to a human-readable text block."""
    lines = []
    for msg in messages:
        ts = getattr(msg, "timestamp", "")
        from_a = getattr(msg, "from_agent", "")
        to_a = getattr(msg, "to_agent", "")
        op = getattr(msg, "operation", "")
        params = getattr(msg, "params", {}) or {}
        content = params.get("content", "") or str(params)[:200]
        lines.append(f"[{ts}] {from_a}->{to_a} ({op}): {content}")
    return "\n".join(lines)


async def _maybe_summarize(
    messages: list[Any],
    session_key: str,
    since_iso: str,
    trace_id: str,
    caller_agent_id: str,
) -> dict[str, Any]:
    """Return summary dict if _summarizer_agent is available, else raw messages dict."""
    turn_count = len(messages)
    base: dict[str, Any] = {
        "session_key": session_key,
        "turn_count": turn_count,
        "since_iso": since_iso,
    }

    if _summarizer_agent is None:
        base["messages"] = [m.model_dump() for m in messages]
        base["summarized"] = False
        return base

    from openrattler.agents.summarizer.models import SummarizerRequest

    text = _messages_to_text(messages)
    request_params = SummarizerRequest(text=text, skill="session").model_dump()
    request_um = create_message(
        from_agent=caller_agent_id,
        to_agent="agent:summarizer:sub",
        session_key=session_key,
        type="request",
        operation="summarize",
        trust_level="main",
        params=request_params,
        trace_id=trace_id,
    )
    response_um = await _summarizer_agent.run(request_um, trace_id)
    if response_um.type == "response":
        base["summary"] = response_um.params.get("summary", "")
        base["summarized"] = True
    else:
        # Summarization failed; fall back to raw messages so the caller isn't blocked
        logger.warning(
            "session tool: SummarizerAgent returned error for session %s; returning raw messages",
            session_key,
        )
        base["messages"] = [m.model_dump() for m in messages]
        base["summarized"] = False
    return base


# ---------------------------------------------------------------------------
# Deprecated tool
# ---------------------------------------------------------------------------


@tool(
    trust_level_required=TrustLevel.main,
    requires_approval=True,
    action_level=4,
    security_notes=(
        "Cross-session data access. Requires human approval before execution. "
        "Every invocation (approved or denied) is audit-logged by the executor. "
        "Session-key validation is delegated to TranscriptStore."
    ),
)
async def sessions_history(target_session_key: str, n: int = 10) -> list[dict[str, Any]]:
    """[DEPRECATED: use session_read_self or session_lookup] Retrieve recent transcript messages.

    Args:
        target_session_key: Session key of the transcript to read.
        n:                  Maximum number of messages to return (default 10).

    Returns:
        A list of message dicts, oldest first, up to *n* entries.

    SECURITY:
    - Requires human approval before execution (cross-session access).
    - TranscriptStore validates the session key format.
    - Trust level required: main.
    """
    if _transcript_store is None:
        raise RuntimeError(
            "TranscriptStore not configured. "
            "Call configure_transcript_store() before using sessions_history."
        )

    messages = await _transcript_store.load_recent(target_session_key, n)
    return [msg.model_dump() for msg in messages]


# ---------------------------------------------------------------------------
# session_read_self
# ---------------------------------------------------------------------------


@tool(
    trust_level_required=TrustLevel.main,
    requires_approval=True,
    action_level=5,
    security_notes=(
        "Reads the CALLER's own session transcript. "
        "session_key is sourced from agent_config (runtime-injected), "
        "so the LLM cannot request a different session's data through this tool. "
        "All invocations are audit-logged."
    ),
)
async def session_read_self(
    since_iso: str,
    max_turns: int = 20,
    summarize: bool = True,
    agent_config: AgentConfig = None,  # type: ignore[assignment]
) -> dict[str, Any]:
    """Read messages from the caller's own session transcript since a given ISO timestamp.

    Args:
        since_iso:    ISO 8601 datetime string; messages at or after this time are returned.
        max_turns:    Maximum number of messages to return after the time filter (default 20).
        summarize:    When True (default), returns a text summary via SummarizerAgent.
                      When False, returns the raw message list.
        agent_config: Runtime-injected by the executor; not supplied by the LLM.

    Returns:
        Dict with keys: session_key, turn_count, since_iso, summarized,
        and either "summary" (str) or "messages" (list).

    SECURITY:
    - session_key is taken from agent_config.session_key, not from LLM input.
    - Trust level required: main.
    """
    if _transcript_store is None:
        raise RuntimeError(
            "TranscriptStore not configured. "
            "Call configure_transcript_store() before using session_read_self."
        )
    if agent_config is None:
        raise RuntimeError(
            "agent_config not injected. "
            "session_read_self must be called through the ToolExecutor."
        )

    session_key = agent_config.session_key or ""
    if not session_key:
        return {"error": "No session_key in agent_config; cannot read own session."}

    messages = await _transcript_store.load_since(session_key, since_iso, max_turns)
    turn_count = len(messages)

    if _audit_log is not None:
        await _audit_log.log(
            AuditEvent(
                event="session_read_own",
                agent_id=agent_config.agent_id,
                session_key=session_key,
                details={
                    "since_iso": since_iso,
                    "max_turns": max_turns,
                    "turn_count": turn_count,
                    "summarize": summarize,
                },
            )
        )

    if not summarize or not messages:
        return {
            "session_key": session_key,
            "turn_count": turn_count,
            "since_iso": since_iso,
            "messages": [m.model_dump() for m in messages],
            "summarized": False,
        }

    trace_id = uuid.uuid4().hex
    return await _maybe_summarize(messages, session_key, since_iso, trace_id, agent_config.agent_id)


# ---------------------------------------------------------------------------
# session_lookup
# ---------------------------------------------------------------------------


@tool(
    trust_level_required=TrustLevel.main,
    requires_approval=True,
    action_level=3,
    security_notes=(
        "Cross-session transcript read with handler-level scope enforcement. "
        "CalibrationAgent (heartbeat sessions) is restricted to agent:main:main "
        "and a 72-hour window, even after the executor approval gate. "
        "All invocations are audit-logged."
    ),
)
async def session_lookup(
    session_key: str,
    since_iso: str,
    max_turns: int = 20,
    summarize: bool = True,
    agent_config: AgentConfig = None,  # type: ignore[assignment]
) -> dict[str, Any]:
    """Read messages from any session transcript since a given ISO timestamp.

    Args:
        session_key:  Session key of the transcript to read.
        since_iso:    ISO 8601 datetime string; messages at or after this time are returned.
        max_turns:    Maximum number of messages to return after the time filter (default 20).
        summarize:    When True (default), returns a text summary via SummarizerAgent.
                      When False, returns the raw message list.
        agent_config: Runtime-injected by the executor; not supplied by the LLM.

    Returns:
        Dict with keys: session_key, turn_count, since_iso, summarized,
        and either "summary" (str) or "messages" (list).
        On scope violation, returns {"error": <description>}.

    SECURITY:
    - Handler-level scope check restricts CalibrationAgent callers.
    - Trust level required: main.
    """
    if _transcript_store is None:
        raise RuntimeError(
            "TranscriptStore not configured. "
            "Call configure_transcript_store() before using session_lookup."
        )
    if agent_config is None:
        raise RuntimeError(
            "agent_config not injected. " "session_lookup must be called through the ToolExecutor."
        )

    caller_key = agent_config.session_key or ""
    is_calibration = caller_key.startswith("agent:main:heartbeat:")

    if is_calibration and session_key != "agent:main:main":
        if _audit_log is not None:
            await _audit_log.log(
                AuditEvent(
                    event="session_lookup_scope_violation",
                    agent_id=agent_config.agent_id,
                    session_key=caller_key,
                    details={
                        "reason": "CalibrationAgent may only read agent:main:main",
                        "requested_session_key": session_key,
                        "since_iso": since_iso,
                    },
                )
            )
        return {"error": "CalibrationAgent may only read agent:main:main"}

    if is_calibration:
        try:
            since_dt = datetime.fromisoformat(since_iso)
        except ValueError:
            return {"error": f"Invalid since_iso: {since_iso!r}"}
        if since_dt.tzinfo is None:
            since_dt = since_dt.replace(tzinfo=timezone.utc)
        cutoff = datetime.now(timezone.utc) - timedelta(hours=72)
        if since_dt < cutoff:
            if _audit_log is not None:
                await _audit_log.log(
                    AuditEvent(
                        event="session_lookup_scope_violation",
                        agent_id=agent_config.agent_id,
                        session_key=caller_key,
                        details={
                            "reason": "CalibrationAgent time window exceeded (max 72h)",
                            "requested_session_key": session_key,
                            "since_iso": since_iso,
                        },
                    )
                )
            return {"error": "CalibrationAgent time window exceeded (max 72h)"}

    messages = await _transcript_store.load_since(session_key, since_iso, max_turns)
    turn_count = len(messages)

    if _audit_log is not None:
        await _audit_log.log(
            AuditEvent(
                event="session_lookup_read",
                agent_id=agent_config.agent_id,
                session_key=caller_key,
                details={
                    "requester_session_key": caller_key,
                    "target_session_key": session_key,
                    "since_iso": since_iso,
                    "max_turns": max_turns,
                    "turn_count": turn_count,
                    "summarize": summarize,
                },
            )
        )

    if not summarize or not messages:
        return {
            "session_key": session_key,
            "turn_count": turn_count,
            "since_iso": since_iso,
            "messages": [m.model_dump() for m in messages],
            "summarized": False,
        }

    trace_id = uuid.uuid4().hex
    return await _maybe_summarize(messages, session_key, since_iso, trace_id, agent_config.agent_id)
