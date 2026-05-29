"""Token usage tracking model for per-turn LLM cost instrumentation."""

from __future__ import annotations

from datetime import datetime
from typing import Optional

from pydantic import BaseModel, Field


class TurnRecord(BaseModel):
    """One record per agent runtime turn — captures token economy for reporting.

    Fields are written by UsageStore.record_turn(); callers pass a plain dict
    and the store handles turn_number assignment and recorded_at stamping.
    """

    recorded_at: datetime
    session_key: str
    agent_type: str  # "main" | "heartbeat" | "research" | "summarizer" | "unknown"
    channel: str  # "slack" | "email" | "heartbeat" | "cli" | "research" | "unknown"
    parent_session_key: Optional[str] = None
    trace_id: Optional[str] = None
    turn_number: int  # 1-indexed, assigned by UsageStore at write time
    model: str
    prompt_tokens: int
    completion_tokens: int
    total_tokens: int
    estimated_cost_usd: float
    llm_calls: int  # how many provider.complete() calls in this turn
    tool_calls: list[str] = Field(default_factory=list)
    tool_loops: int = 0


def infer_channel_and_agent(session_key: str) -> tuple[str, str]:
    """Return (channel, agent_type) inferred from the session_key format.

    Patterns:
      agent:main:heartbeat:* → ("heartbeat", "heartbeat")
      agent:main:slack:*     → ("slack", "main")
      agent:main:email:*     → ("email", "main")
      agent:main:main        → ("cli", "main")
      agent:research:*       → ("research", "research")
      agent:summarizer:*     → ("summarizer", "summarizer")
      everything else        → ("unknown", "unknown")
    """
    parts = session_key.split(":")
    if len(parts) < 3:
        return ("unknown", "unknown")

    # agent:main:heartbeat:... → parts[2] == "heartbeat"
    if parts[1] == "main" and len(parts) >= 3 and parts[2] == "heartbeat":
        return ("heartbeat", "heartbeat")

    if parts[1] == "main" and len(parts) >= 3:
        channel_part = parts[2]
        if channel_part == "slack":
            return ("slack", "main")
        if channel_part == "email":
            return ("email", "main")
        if channel_part == "main":
            return ("cli", "main")

    if parts[1] == "research":
        return ("research", "research")

    if parts[1] == "summarizer":
        return ("summarizer", "summarizer")

    return ("unknown", "unknown")
