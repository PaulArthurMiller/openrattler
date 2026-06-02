"""Token economy report generator.

Reads TurnRecords from UsageStore, groups them into per-session summaries,
detects context accumulation, and produces a plain-text email report.

Session status is tri-state (piece 46.1):
  closed         — a close event exists in SessionLifecycleStore
  active         — no close event, last_turn_at is recent (within staleness_window_minutes)
  stale_unclosed — no close event, last_turn_at is old
"""

from __future__ import annotations

import math
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import TYPE_CHECKING, Literal, Optional

from openrattler import __version__
from openrattler.models.session_lifecycle import infer_session_type
from openrattler.models.usage import TurnRecord
from openrattler.storage.usage import UsageStore

if TYPE_CHECKING:
    from openrattler.storage.session_lifecycle import SessionLifecycleStore

# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------


@dataclass
class SessionSummary:
    """Aggregated view of all TurnRecords for one session."""

    session_key: str
    agent_type: str
    channel: str
    parent_session_key: Optional[str]
    first_turn_at: datetime
    last_turn_at: datetime
    turns: int
    total_prompt_tokens: int
    total_completion_tokens: int
    total_tokens: int
    total_cost_usd: float
    models_used: list[str]  # deduplicated, insertion-ordered
    tool_calls: dict[str, int]  # {tool_name: count}
    prompt_tokens_per_turn: list[int]  # ordered by turn_number for growth analysis
    session_status: Literal["closed", "active", "stale_unclosed"] = "active"
    session_type: str = "unknown"  # derived from session_key via infer_session_type()


# ---------------------------------------------------------------------------
# Generator
# ---------------------------------------------------------------------------


class UsageReportGenerator:
    """Reads TurnRecords and renders a plain-text usage report."""

    def __init__(
        self,
        usage_store: UsageStore,
        idle_timeout_minutes: int = 60,
        context_growth_warning_pct: float = 500.0,
        lifecycle_store: Optional["SessionLifecycleStore"] = None,
        staleness_window_minutes: int = 30,
    ) -> None:
        self._store = usage_store
        self._idle_timeout_minutes = idle_timeout_minutes
        self._context_growth_warning_pct = context_growth_warning_pct
        self._lifecycle_store = lifecycle_store
        self._staleness_window_minutes = staleness_window_minutes

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    async def generate(
        self,
        since: Optional[datetime] = None,
        until: Optional[datetime] = None,
    ) -> str:
        """Generate a plain-text report for the given time window.

        Args:
            since: Inclusive start of window. Defaults to 24 hours ago.
            until: Inclusive end of window. Defaults to now.

        Returns:
            Formatted plain-text report string.
        """
        now = datetime.now(timezone.utc)
        if since is None:
            since = now - timedelta(hours=24)
        if until is None:
            until = now

        records = await self._store.load_since(since)
        # Apply upper bound filter (load_since only filters by lower bound).
        records = [r for r in records if r.recorded_at <= until]

        sessions = await self._build_session_summaries(records, now)
        return self._format_report(sessions, since, until, now)

    # ------------------------------------------------------------------
    # Session aggregation
    # ------------------------------------------------------------------

    async def _build_session_summaries(
        self,
        records: list[TurnRecord],
        now: datetime,
    ) -> list[SessionSummary]:
        """Group TurnRecords by session_key and build SessionSummary objects."""
        # Collect records per session in turn_number order.
        per_session: dict[str, list[TurnRecord]] = {}
        for rec in records:
            per_session.setdefault(rec.session_key, []).append(rec)

        # Sort each session's records by turn_number so prompt_tokens_per_turn
        # is ordered chronologically.
        for key in per_session:
            per_session[key].sort(key=lambda r: r.turn_number)

        summaries: list[SessionSummary] = []
        for session_key, recs in per_session.items():
            summaries.append(await self._summarize_session(session_key, recs, now))

        return summaries

    async def _summarize_session(
        self,
        session_key: str,
        recs: list[TurnRecord],
        now: datetime,
    ) -> SessionSummary:
        """Build one SessionSummary from a list of TurnRecords for a session."""
        first = recs[0]
        last = recs[-1]

        # Deduplicate models preserving first-seen order.
        seen_models: dict[str, None] = {}
        for r in recs:
            seen_models[r.model] = None

        # Aggregate tool call counts.
        tool_counts: dict[str, int] = {}
        for r in recs:
            for tool_name in r.tool_calls:
                tool_counts[tool_name] = tool_counts.get(tool_name, 0) + 1

        status = await self._get_session_status(session_key, last.recorded_at, now)

        return SessionSummary(
            session_key=session_key,
            agent_type=first.agent_type,
            channel=first.channel,
            parent_session_key=first.parent_session_key,
            first_turn_at=first.recorded_at,
            last_turn_at=last.recorded_at,
            turns=len(recs),
            total_prompt_tokens=sum(r.prompt_tokens for r in recs),
            total_completion_tokens=sum(r.completion_tokens for r in recs),
            total_tokens=sum(r.total_tokens for r in recs),
            total_cost_usd=sum(r.estimated_cost_usd for r in recs),
            models_used=list(seen_models.keys()),
            tool_calls=tool_counts,
            prompt_tokens_per_turn=[r.prompt_tokens for r in recs],
            session_status=status,
            session_type=infer_session_type(session_key),
        )

    # ------------------------------------------------------------------
    # Helper computations
    # ------------------------------------------------------------------

    async def _get_session_status(
        self,
        session_key: str,
        last_turn_at: datetime,
        now: datetime,
    ) -> Literal["closed", "active", "stale_unclosed"]:
        """Return tri-state session status.

        closed         — a close event exists in the lifecycle store
        active         — no close event, last_turn_at within staleness_window_minutes
        stale_unclosed — no close event, last_turn_at older than staleness_window_minutes
        """
        if self._lifecycle_store is not None:
            try:
                close_evt = await self._lifecycle_store.get_close_event(session_key)
                if close_evt is not None:
                    return "closed"
            except Exception:
                pass  # lifecycle store unavailable — fall through to heuristic

        # No close event found (or no lifecycle store) — use recency heuristic.
        delta = now - last_turn_at
        if delta < timedelta(minutes=self._staleness_window_minutes):
            return "active"
        return "stale_unclosed"

    def _context_growth_pct(self, per_turn: list[int]) -> Optional[float]:
        """Return percentage growth from first to last prompt_token value.

        Returns None when there are fewer than 2 turns or the first value is 0.
        """
        if len(per_turn) < 2 or per_turn[0] == 0:
            return None
        return (per_turn[-1] - per_turn[0]) / per_turn[0] * 100.0

    # ------------------------------------------------------------------
    # Formatting helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _format_bar(pct: float, width: int = 20) -> str:
        """ASCII progress bar representing *pct* percentage (0-100).

        Returns filled blocks proportional to the percentage, padded to *width*.
        """
        filled = min(width, math.ceil(pct / 100.0 * width))
        empty = width - filled
        return "█" * filled + "░" * empty

    @staticmethod
    def _format_tool_summary(tool_calls: dict[str, int]) -> str:
        """Render tool call counts as a compact summary string.

        Example: send_email×2, memory_read×5, research_query×1
        """
        if not tool_calls:
            return "(none)"
        parts = []
        for name, count in sorted(tool_calls.items()):
            parts.append(f"{name}×{count}" if count > 1 else name)
        return ", ".join(parts)

    @staticmethod
    def _fmt_tokens(n: int) -> str:
        """Format token count as abbreviated string (e.g. 1,234 or 12.3K)."""
        if n < 10_000:
            return f"{n:,}"
        return f"{n / 1000:.1f}K"

    @staticmethod
    def _fmt_time(dt: datetime) -> str:
        """Format a UTC datetime for display in the report."""
        return dt.strftime("%Y-%m-%d %H:%M UTC")

    @staticmethod
    def _relative_time(dt: datetime, now: datetime) -> str:
        """Return a human-friendly relative time description."""
        delta = now - dt
        minutes = int(delta.total_seconds() / 60)
        if minutes < 1:
            return "just now"
        if minutes < 60:
            return f"~{minutes} min ago"
        hours = minutes // 60
        if hours < 24:
            return f"~{hours}h ago"
        days = hours // 24
        return f"~{days}d ago"

    # ------------------------------------------------------------------
    # Report formatting
    # ------------------------------------------------------------------

    def _format_report(
        self,
        sessions: list[SessionSummary],
        since: datetime,
        until: datetime,
        now: datetime,
    ) -> str:
        """Render the full plain-text report."""
        lines: list[str] = []

        # Title box
        window_str = (
            f"{since.strftime('%Y-%m-%d %H:%M UTC')} → " f"{until.strftime('%Y-%m-%d %H:%M UTC')}"
        )
        hours = int((until - since).total_seconds() / 3600)
        lines.append("╔" + "═" * 74 + "╗")
        lines.append("║" + "           OPENRATTLER TOKEN ECONOMY REPORT".center(74) + "║")
        lines.append("║" + f"           {window_str} ({hours}h)".center(74) + "║")
        lines.append("╚" + "═" * 74 + "╝")
        lines.append("")

        if not sessions:
            lines.append("No sessions in this window.")
            lines.append("")
            lines.append(f"GENERATED: {self._fmt_time(now)} | " f"OpenRattler v{__version__}")
            return "\n".join(lines)

        # Aggregate totals
        total_cost = sum(s.total_cost_usd for s in sessions)
        total_tokens = sum(s.total_tokens for s in sessions)
        active = [s for s in sessions if s.session_status == "active"]
        closed = [s for s in sessions if s.session_status == "closed"]
        stale = [s for s in sessions if s.session_status == "stale_unclosed"]

        # Subtotals by session_type
        type_counts: dict[str, int] = {}
        type_costs: dict[str, float] = {}
        for s in sessions:
            type_counts[s.session_type] = type_counts.get(s.session_type, 0) + 1
            type_costs[s.session_type] = type_costs.get(s.session_type, 0.0) + s.total_cost_usd

        # SUMMARY
        lines.append("SUMMARY")
        lines.append("─" * 52)
        lines.append(f"  Total estimated cost:   ${total_cost:.3f}")
        lines.append(f"  Total tokens:           {total_tokens:,}")
        lines.append(f"  Active sessions:        {len(active)}")
        lines.append(f"  Closed sessions:        {len(closed)}")
        lines.append(f"  Stale/unclosed:         {len(stale)}")
        lines.append("")

        # SESSION TYPE BREAKDOWN
        if type_counts:
            lines.append("SESSIONS BY TYPE")
            lines.append("─" * 52)
            for stype, count in sorted(type_counts.items()):
                cost = type_costs.get(stype, 0.0)
                lines.append(f"  {stype:<20} {count:>3} sessions  ${cost:.3f}")
            lines.append("")

        # COST BY CHANNEL
        channel_costs: dict[str, float] = {}
        for s in sessions:
            channel_costs[s.channel] = channel_costs.get(s.channel, 0.0) + s.total_cost_usd
        sorted_channels = sorted(channel_costs.items(), key=lambda x: x[1], reverse=True)

        lines.append(f"COST BY CHANNEL ({hours}h)")
        lines.append("─" * 52)
        for ch, cost in sorted_channels:
            pct = (cost / total_cost * 100) if total_cost > 0 else 0.0
            bar = self._format_bar(pct)
            lines.append(f"  {ch:<12} ${cost:.3f}  {pct:3.0f}%  {bar}")
        lines.append("")

        # COST BY AGENT TYPE
        agent_costs: dict[str, float] = {}
        for s in sessions:
            agent_costs[s.agent_type] = agent_costs.get(s.agent_type, 0.0) + s.total_cost_usd
        sorted_agents = sorted(agent_costs.items(), key=lambda x: x[1], reverse=True)

        lines.append(f"COST BY AGENT TYPE ({hours}h)")
        lines.append("─" * 52)
        for agent, cost in sorted_agents:
            pct = (cost / total_cost * 100) if total_cost > 0 else 0.0
            lines.append(f"  {agent:<14} ${cost:.3f}  {pct:3.0f}%")
        lines.append("")

        # Partition: research sub-sessions vs top-level sessions
        top_level = [s for s in sessions if s.parent_session_key is None]
        sub_sessions: dict[str, list[SessionSummary]] = {}
        for s in sessions:
            if s.parent_session_key is not None:
                sub_sessions.setdefault(s.parent_session_key, []).append(s)

        # ACTIVE SESSIONS
        active_top = [s for s in top_level if s.session_status == "active"]
        lines.append("─" * 53)
        lines.append(
            f"ACTIVE SESSIONS (last turn within {self._staleness_window_minutes} min, no close event)"
        )
        lines.append("─" * 53)
        if not active_top:
            lines.append("  (none)")
        else:
            for s in active_top:
                lines.extend(self._format_session_block(s, sub_sessions, now, indent=""))
        lines.append("")

        # CLOSED SESSIONS
        closed_top = sorted(
            [s for s in top_level if s.session_status == "closed"],
            key=lambda s: s.last_turn_at,
            reverse=True,
        )
        lines.append("─" * 52)
        lines.append("CLOSED SESSIONS (close event received, most recent first)")
        lines.append("─" * 52)
        if not closed_top:
            lines.append("  (none)")
        else:
            for s in closed_top:
                lines.extend(self._format_session_block(s, sub_sessions, now, indent=""))
        lines.append("")

        # STALE / UNCLOSED SESSIONS
        stale_top = sorted(
            [s for s in top_level if s.session_status == "stale_unclosed"],
            key=lambda s: s.last_turn_at,
            reverse=True,
        )
        lines.append("─" * 53)
        lines.append(
            f"STALE / UNCLOSED SESSIONS (no close event, last turn "
            f">{ self._staleness_window_minutes} min ago)"
        )
        lines.append("─" * 53)
        if not stale_top:
            lines.append("  (none)")
        else:
            for s in stale_top:
                lines.extend(self._format_session_block(s, sub_sessions, now, indent=""))
        lines.append("")

        # CONTEXT ACCUMULATION WARNINGS
        warnings = [
            s
            for s in top_level
            if (
                (g := self._context_growth_pct(s.prompt_tokens_per_turn)) is not None
                and g > self._context_growth_warning_pct
            )
        ]
        lines.append("─" * 53)
        lines.append(
            f"CONTEXT ACCUMULATION WARNINGS (sessions with "
            f">{self._context_growth_warning_pct:.0f}% growth)"
        )
        lines.append("─" * 53)
        if not warnings:
            lines.append("  (none)")
        else:
            for i, s in enumerate(warnings, 1):
                growth = self._context_growth_pct(s.prompt_tokens_per_turn) or 0.0
                first_tok = self._fmt_tokens(s.prompt_tokens_per_turn[0])
                last_tok = self._fmt_tokens(s.prompt_tokens_per_turn[-1])
                status = s.session_status
                lines.append(f"  {i}. {s.session_key} ({status})")
                lines.append(
                    f"     Prompt tokens: {first_tok} → {last_tok} | "
                    f"Growth: {growth:.0f}% | {s.turns} turns | "
                    f"Cost: ${s.total_cost_usd:.3f}"
                )
        lines.append("")

        lines.append("─" * 53)
        lines.append(f"GENERATED: {self._fmt_time(now)} | " f"OpenRattler v{__version__}")

        return "\n".join(lines)

    def _format_session_block(
        self,
        s: SessionSummary,
        sub_sessions: dict[str, list[SessionSummary]],
        now: datetime,
        indent: str,
    ) -> list[str]:
        """Render one session block including context growth and sub-sessions."""
        lines: list[str] = []
        growth = self._context_growth_pct(s.prompt_tokens_per_turn)
        model_str = ", ".join(s.models_used) if s.models_used else "unknown"
        last_rel = self._relative_time(s.last_turn_at, now)
        if s.session_status == "active":
            status_suffix = f" | Last active: {self._fmt_time(s.last_turn_at)} ({last_rel})"
        elif s.session_status == "closed":
            status_suffix = f" | Closed: {self._fmt_time(s.last_turn_at)}"
        else:
            status_suffix = f" | Stale/unclosed: {self._fmt_time(s.last_turn_at)} ({last_rel})"

        lines.append("")
        lines.append(f"{indent}  {s.session_key} | Channel: {s.channel} | Model: {model_str}")
        lines.append(f"{indent}  Started: {self._fmt_time(s.first_turn_at)}{status_suffix}")
        lines.append(
            f"{indent}  Turns: {s.turns} | "
            f"Total tokens: {s.total_tokens:,} | "
            f"Cost: ${s.total_cost_usd:.3f}"
        )
        if s.tool_calls:
            lines.append(f"{indent}  Tools: {self._format_tool_summary(s.tool_calls)}")

        # Context accumulation warning inline with session
        if growth is not None and growth > self._context_growth_warning_pct:
            turns_str = " → ".join(self._fmt_tokens(t) for t in s.prompt_tokens_per_turn)
            lines.append("")
            lines.append(f"{indent}  ⚠ CONTEXT ACCUMULATION DETECTED")
            lines.append(f"{indent}    Prompt tokens per turn: {turns_str}")
            lines.append(
                f"{indent}    Growth: {growth:.0f}% over {s.turns} turns. "
                "This session is accumulating context rapidly."
            )
            lines.append(
                f"{indent}    Consider: session timeout, context summarization, "
                "or manual session reset."
            )
        elif (
            growth is not None and growth > self._context_growth_warning_pct * 0.5 and s.turns >= 3
        ):
            # Moderate growth note (>50% of warning threshold) — show in non-active sessions
            lines.append(
                f"{indent}  Prompt tokens per turn: "
                + " → ".join(self._fmt_tokens(t) for t in s.prompt_tokens_per_turn)
            )
            lines.append(
                f"{indent}  ⚠ Moderate context growth ({growth:.0f}% " f"over {s.turns} turns)"
            )

        # Sub-sessions (research, summarizer)
        children = sub_sessions.get(s.session_key, [])
        for child in sorted(children, key=lambda c: c.first_turn_at):
            child_model = ", ".join(child.models_used) if child.models_used else "unknown"
            lines.append(
                f"{indent}  └─ Sub-session: {child.agent_type} "
                f"| {self._fmt_time(child.first_turn_at)}"
            )
            lines.append(
                f"{indent}       Turns: {child.turns} | "
                f"Tokens: {child.total_tokens:,} | "
                f"Cost: ${child.total_cost_usd:.3f} | "
                f"Model: {child_model}"
            )
            if child.tool_calls:
                lines.append(f"{indent}       Tools: {self._format_tool_summary(child.tool_calls)}")

        return lines
