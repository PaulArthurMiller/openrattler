"""Append-only JSONL store for SessionLifecycleEvent records.

One file for all sessions at the configured path.  Each line is a
JSON-serialised SessionLifecycleEvent.  Concurrent writes are serialised
with a single asyncio Lock; all file I/O runs in a thread pool so the
event loop is never blocked.

Usage:
    store = SessionLifecycleStore(Path("~/.openrattler/usage/session_lifecycle.jsonl"))
    await store.emit_open("agent:main:heartbeat:hb_...", "heartbeat")
    ...
    await store.emit_close("agent:main:heartbeat:hb_...", "completed",
                           total_prompt_tokens=1234, total_completion_tokens=200)
"""

from __future__ import annotations

import asyncio
import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from openrattler.models.session_lifecycle import SessionLifecycleEvent, infer_session_type

logger = logging.getLogger(__name__)


class SessionLifecycleStore:
    """Append-only JSONL store for session open/close events.

    Security notes:
    - ``log_path`` is set at construction and never modified.
    - File opened in append mode only; no truncation possible.
    - A single asyncio Lock serialises all writes.
    """

    def __init__(self, log_path: Path) -> None:
        self._path = log_path
        self._lock = asyncio.Lock()

    # ------------------------------------------------------------------
    # Public async API
    # ------------------------------------------------------------------

    async def emit_open(
        self,
        session_key: str,
        session_type: Optional[str] = None,
        parent_session_key: Optional[str] = None,
    ) -> None:
        """Append an open event for *session_key*.

        Args:
            session_key:        Identifies the session.
            session_type:       Semantic type; inferred from session_key if None.
            parent_session_key: Set for subagent sessions to link to parent.
        """
        resolved_type = session_type or infer_session_type(session_key)
        event = SessionLifecycleEvent(
            event_type="open",
            session_key=session_key,
            session_type=resolved_type,
            parent_session_key=parent_session_key,
            timestamp=datetime.now(timezone.utc),
        )
        await self._append(event)

    async def emit_close(
        self,
        session_key: str,
        close_reason: str,
        total_prompt_tokens: Optional[int] = None,
        total_completion_tokens: Optional[int] = None,
    ) -> None:
        """Append a close event for *session_key*.

        Duration is computed by reading the most recent open event's timestamp.

        Args:
            session_key:              Identifies the session being closed.
            close_reason:             "completed", "error", or "disconnect".
            total_prompt_tokens:      Accumulated prompt tokens for the session.
            total_completion_tokens:  Accumulated completion tokens.
        """
        open_event = await self.get_open_event(session_key)
        duration: Optional[float] = None
        if open_event is not None:
            duration = (datetime.now(timezone.utc) - open_event.timestamp).total_seconds()

        # Infer session_type from the key for consistency with open event.
        session_type = (
            open_event.session_type if open_event is not None else infer_session_type(session_key)
        )
        parent = open_event.parent_session_key if open_event is not None else None

        event = SessionLifecycleEvent(
            event_type="close",
            session_key=session_key,
            session_type=session_type,
            parent_session_key=parent,
            timestamp=datetime.now(timezone.utc),
            total_prompt_tokens=total_prompt_tokens,
            total_completion_tokens=total_completion_tokens,
            duration_seconds=duration,
            close_reason=close_reason,
        )
        await self._append(event)

    async def get_open_event(self, session_key: str) -> Optional[SessionLifecycleEvent]:
        """Return the most recent open event for *session_key*, or None."""
        events = await self._load_events_for_session(session_key)
        opens = [e for e in events if e.event_type == "open"]
        return opens[-1] if opens else None

    async def get_close_event(self, session_key: str) -> Optional[SessionLifecycleEvent]:
        """Return the most recent close event for *session_key*, or None."""
        events = await self._load_events_for_session(session_key)
        closes = [e for e in events if e.event_type == "close"]
        return closes[-1] if closes else None

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    async def _append(self, event: SessionLifecycleEvent) -> None:
        """Serialise *event* and append it to the JSONL file."""
        line = event.model_dump_json() + "\n"
        async with self._lock:
            await asyncio.to_thread(_sync_append, self._path, line)

    async def _load_events_for_session(self, session_key: str) -> list[SessionLifecycleEvent]:
        """Load all events matching *session_key* from the JSONL file."""
        raw_lines: list[str] = await asyncio.to_thread(_sync_read_lines, self._path)
        events: list[SessionLifecycleEvent] = []
        for line in raw_lines:
            try:
                event = SessionLifecycleEvent.model_validate_json(line)
            except Exception:
                continue
            if event.session_key == session_key:
                events.append(event)
        return events


# ---------------------------------------------------------------------------
# Synchronous file-I/O helpers (run inside asyncio.to_thread)
# ---------------------------------------------------------------------------


def _sync_append(path: Path, line: str) -> None:
    """Create parent directories and append *line* to *path*."""
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "a", encoding="utf-8") as fh:
        fh.write(line)


def _sync_read_lines(path: Path) -> list[str]:
    """Read all non-empty lines from a JSONL file.

    Returns an empty list if the file does not exist.
    """
    if not path.exists():
        return []
    with open(path, "r", encoding="utf-8") as fh:
        return [line for line in (ln.strip() for ln in fh) if line]
