"""Append-only JSONL store for per-turn token usage records.

One file for all sessions at ``log_path``.  Each line is a JSON-serialised
``TurnRecord``.  Concurrent writes are serialised with a single asyncio Lock.
All file I/O is offloaded to a thread pool via ``asyncio.to_thread`` so the
event loop is never blocked.
"""

from __future__ import annotations

import asyncio
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from openrattler.models.usage import TurnRecord


class UsageStore:
    """Append-only JSONL store for TurnRecord objects.

    Security notes:
    - ``log_path`` is set at construction time and never modified.
    - The file is opened in append mode for each write; no truncation is possible.
    - A single asyncio Lock serialises all writes to avoid interleaving.
    """

    def __init__(self, log_path: Path) -> None:
        """Initialise the store.

        Args:
            log_path: Path to ``usage_log.jsonl``. Parent directory is created
                      on first write if it does not yet exist.
        """
        self._path = log_path
        # Single lock for the whole file — records are short and writes are infrequent.
        self._lock = asyncio.Lock()

    # ------------------------------------------------------------------
    # Public async API
    # ------------------------------------------------------------------

    async def record_turn(self, record_data: dict[str, Any]) -> None:
        """Write one TurnRecord to the JSONL file.

        Assigns ``turn_number`` (1-indexed count of prior records for this
        session + 1) and sets ``recorded_at`` to the current UTC time.
        Callers should NOT include those two fields in ``record_data``.

        Args:
            record_data: Dict with all TurnRecord fields except ``turn_number``
                         and ``recorded_at``.
        """
        session_key: str = record_data["session_key"]
        turn_number = await self.count_for_session(session_key) + 1
        recorded_at = datetime.now(timezone.utc)

        full_data = {
            **record_data,
            "turn_number": turn_number,
            "recorded_at": recorded_at.isoformat(),
        }
        # Validate via the model before writing — catches missing/wrong-typed fields early.
        record = TurnRecord.model_validate(full_data)
        line = record.model_dump_json() + "\n"

        async with self._lock:
            await asyncio.to_thread(_sync_append, self._path, line)

    async def load_since(
        self,
        since: datetime,
        max_records: int = 10_000,
    ) -> list[TurnRecord]:
        """Load TurnRecords whose ``recorded_at`` >= *since*.

        Reads the full file then filters; acceptable for typical log sizes.
        Returns an empty list if the file does not exist.

        Args:
            since: Inclusive lower bound (UTC-aware or naive; naive treated as UTC).
            max_records: Cap on returned records (most-recent records kept when capping).
        """
        # Normalize naive datetime to UTC for safe comparison.
        if since.tzinfo is None:
            since = since.replace(tzinfo=timezone.utc)

        raw_lines: list[str] = await asyncio.to_thread(_sync_read_lines, self._path)
        records: list[TurnRecord] = []
        for line in raw_lines:
            try:
                record = TurnRecord.model_validate_json(line)
            except Exception:
                continue  # skip malformed lines
            if record.recorded_at >= since:
                records.append(record)

        if len(records) > max_records:
            records = records[-max_records:]
        return records

    async def count_for_session(self, session_key: str) -> int:
        """Count existing TurnRecords for *session_key*.

        Used internally to derive ``turn_number``.  Reads the full file on
        each call; an in-memory cache can be added if the file grows very large.
        """
        raw_lines: list[str] = await asyncio.to_thread(_sync_read_lines, self._path)
        count = 0
        for line in raw_lines:
            try:
                obj = json.loads(line)
            except json.JSONDecodeError:
                continue
            if obj.get("session_key") == session_key:
                count += 1
        return count


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
