"""HeartbeatLog — structured, prunable cross-cycle log for HeartbeatProcessor.

Each heartbeat cycle appends one ``HeartbeatLogEntry`` to
``{workspace}/identity/heartbeat_log.jsonl``.  The log is the sole source of
cross-cycle state injected into the LLM context window — session transcripts are
ephemeral and are never re-used across cycles.

DESIGN DECISIONS
----------------
- Atomic writes throughout: all mutations write to a ``.tmp`` sibling then
  ``os.replace``-rename so a crash mid-write never corrupts the existing file.
- ``max_context_entries`` (from ``HeartbeatConfig.log_context_entries``) controls
  *LLM injection size*; ``prune(keep)`` controls *disk retention*.  These two
  numbers are intentionally decoupled — the audit trail and the context window
  have different optimal sizes.
- ``predictions`` and ``outcomes`` fields are stubs in Build Piece 20.1.  They
  always default to empty lists but the schema is fixed so no migration is needed
  when CalibrationAgent extraction logic is wired in.

SECURITY NOTES
--------------
- ``heartbeat_log.jsonl`` is written only by HeartbeatProcessor — no agent tool
  has direct write access to this file.
- ``update_outcomes`` is the only mutation path for ``outcomes`` and is invoked
  only by HeartbeatProcessor (future: CalibrationAgent via HeartbeatProcessor).
- The context block injected into the system prompt is rendered as read-only
  markdown; it does not include raw tool call transcripts or session history.
"""

from __future__ import annotations

import json
import logging
import os
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

# Maximum characters for summary in table display (storage preserves full 120).
_TABLE_SUMMARY_MAX = 80


# ---------------------------------------------------------------------------
# HeartbeatLogEntry
# ---------------------------------------------------------------------------


@dataclass
class HeartbeatLogEntry:
    """One cycle's outcome, persisted in ``heartbeat_log.jsonl``.

    Fields:
        cycle_id:             Unique ID matching the per-cycle session key suffix.
                              Format: ``hb_{ISO8601_UTC}``.
        run_at:               ISO8601 UTC timestamp of the cycle start.
        urgency:              One of "low", "medium", "high", "immediate".
        flagged_topics:       Agent-generated topic labels from the cycle summary.
        delivered_to_user:    True if a HeartbeatOutput was emitted (urgency threshold met).
        summary:              One-sentence plain-text summary. Max 120 chars; truncated
                              at construction time with ellipsis — no exception raised.
        predictions:          Forward assertions for CalibrationAgent evaluation.
                              Each entry: {topic, predicted_urgency, predicted_action}.
                              Always [] until prediction extraction is wired in.
        outcomes:             Retrospective observations populated by a later cycle.
                              Each entry: {topic, observed, prediction_correct,
                              turns_to_resolution}.
                              Always [] until CalibrationAgent is wired in.
        calibration_applied:  False until CalibrationAgent is wired in.
    """

    cycle_id: str
    run_at: str
    urgency: str
    flagged_topics: list[str]
    delivered_to_user: bool
    summary: str
    predictions: list[dict[str, Any]] = field(default_factory=list)
    outcomes: list[dict[str, Any]] = field(default_factory=list)
    calibration_applied: bool = False

    def __post_init__(self) -> None:
        # Enforce 120-char summary cap with ellipsis — do not raise.
        if len(self.summary) > 120:
            self.summary = self.summary[:117] + "..."


# ---------------------------------------------------------------------------
# HeartbeatLog
# ---------------------------------------------------------------------------


class HeartbeatLog:
    """Reader/writer for ``heartbeat_log.jsonl``.

    Args:
        log_path:           Full path to the JSONL file.
        max_context_entries: How many recent entries are injected into the
                             heartbeat system prompt per cycle.  Does not affect
                             disk retention — see ``prune()``.
    """

    def __init__(self, log_path: Path, max_context_entries: int) -> None:
        self._log_path = log_path
        self._max_context_entries = max_context_entries

    # ------------------------------------------------------------------
    # Write operations (all atomic)
    # ------------------------------------------------------------------

    async def append(self, entry: HeartbeatLogEntry) -> None:
        """Append *entry* as a single JSON line.

        Creates the file (and any parent directories) if absent.
        Uses atomic write: new content → ``.tmp`` → ``os.replace``.
        """
        self._log_path.parent.mkdir(parents=True, exist_ok=True)
        existing = self._read_raw_lines()
        existing.append(json.dumps(asdict(entry)))
        self._atomic_write(existing)

    async def update_outcomes(self, cycle_id: str, outcomes: list[dict[str, Any]]) -> None:
        """Replace the ``outcomes`` field of the entry matching *cycle_id*.

        Uses atomic write.  Logs a WARNING and returns without raising if
        *cycle_id* is not found.
        """
        lines = self._read_raw_lines()
        updated = False
        new_lines: list[str] = []
        for line in lines:
            try:
                data = json.loads(line)
            except json.JSONDecodeError:
                new_lines.append(line)
                continue
            if data.get("cycle_id") == cycle_id:
                data["outcomes"] = outcomes
                new_lines.append(json.dumps(data))
                updated = True
            else:
                new_lines.append(line)

        if not updated:
            logger.warning("HeartbeatLog.update_outcomes: cycle_id %r not found — no-op", cycle_id)
            return

        self._atomic_write(new_lines)

    async def prune(self, keep: int) -> None:
        """Trim the log to the last *keep* entries.

        No-op if ``len(entries) <= keep``.  Uses atomic write.
        """
        lines = self._read_raw_lines()
        if len(lines) <= keep:
            return
        self._atomic_write(lines[-keep:])

    # ------------------------------------------------------------------
    # Read operations
    # ------------------------------------------------------------------

    async def read_recent(self, n: int) -> list[HeartbeatLogEntry]:
        """Return the last *n* entries in chronological order (oldest first).

        Returns an empty list if the file does not exist.
        Returns all entries if *n* > file length.
        """
        lines = self._read_raw_lines()
        if not lines:
            return []
        recent = lines[-n:] if n < len(lines) else lines
        entries: list[HeartbeatLogEntry] = []
        for line in recent:
            try:
                data = json.loads(line)
                entries.append(HeartbeatLogEntry(**data))
            except (json.JSONDecodeError, TypeError) as exc:
                logger.warning("HeartbeatLog: skipping malformed line: %s", exc)
        return entries

    # ------------------------------------------------------------------
    # Context block builder
    # ------------------------------------------------------------------

    def build_context_block(self, entries: list[HeartbeatLogEntry]) -> str:
        """Format *entries* as a compact markdown block for system prompt injection.

        Returns a minimal "no prior cycles recorded" string for an empty list
        so the injected content is never a broken table.

        Summary values are truncated to 80 chars in the table; the full 120-char
        value is preserved in storage.
        """
        if not entries:
            return "## Recent Heartbeat History\n\n" "_No prior cycles recorded._\n"

        n = len(entries)
        header = (
            f"## Recent Heartbeat History (last {n} cycle{'s' if n != 1 else ''})\n\n"
            "| Cycle | Urgency | Delivered | Predictions Pending Review | Topics | Summary |\n"
            "|-------|---------|-----------|---------------------------|--------|---------|"
        )
        rows: list[str] = []
        for e in entries:
            # Pending predictions: topics in predictions with no matching outcomes entry.
            resolved_topics = {o.get("topic") for o in e.outcomes}
            pending = [p["topic"] for p in e.predictions if p.get("topic") not in resolved_topics]
            pending_str = ", ".join(pending) if pending else "\u2014"

            topics_str = ", ".join(e.flagged_topics) if e.flagged_topics else "\u2014"
            delivered_str = "yes" if e.delivered_to_user else "no"

            # Truncate summary to 80 chars in table display.
            table_summary = e.summary
            if len(table_summary) > _TABLE_SUMMARY_MAX:
                table_summary = table_summary[: _TABLE_SUMMARY_MAX - 3] + "..."

            rows.append(
                f"| {e.cycle_id} | {e.urgency} | {delivered_str} | {pending_str} | {topics_str} | {table_summary} |"
            )

        return header + "\n" + "\n".join(rows) + "\n"

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _read_raw_lines(self) -> list[str]:
        """Read all non-empty lines from the log file.  Returns [] if absent."""
        if not self._log_path.exists():
            return []
        try:
            text = self._log_path.read_text(encoding="utf-8")
        except OSError as exc:
            logger.warning("HeartbeatLog: could not read log file: %s", exc)
            return []
        return [ln for ln in text.splitlines() if ln.strip()]

    def _atomic_write(self, lines: list[str]) -> None:
        """Write *lines* to the log file via a ``.tmp`` + ``os.replace`` swap."""
        tmp = self._log_path.with_suffix(self._log_path.suffix + ".tmp")
        content = "\n".join(lines) + ("\n" if lines else "")
        try:
            tmp.write_text(content, encoding="utf-8")
            os.replace(str(tmp), str(self._log_path))
        except Exception:
            try:
                tmp.unlink(missing_ok=True)
            except OSError:
                pass
            raise
