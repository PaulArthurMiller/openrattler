"""Structured JSON memory store for agent persistent knowledge.

Each agent's memory lives in a single JSON file at
``{base_dir}/{agent_id}/memory.json``.  The file contains arbitrary
top-level keys (e.g. ``facts``, ``preferences``, ``instructions``) plus a
mandatory ``history`` list that records every approved change.

Writes are atomic: data is written to a ``.tmp`` file first, then renamed
over the target, so a crash mid-write never leaves a corrupt memory file.
All file I/O is offloaded to a thread pool via ``asyncio.to_thread``.
"""

from __future__ import annotations

import asyncio
import json
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

# ---------------------------------------------------------------------------
# Validation
# ---------------------------------------------------------------------------

_SAFE_AGENT_ID: re.Pattern[str] = re.compile(r"^[a-zA-Z0-9_-]+$")


def _validate_agent_id(agent_id: str) -> None:
    """Reject agent IDs that could cause path traversal or other attacks.

    Security notes:
    - Empty strings are rejected — they would resolve to the base directory.
    - ``..`` is the primary path-traversal vector; reject any ID containing it.
    - Absolute paths (starting with ``/`` or ``\\``) are rejected.
    - Only alphanumeric characters, hyphens, and underscores are permitted so
      that the ID maps safely to a filesystem directory name.
    """
    if not agent_id:
        raise ValueError("agent_id must not be empty")
    if ".." in agent_id:
        raise ValueError(f"agent_id must not contain '..': {agent_id!r}")
    if agent_id.startswith("/") or agent_id.startswith("\\"):
        raise ValueError(f"agent_id must not be an absolute path: {agent_id!r}")
    if not _SAFE_AGENT_ID.match(agent_id):
        raise ValueError(
            f"agent_id contains invalid characters (only alphanumeric, "
            f"hyphens, and underscores are allowed): {agent_id!r}"
        )


# ---------------------------------------------------------------------------
# Path helpers
# ---------------------------------------------------------------------------

_MEMORY_FILENAME = "memory.json"


def _agent_path(base_dir: Path, agent_id: str) -> Path:
    """Return the memory file path for *agent_id*."""
    return base_dir / agent_id / _MEMORY_FILENAME


# ---------------------------------------------------------------------------
# Diff helpers
# ---------------------------------------------------------------------------


def _compute_diff(current: dict[str, Any], proposed: dict[str, Any]) -> dict[str, Any]:
    """Compute a shallow diff between *current* and *proposed*.

    The ``history`` key is excluded from comparison because it is managed
    internally and always grows monotonically.

    Returns a dict with three keys:
    - ``added``:    keys present in *proposed* but absent from *current*
    - ``removed``:  keys present in *current* but absent from *proposed*
    - ``modified``: keys present in both with different values
                    (each entry is ``{"old": ..., "new": ...}``)
    """
    cur_keys = {k for k in current if k != "history"}
    pro_keys = {k for k in proposed if k != "history"}
    return {
        "added": {k: proposed[k] for k in pro_keys - cur_keys},
        "removed": {k: current[k] for k in cur_keys - pro_keys},
        "modified": {
            k: {"old": current[k], "new": proposed[k]}
            for k in cur_keys & pro_keys
            if current[k] != proposed[k]
        },
    }


def _describe_diff(diff: dict[str, Any]) -> str:
    """Return a human-readable one-line summary of *diff*."""
    parts: list[str] = []
    if diff["added"]:
        parts.append(f"added: {sorted(diff['added'].keys())}")
    if diff["removed"]:
        parts.append(f"removed: {sorted(diff['removed'].keys())}")
    if diff["modified"]:
        parts.append(f"modified: {sorted(diff['modified'].keys())}")
    return "; ".join(parts) if parts else "no changes"


# ---------------------------------------------------------------------------
# MemoryStore
# ---------------------------------------------------------------------------


class MemoryStore:
    """JSON memory store for agent persistent knowledge.

    One directory per agent; one ``memory.json`` file per agent.  Writes are
    atomic (temp-file + rename) to prevent corrupt state on crash.

    Security notes:
    - All ``agent_id`` arguments are validated before use to prevent path
      traversal attacks.
    - ``apply_changes`` never permits callers to overwrite the ``history``
      key directly — history entries are always appended by the store itself.
    - No delete or modify methods are provided for history; it is append-only.
    """

    def __init__(self, base_dir: Path) -> None:
        """Initialise the store.

        Args:
            base_dir: Root directory under which all agent memory directories
                      live.  Created on first write if it does not yet exist.
        """
        self._base = base_dir

    # ------------------------------------------------------------------
    # Public async API
    # ------------------------------------------------------------------

    async def load(self, agent_id: str) -> dict[str, Any]:
        """Load the memory dict for *agent_id*.

        Returns an empty dict if no memory file exists yet.
        """
        _validate_agent_id(agent_id)
        path = _agent_path(self._base, agent_id)
        return await asyncio.to_thread(_sync_load, path)

    async def save(self, agent_id: str, memory: dict[str, Any]) -> None:
        """Atomically persist *memory* for *agent_id*.

        Creates the agent directory if it does not exist.  Uses a
        temp-file + rename strategy so a crash mid-write never leaves a
        corrupt memory file.
        """
        _validate_agent_id(agent_id)
        path = _agent_path(self._base, agent_id)
        await asyncio.to_thread(_sync_save, path, memory)

    async def compute_diff(self, agent_id: str, proposed: dict[str, Any]) -> dict[str, Any]:
        """Compare the current on-disk memory for *agent_id* against *proposed*.

        Returns a dict with ``added``, ``removed``, and ``modified`` keys.
        The ``history`` key is excluded from comparison.
        """
        _validate_agent_id(agent_id)
        current = await self.load(agent_id)
        return _compute_diff(current, proposed)

    async def apply_changes(self, agent_id: str, changes: dict[str, Any], approved_by: str) -> bool:
        """Apply *changes* to the agent's memory and record a history entry.

        *changes* is a shallow map of top-level memory keys to their new
        values.  If *changes* contains the key ``"history"`` it is silently
        ignored — history is always managed by this method itself.

        A history entry recording the diff, ISO-format UTC timestamp, and
        *approved_by* identity is appended before saving.

        Returns ``True`` on success.

        Security notes:
        - Callers cannot directly overwrite the ``history`` key.
        - ``approved_by`` should reflect the actual authoriser (e.g.
          ``"user"``, ``"security_agent"``), not the requesting agent.
        """
        _validate_agent_id(agent_id)
        current = await self.load(agent_id)

        # Build updated memory; exclude 'history' from caller-supplied changes.
        updated: dict[str, Any] = dict(current)
        for key, value in changes.items():
            if key == "history":
                continue
            updated[key] = value

        # Compute diff before appending history, then record.
        diff = _compute_diff(current, updated)
        history: list[dict[str, Any]] = list(updated.get("history", []))
        history.append(
            {
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "change": _describe_diff(diff),
                "approved_by": approved_by,
            }
        )
        updated["history"] = history

        await self.save(agent_id, updated)
        return True


# ---------------------------------------------------------------------------
# Synchronous file-I/O helpers (run inside asyncio.to_thread)
# ---------------------------------------------------------------------------


def _sync_load(path: Path) -> dict[str, Any]:
    """Return the parsed memory dict from *path*, or ``{}`` if not found."""
    if not path.exists():
        return {}
    with open(path, "r", encoding="utf-8") as fh:
        return json.load(fh)  # type: ignore[no-any-return]


def _sync_save(path: Path, memory: dict[str, Any]) -> None:
    """Atomically write *memory* to *path* via a temp-file + rename.

    Security notes:
    - ``Path.replace()`` is used (not ``rename()``) so the operation succeeds
      on Windows even when the target already exists.
    - The temp file is cleaned up on any exception before the rename so
      interrupted writes never leave stale ``.tmp`` files indefinitely.
    """
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp_path = path.with_suffix(".tmp")
    try:
        with open(tmp_path, "w", encoding="utf-8") as fh:
            json.dump(memory, fh, indent=2, ensure_ascii=False)
            fh.flush()
        # replace() is atomic on POSIX; on Windows it atomically replaces
        # the target without requiring it to be absent first.
        tmp_path.replace(path)
    except Exception:
        try:
            tmp_path.unlink(missing_ok=True)
        except OSError:
            pass
        raise
