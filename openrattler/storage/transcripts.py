"""JSONL transcript storage for session conversation history.

Each session maps to one ``.jsonl`` file on disk.  Every message in the
conversation is appended as a single JSON line.  The session key is converted
to a relative directory path by replacing ``:`` with ``/``, so the file for
``agent:main:main`` lives at ``{base_dir}/agent/main/main.jsonl``.

Concurrent writes to the same session are serialised with a per-session
asyncio Lock.  All file I/O is offloaded to a thread pool via
``asyncio.to_thread`` so the event loop is never blocked.
"""

from __future__ import annotations

import asyncio
import re
from pathlib import Path

from openrattler.models.messages import UniversalMessage

# ---------------------------------------------------------------------------
# Validation
# ---------------------------------------------------------------------------

_SAFE_KEY: re.Pattern[str] = re.compile(r"^[a-zA-Z0-9_-]+(:[a-zA-Z0-9_-]+){2,}$")


def _validate_session_key(session_key: str) -> None:
    """Reject session keys that could cause path traversal or other attacks.

    Security notes:
    - ``..`` is the primary path-traversal vector; reject any key containing it.
    - Absolute paths (starting with ``/`` or ``\\``) are rejected.
    - Only alphanumeric characters, hyphens, underscores, and colons are
      permitted so that the key maps safely to a filesystem path.
    - Keys must start with ``agent:`` and have at least three colon-separated
      parts, matching the ``SessionKey`` format used throughout the system.
    """
    if ".." in session_key:
        raise ValueError(f"Session key must not contain '..': {session_key!r}")
    if session_key.startswith("/") or session_key.startswith("\\"):
        raise ValueError(f"Session key must not be an absolute path: {session_key!r}")
    if not session_key.startswith("agent:"):
        raise ValueError(f"Session key must start with 'agent:': {session_key!r}")
    if not _SAFE_KEY.match(session_key):
        raise ValueError(
            f"Session key contains invalid characters (only alphanumeric, "
            f"hyphens, underscores, and colons are allowed): {session_key!r}"
        )


# ---------------------------------------------------------------------------
# Path helpers
# ---------------------------------------------------------------------------

_JSONL_SUFFIX = ".jsonl"


def _key_to_path(base_dir: Path, session_key: str) -> Path:
    """Convert ``agent:main:main`` → ``{base_dir}/agent/main/main.jsonl``."""
    parts = session_key.split(":")
    # Build a relative path from the parts, then append the .jsonl suffix
    # to the last component.
    rel: Path = Path(parts[0])
    for part in parts[1:]:
        rel = rel / part
    return (base_dir / rel).with_suffix(_JSONL_SUFFIX)


def _path_to_key(base_dir: Path, path: Path) -> str:
    """Convert ``{base_dir}/agent/main/main.jsonl`` → ``agent:main:main``."""
    rel = path.relative_to(base_dir)
    parts = list(rel.parts)
    # Strip the .jsonl suffix from the last component
    last = parts[-1]
    if last.endswith(_JSONL_SUFFIX):
        parts[-1] = last[: -len(_JSONL_SUFFIX)]
    return ":".join(parts)


# ---------------------------------------------------------------------------
# TranscriptStore
# ---------------------------------------------------------------------------


class TranscriptStore:
    """Append-only JSONL store for session conversation transcripts.

    One file per session; one UniversalMessage per line.

    Security notes:
    - All ``session_key`` arguments are validated before use to prevent path
      traversal attacks.
    - Per-session asyncio Locks ensure no two coroutines interleave writes to
      the same file.
    """

    def __init__(self, base_dir: Path) -> None:
        """Initialise the store.

        Args:
            base_dir: Root directory under which all transcript files live.
                      Created on first write if it does not yet exist.
        """
        self._base = base_dir
        # Per-session-key asyncio Locks.  Dictionary access between awaits is
        # safe on a single-threaded event loop; no additional locking needed.
        self._locks: dict[str, asyncio.Lock] = {}

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _lock_for(self, session_key: str) -> asyncio.Lock:
        if session_key not in self._locks:
            self._locks[session_key] = asyncio.Lock()
        return self._locks[session_key]

    # ------------------------------------------------------------------
    # Public async API
    # ------------------------------------------------------------------

    async def append(self, session_key: str, message: UniversalMessage) -> None:
        """Append *message* as a single JSON line to the session transcript.

        Creates the transcript file (and any parent directories) if they do
        not exist.  Serialised per-session to prevent interleaved writes.
        """
        _validate_session_key(session_key)
        path = _key_to_path(self._base, session_key)
        line = message.model_dump_json() + "\n"

        async with self._lock_for(session_key):
            await asyncio.to_thread(_sync_append, path, line)

    async def load(self, session_key: str) -> list[UniversalMessage]:
        """Load and deserialise all messages for a session.

        Returns an empty list if the transcript does not exist.
        """
        _validate_session_key(session_key)
        path = _key_to_path(self._base, session_key)
        raw_lines: list[str] = await asyncio.to_thread(_sync_read_lines, path)
        return [UniversalMessage.model_validate_json(line) for line in raw_lines]

    async def load_recent(self, session_key: str, n: int) -> list[UniversalMessage]:
        """Return the last *n* messages for a session.

        Reads all lines from disk then takes the tail slice.  For the typical
        session transcript (hundreds of messages) this is fast enough; a
        backwards-seeking optimisation can be added if very large sessions
        become a concern.

        Returns an empty list if the transcript does not exist or *n* is 0.
        """
        _validate_session_key(session_key)
        if n <= 0:
            return []
        path = _key_to_path(self._base, session_key)
        raw_lines: list[str] = await asyncio.to_thread(_sync_read_lines, path)
        return [UniversalMessage.model_validate_json(line) for line in raw_lines[-n:]]

    async def exists(self, session_key: str) -> bool:
        """Return ``True`` if a transcript file exists for *session_key*."""
        _validate_session_key(session_key)
        path = _key_to_path(self._base, session_key)
        return await asyncio.to_thread(path.exists)

    async def list_sessions(self) -> list[str]:
        """Return a sorted list of all session keys that have transcripts on disk."""
        return await asyncio.to_thread(_sync_list_sessions, self._base)


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
        return [line for line in (l.strip() for l in fh) if line]


def _sync_list_sessions(base_dir: Path) -> list[str]:
    """Walk *base_dir* and return sorted session keys for every .jsonl file found."""
    if not base_dir.exists():
        return []
    return sorted(_path_to_key(base_dir, p) for p in base_dir.rglob(f"*{_JSONL_SUFFIX}"))
