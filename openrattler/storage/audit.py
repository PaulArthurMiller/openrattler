"""Append-only JSONL audit log with optional HMAC tamper detection.

Every security-relevant event is appended as a single JSON line to the
log file.  When an HMAC key is supplied, each line is augmented with a
``_hmac`` field — a SHA-256 HMAC over the canonical form of the event
dict — so any post-write modification is detectable via
``verify_integrity()``.

All file I/O is offloaded to a thread pool via ``asyncio.to_thread`` and
a per-instance asyncio Lock serialises concurrent appends so lines are
never interleaved.
"""

from __future__ import annotations

import asyncio
import hashlib
import hmac as _hmac_mod
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

from openrattler.models.audit import AuditEvent

# ---------------------------------------------------------------------------
# HMAC helpers
# ---------------------------------------------------------------------------

_HMAC_FIELD = "_hmac"


def _canonical_bytes(d: dict[str, Any]) -> bytes:
    """Return a deterministic UTF-8 JSON encoding of *d* (keys sorted).

    ``sort_keys=True`` and compact separators ensure identical byte output
    regardless of dict insertion order — required for reproducible HMAC
    computation across write and verify phases.
    """
    return json.dumps(d, sort_keys=True, ensure_ascii=False, separators=(",", ":")).encode("utf-8")


def _sign(d: dict[str, Any], key: str) -> str:
    """Return the hex HMAC-SHA256 signature for *d* under *key*."""
    return _hmac_mod.new(key.encode("utf-8"), _canonical_bytes(d), hashlib.sha256).hexdigest()


def _verify(d: dict[str, Any], sig: str, key: str) -> bool:
    """Return True if *sig* matches the HMAC of *d* under *key*.

    Uses ``hmac.compare_digest`` to prevent timing-based side-channel attacks.
    """
    return _hmac_mod.compare_digest(_sign(d, key), sig)


# ---------------------------------------------------------------------------
# Line serialization helpers
# ---------------------------------------------------------------------------


def _serialize_event(event: AuditEvent, hmac_key: Optional[str]) -> str:
    """Serialize *event* to a JSON line, optionally with an HMAC signature.

    Without a key: ``model_dump_json()`` is used directly.
    With a key: the event dict is augmented with a ``_hmac`` field before
    serialization.  The HMAC is computed over the **unsigned** dict so that
    verification can recover the original values cleanly.
    """
    base: dict[str, Any] = event.model_dump(mode="json")
    if hmac_key is not None:
        sig = _sign(base, hmac_key)
        return json.dumps({**base, _HMAC_FIELD: sig}, ensure_ascii=False)
    return event.model_dump_json()


def _deserialize_line(line: str) -> AuditEvent:
    """Parse a JSON line into an AuditEvent, stripping any ``_hmac`` field."""
    d: dict[str, Any] = json.loads(line)
    d.pop(_HMAC_FIELD, None)
    return AuditEvent.model_validate(d)


# ---------------------------------------------------------------------------
# AuditLog
# ---------------------------------------------------------------------------


class AuditLog:
    """Append-only JSONL audit log with optional HMAC tamper detection.

    Security notes:
    - No delete, clear, or modify methods are exposed — the log is
      intentionally write-only after the fact.
    - When ``hmac_key`` is set, every line carries a ``_hmac`` field.
      ``verify_integrity()`` flags lines whose signatures do not match or
      that are missing a signature altogether (potential injection).
    - An ``asyncio.Lock`` serialises concurrent appends so no two
      coroutines can interleave writes to the same file.
    """

    def __init__(self, log_path: Path, hmac_key: Optional[str] = None) -> None:
        """Initialise the audit log.

        Args:
            log_path: Path to the JSONL log file.  Parent directories are
                      created on first write if they do not yet exist.
            hmac_key: Optional secret key for HMAC-SHA256 signing.  When
                      omitted events are written without signatures and
                      ``verify_integrity()`` returns ``(True, [])``
                      immediately.
        """
        self._path = log_path
        self._hmac_key = hmac_key
        self._lock = asyncio.Lock()

    # ------------------------------------------------------------------
    # Public async API
    # ------------------------------------------------------------------

    async def log(self, event: AuditEvent) -> None:
        """Append *event* as a single JSON line to the audit log.

        Creates the log file (and any parent directories) if they do not
        exist.  Concurrent calls are serialised by an asyncio Lock.
        """
        line = _serialize_event(event, self._hmac_key) + "\n"
        async with self._lock:
            await asyncio.to_thread(_sync_append, self._path, line)

    async def query(
        self,
        event_type: Optional[str] = None,
        since: Optional[datetime] = None,
        session_key: Optional[str] = None,
        trace_id: Optional[str] = None,
        limit: int = 100,
    ) -> list[AuditEvent]:
        """Return a filtered list of audit events.

        Reads the entire log from disk and applies the supplied filters.
        Returns the **last** ``limit`` matching events (most recent first
        within the returned slice, but in log order).

        Args:
            event_type:  Exact match on ``AuditEvent.event``.
            since:       Only events with ``timestamp >= since``.
            session_key: Exact match on ``AuditEvent.session_key``.
            trace_id:    Exact match on ``AuditEvent.trace_id``.
            limit:       Maximum number of events to return (>0).
        """
        lines = await asyncio.to_thread(_sync_read_lines, self._path)
        results: list[AuditEvent] = []
        for line in lines:
            try:
                ev = _deserialize_line(line)
            except Exception:
                continue
            if event_type is not None and ev.event != event_type:
                continue
            if since is not None and ev.timestamp < since:
                continue
            if session_key is not None and ev.session_key != session_key:
                continue
            if trace_id is not None and ev.trace_id != trace_id:
                continue
            results.append(ev)
        return results[-limit:] if limit > 0 else []

    async def verify_integrity(self) -> tuple[bool, list[int]]:
        """Verify HMAC signatures on all lines in the log.

        Returns ``(all_valid, bad_line_numbers)`` where *bad_line_numbers*
        is a sorted list of 1-indexed line numbers that either lack an
        ``_hmac`` field or whose signature does not verify.

        If no HMAC key is configured, returns ``(True, [])`` immediately.

        Security notes:
        - Lines missing ``_hmac`` are treated as bad when a key is set —
          they may represent lines injected after signing was enabled.
        - Signature comparison uses ``hmac.compare_digest`` to prevent
          timing-based side-channel attacks.
        """
        if self._hmac_key is None:
            return True, []

        lines = await asyncio.to_thread(_sync_read_lines, self._path)
        bad: list[int] = []
        for i, line in enumerate(lines, start=1):
            try:
                d: dict[str, Any] = json.loads(line)
            except Exception:
                bad.append(i)
                continue
            sig = d.pop(_HMAC_FIELD, None)
            if sig is None or not _verify(d, sig, self._hmac_key):
                bad.append(i)
        return len(bad) == 0, bad


# ---------------------------------------------------------------------------
# Synchronous file-I/O helpers (run inside asyncio.to_thread)
# ---------------------------------------------------------------------------


def _sync_append(path: Path, line: str) -> None:
    """Create parent directories and append *line* to *path*."""
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "a", encoding="utf-8") as fh:
        fh.write(line)


def _sync_read_lines(path: Path) -> list[str]:
    """Return all non-empty lines from *path*, or ``[]`` if not found."""
    if not path.exists():
        return []
    with open(path, "r", encoding="utf-8") as fh:
        return [line for line in (l.strip() for l in fh) if line]


# ---------------------------------------------------------------------------
# Module-level default log and convenience function
# ---------------------------------------------------------------------------

_default_log: Optional[AuditLog] = None


def configure_default_log(log: AuditLog) -> None:
    """Set the module-level default AuditLog used by ``audit_log()``.

    Call this once during application startup so that components can call
    ``audit_log()`` without threading an ``AuditLog`` instance everywhere.
    """
    global _default_log
    _default_log = log


async def audit_log(
    event: str,
    *,
    log: Optional[AuditLog] = None,
    session_key: Optional[str] = None,
    agent_id: Optional[str] = None,
    trace_id: Optional[str] = None,
    **details: Any,
) -> None:
    """Convenience coroutine: create an AuditEvent and append it.

    Uses *log* if provided; otherwise falls back to the module-level
    default configured via ``configure_default_log()``.  Silently does
    nothing if no log is configured — safe to call unconditionally.

    Usage::

        await audit_log("tool_call", session_key=sk, tool="file_read", result="ok")
        await audit_log("approval_requested", log=my_log, approval_id="abc123")
    """
    target = log or _default_log
    if target is None:
        return
    await target.log(
        AuditEvent(
            event=event,
            session_key=session_key,
            agent_id=agent_id,
            trace_id=trace_id,
            details=dict(details),
        )
    )
