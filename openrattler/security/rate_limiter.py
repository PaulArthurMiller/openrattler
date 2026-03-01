"""In-memory sliding-window rate limiter.

Tracks request timestamps per key and enforces per-minute and per-hour limits.
All state is in-memory — no external dependencies.  This means limits reset on
process restart, which is acceptable for the current threat model.

SECURITY NOTES
--------------
- Cleans stale timestamps on every ``check`` / ``record`` call to prevent
  unbounded memory growth from many unique keys.
- Uses ``asyncio.Lock`` per key to prevent race conditions when multiple
  coroutines share the same rate-limiter instance.
- Keys are arbitrary strings; callers should use a stable, non-forgeable
  identifier such as an agent_id or session_key.
"""

from __future__ import annotations

import asyncio
from collections import defaultdict, deque
from datetime import datetime, timezone
from typing import Deque


class RateLimiter:
    """Sliding-window rate limiter (per-minute and per-hour).

    ``check`` returns ``True`` if the key is *within* the limits (request is
    allowed) and ``False`` if it would exceed them.  It does **not** record the
    request — call ``record`` afterwards to do that.

    This two-step design lets callers decide whether to proceed before
    incrementing the counter.

    Security notes:
    - Timestamps are in UTC to avoid daylight-saving edge cases.
    - Each key has its own asyncio.Lock to prevent data races under concurrent
      coroutines.
    - Stale timestamps older than one hour are pruned on every operation to
      bound memory growth.
    """

    def __init__(self, max_per_minute: int, max_per_hour: int) -> None:
        """Initialise the rate limiter.

        Args:
            max_per_minute: Maximum requests allowed in a rolling 60-second window.
            max_per_hour:   Maximum requests allowed in a rolling 3600-second window.

        Raises:
            ValueError: If limits are non-positive.
        """
        if max_per_minute <= 0:
            raise ValueError("max_per_minute must be a positive integer")
        if max_per_hour <= 0:
            raise ValueError("max_per_hour must be a positive integer")
        self._max_per_minute = max_per_minute
        self._max_per_hour = max_per_hour
        # Per-key deque of UTC timestamps (most-recent last).
        self._timestamps: dict[str, Deque[datetime]] = defaultdict(deque)
        # Per-key lock to serialise concurrent access.
        self._locks: dict[str, asyncio.Lock] = defaultdict(asyncio.Lock)

    async def check(self, key: str) -> bool:
        """Return ``True`` if *key* is within the rate limits, ``False`` otherwise.

        This is a read-only check — it does **not** count the request.  Call
        ``record`` to increment the counter after deciding to proceed.

        Args:
            key: Arbitrary identifier (e.g. agent_id, session_key).

        Returns:
            ``True``  → request may proceed.
            ``False`` → rate limit would be exceeded.
        """
        async with self._locks[key]:
            self._prune(key)
            ts = self._timestamps[key]
            now = datetime.now(timezone.utc)
            minute_count = sum(1 for t in ts if (now - t).total_seconds() < 60)
            if minute_count >= self._max_per_minute:
                return False
            # Hour count is just len(ts) after pruning (all are within 1 hour).
            if len(ts) >= self._max_per_hour:
                return False
            return True

    async def record(self, key: str) -> None:
        """Record one request for *key*.

        Appends the current UTC timestamp to the key's history.  Stale entries
        (older than one hour) are pruned first to keep memory bounded.

        Args:
            key: Arbitrary identifier matching the one passed to ``check``.
        """
        async with self._locks[key]:
            self._prune(key)
            self._timestamps[key].append(datetime.now(timezone.utc))

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _prune(self, key: str) -> None:
        """Remove timestamps older than one hour for *key*.

        Must be called while holding ``self._locks[key]``.
        """
        ts = self._timestamps[key]
        now = datetime.now(timezone.utc)
        while ts and (now - ts[0]).total_seconds() >= 3600:
            ts.popleft()
