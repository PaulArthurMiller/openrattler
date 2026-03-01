"""Tests for RateLimiter — sliding-window in-memory rate limiting."""

from __future__ import annotations

import asyncio
from datetime import datetime, timedelta, timezone
from unittest.mock import patch

import pytest

from openrattler.security.rate_limiter import RateLimiter

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _past(seconds: int) -> datetime:
    """Return a UTC datetime *seconds* in the past."""
    return datetime.now(timezone.utc) - timedelta(seconds=seconds)


# ---------------------------------------------------------------------------
# Constructor validation
# ---------------------------------------------------------------------------


class TestRateLimiterInit:
    def test_rejects_zero_per_minute(self) -> None:
        with pytest.raises(ValueError, match="max_per_minute"):
            RateLimiter(max_per_minute=0, max_per_hour=100)

    def test_rejects_negative_per_hour(self) -> None:
        with pytest.raises(ValueError, match="max_per_hour"):
            RateLimiter(max_per_minute=10, max_per_hour=-1)


# ---------------------------------------------------------------------------
# Within-limit requests pass
# ---------------------------------------------------------------------------


class TestWithinLimits:
    async def test_single_request_passes(self) -> None:
        rl = RateLimiter(max_per_minute=5, max_per_hour=20)
        assert await rl.check("agent-1") is True

    async def test_up_to_limit_passes(self) -> None:
        rl = RateLimiter(max_per_minute=3, max_per_hour=20)
        for _ in range(3):
            assert await rl.check("agent-1") is True
            await rl.record("agent-1")

    async def test_different_keys_are_independent(self) -> None:
        rl = RateLimiter(max_per_minute=1, max_per_hour=10)
        await rl.record("agent-a")
        # agent-a is at the limit but agent-b should still pass
        assert await rl.check("agent-a") is False
        assert await rl.check("agent-b") is True

    async def test_check_does_not_increment_counter(self) -> None:
        rl = RateLimiter(max_per_minute=1, max_per_hour=10)
        # Calling check multiple times without record should not exhaust the limit
        for _ in range(5):
            assert await rl.check("agent-1") is True


# ---------------------------------------------------------------------------
# Per-minute limit enforcement
# ---------------------------------------------------------------------------


class TestPerMinuteLimit:
    async def test_exceeding_per_minute_limit_fails(self) -> None:
        rl = RateLimiter(max_per_minute=2, max_per_hour=100)
        await rl.record("agent-1")
        await rl.record("agent-1")
        assert await rl.check("agent-1") is False

    async def test_old_timestamps_not_counted_in_minute_window(self) -> None:
        """Timestamps older than 60 s do not count toward the per-minute cap."""
        rl = RateLimiter(max_per_minute=2, max_per_hour=100)
        # Manually inject two timestamps that are 90 s old (outside the minute window)
        rl._timestamps["agent-1"].append(_past(90))
        rl._timestamps["agent-1"].append(_past(90))
        # Should pass because those old entries don't count toward per-minute
        assert await rl.check("agent-1") is True

    async def test_recent_timestamps_counted_in_minute_window(self) -> None:
        rl = RateLimiter(max_per_minute=2, max_per_hour=100)
        rl._timestamps["agent-1"].append(_past(30))
        rl._timestamps["agent-1"].append(_past(30))
        assert await rl.check("agent-1") is False


# ---------------------------------------------------------------------------
# Per-hour limit enforcement
# ---------------------------------------------------------------------------


class TestPerHourLimit:
    async def test_exceeding_per_hour_limit_fails(self) -> None:
        rl = RateLimiter(max_per_minute=100, max_per_hour=3)
        await rl.record("agent-1")
        await rl.record("agent-1")
        await rl.record("agent-1")
        assert await rl.check("agent-1") is False

    async def test_old_timestamps_pruned_before_hour_count(self) -> None:
        """Timestamps older than 1 hour are pruned and don't count toward hourly cap."""
        rl = RateLimiter(max_per_minute=100, max_per_hour=3)
        # Inject 3 timestamps that are 3601 s old — outside the hour window
        for _ in range(3):
            rl._timestamps["agent-1"].append(_past(3601))
        # After pruning, count should be 0 — request should pass
        assert await rl.check("agent-1") is True

    async def test_within_hour_timestamps_counted(self) -> None:
        rl = RateLimiter(max_per_minute=100, max_per_hour=3)
        for _ in range(3):
            rl._timestamps["agent-1"].append(_past(1800))  # 30 min ago
        assert await rl.check("agent-1") is False


# ---------------------------------------------------------------------------
# Concurrent access
# ---------------------------------------------------------------------------


class TestConcurrentAccess:
    async def test_concurrent_records_are_serialised(self) -> None:
        """100 concurrent record calls should not corrupt the deque."""
        rl = RateLimiter(max_per_minute=200, max_per_hour=200)
        await asyncio.gather(*[rl.record("agent-1") for _ in range(100)])
        assert len(rl._timestamps["agent-1"]) == 100
