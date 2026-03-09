"""ProcessorScheduler — runs ProactiveProcessor instances on a configurable schedule.

The scheduler accepts ``ProactiveProcessor`` instances, runs their
``run_cycle()`` at configured intervals, handles errors gracefully, and
optionally fires an urgent notification callback when ``immediate``-urgency
alerts are found after a cycle.

SCHEDULING MODEL
----------------
The scheduler ticks every ``_TICK_SECONDS`` seconds.  On each tick it checks
whether any registered processor is due to run (based on the configured
interval and the last-run timestamp) and, if so, calls ``run_cycle()``.

The scheduler itself does **not** enforce active hours — that responsibility
belongs to each processor's ``run_cycle()`` implementation.

ERROR HANDLING
--------------
- Processor errors never crash the scheduler: they are audit-logged and the
  loop continues to the next processor on the next tick.
- Cancellation (``stop()``) cleanly terminates the background asyncio task.

SECURITY NOTES
--------------
- The scheduler never forwards raw social content to any component.
- Urgent notification callbacks receive a structured ``UniversalMessage``;
  raw alert data is never passed directly.
- The scheduler's audit session key is always ``"scheduler:system"``.
"""

from __future__ import annotations

import asyncio
import logging
from datetime import datetime, timezone
from typing import TYPE_CHECKING, Any, Awaitable, Callable, Optional

from openrattler.models.audit import AuditEvent
from openrattler.models.messages import create_message
from openrattler.processors.base import ProactiveProcessor

if TYPE_CHECKING:
    from openrattler.storage.audit import AuditLog

logger = logging.getLogger(__name__)

#: How often the scheduler tick loop wakes to check processors.
_TICK_SECONDS: int = 60

#: Audit session key for all scheduler events.
_SCHEDULER_SESSION_KEY = "scheduler:system"

#: Agent ID used in scheduler audit events.
_SCHEDULER_AGENT_ID = "scheduler"


class ProcessorScheduler:
    """Runs ``ProactiveProcessor`` instances on a configurable schedule.

    Args:
        audit:            Optional audit log for cycle completion and error events.
        on_urgent_alert:  Optional async callback invoked with a
                          ``UniversalMessage`` when an ``immediate``-urgency
                          item is found in a processor's pending output after
                          a successful cycle.

    Security notes:
    - Processors are isolated from each other — an error in one does not
      affect the scheduling of others.
    - The urgent-alert callback receives only a structured ``UniversalMessage``
      built from safe, typed fields; raw alert content is never forwarded.
    - The scheduler does not gate on trust levels — that is each processor's
      responsibility.
    """

    def __init__(
        self,
        audit: Optional["AuditLog"] = None,
        on_urgent_alert: Optional[Callable[[Any], Awaitable[None]]] = None,
    ) -> None:
        self._processors: list[tuple[ProactiveProcessor, int]] = []
        self._last_run: dict[str, Optional[datetime]] = {}
        self._audit = audit
        self._on_urgent_alert = on_urgent_alert
        self._running: bool = False
        self._task: Optional[asyncio.Task[None]] = None

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def register_processor(self, processor: ProactiveProcessor, interval_minutes: int) -> None:
        """Register *processor* to run every *interval_minutes* minutes.

        Args:
            processor:        The ``ProactiveProcessor`` to schedule.
            interval_minutes: Minimum minutes between runs (clamped to ≥ 1).
        """
        interval_minutes = max(1, interval_minutes)
        self._processors.append((processor, interval_minutes))
        self._last_run[processor.processor_name] = None
        logger.info(
            "ProcessorScheduler: registered '%s' (interval=%d min)",
            processor.processor_name,
            interval_minutes,
        )

    async def start(self) -> None:
        """Start the scheduler loop as a background asyncio task.

        No-op if the scheduler is already running.
        """
        if self._running:
            logger.debug("ProcessorScheduler: already running — ignoring start()")
            return
        self._running = True
        self._task = asyncio.create_task(self._scheduler_loop())
        logger.info("ProcessorScheduler: started with %d processor(s)", len(self._processors))

    async def stop(self) -> None:
        """Stop the scheduler loop and wait for it to terminate."""
        self._running = False
        if self._task is not None:
            self._task.cancel()
            try:
                await self._task
            except asyncio.CancelledError:
                pass
            self._task = None
        logger.info("ProcessorScheduler: stopped")

    # ------------------------------------------------------------------
    # Scheduler loop
    # ------------------------------------------------------------------

    async def _scheduler_loop(self) -> None:
        """Main loop — check processors each tick and run those that are due."""
        while self._running:
            now = datetime.now(timezone.utc)
            for processor, interval_minutes in self._processors:
                last = self._last_run.get(processor.processor_name)
                elapsed = (now - last).total_seconds() if last is not None else float("inf")
                if elapsed >= interval_minutes * 60:
                    self._last_run[processor.processor_name] = now
                    await self._run_processor_cycle(processor)
            try:
                await asyncio.sleep(_TICK_SECONDS)
            except asyncio.CancelledError:
                break

    async def _run_processor_cycle(self, processor: ProactiveProcessor) -> None:
        """Execute one processor cycle with error handling and audit logging.

        After a successful cycle that produced output, checks for any
        ``immediate``-urgency items and fires the urgent notification callback.
        """
        try:
            count = await processor.run_cycle()
            logger.debug(
                "ProcessorScheduler: '%s' cycle complete — %d output(s)",
                processor.processor_name,
                count,
            )
            await self._audit_event(
                f"{processor.processor_name}_cycle_complete",
                alerts_generated=count,
            )
            if count > 0 and self._on_urgent_alert is not None:
                await self._dispatch_urgent_alerts(processor)
        except Exception as exc:
            logger.warning(
                "ProcessorScheduler: cycle error for '%s': %s",
                processor.processor_name,
                exc,
            )
            await self._audit_event(
                f"{processor.processor_name}_cycle_error",
                error=type(exc).__name__,
                message=str(exc)[:200],
            )

    async def _dispatch_urgent_alerts(self, processor: ProactiveProcessor) -> None:
        """Check pending output for ``immediate``-urgency items and call callback."""
        if self._on_urgent_alert is None:
            return
        try:
            pending = await processor.get_pending_output()
        except Exception:
            return
        for item in pending:
            if getattr(item, "urgency", None) == "immediate":
                msg = create_message(
                    from_agent=f"processor:{processor.processor_name}",
                    to_agent="agent:main:main",
                    session_key=_SCHEDULER_SESSION_KEY,
                    type="event",
                    operation="social_alert_urgent",
                    trust_level="main",
                    params={
                        "alert_id": getattr(item, "id", ""),
                        "summary": getattr(item, "summary", ""),
                        "event_type": getattr(item, "event_type", ""),
                        "person": getattr(item, "person", ""),
                    },
                )
                await self._on_urgent_alert(msg)

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    async def _audit_event(self, event: str, **details: Any) -> None:
        """Emit an audit event if an audit log is configured."""
        if self._audit is None:
            return
        await self._audit.log(
            AuditEvent(
                event=event,
                agent_id=_SCHEDULER_AGENT_ID,
                session_key=_SCHEDULER_SESSION_KEY,
                details=dict(details),
            )
        )
