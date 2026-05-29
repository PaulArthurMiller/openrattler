"""UsageReportProcessor — daily token economy report delivery via the scheduler.

Registered with ``ProcessorScheduler`` at a 24-hour interval.  On each cycle
it calls ``UsageReportDelivery.send_report()`` for the configured window.

Security notes:
- The processor never exposes raw session content; it only triggers the
  delivery layer which generates a summary of aggregate token counts.
- ``get_pending_output()`` always returns an empty list — the processor has
  no alerts to surface to the main agent.
"""

from __future__ import annotations

import logging
from datetime import datetime, timedelta, timezone
from typing import TYPE_CHECKING, Any

from openrattler.processors.base import ProactiveProcessor

if TYPE_CHECKING:
    from openrattler.reports.email_delivery import UsageReportDelivery

logger = logging.getLogger(__name__)


class UsageReportProcessor(ProactiveProcessor):
    """Scheduler-driven processor that emails a token usage report once per cycle.

    Args:
        delivery:             ``UsageReportDelivery`` that generates and sends the report.
        report_window_hours:  How many hours back the report window covers.
    """

    def __init__(
        self,
        delivery: "UsageReportDelivery",
        report_window_hours: int = 24,
    ) -> None:
        self._delivery = delivery
        self._report_window_hours = report_window_hours

    # ------------------------------------------------------------------
    # ProactiveProcessor interface
    # ------------------------------------------------------------------

    @property
    def processor_name(self) -> str:
        """Machine-readable name used by the scheduler for logging and audit."""
        return "usage_report"

    async def connect(self) -> None:
        """No external connections required."""

    async def disconnect(self) -> None:
        """No connections to release."""

    async def run_cycle(self) -> int:
        """Generate and email a usage report for the configured window.

        Returns:
            1 if the report was sent successfully, 0 otherwise.
        """
        since = datetime.now(timezone.utc) - timedelta(hours=self._report_window_hours)
        success = await self._delivery.send_report(since=since)
        if success:
            logger.info("UsageReportProcessor: daily report sent")
            return 1
        logger.info("UsageReportProcessor: report not sent (see delivery logs)")
        return 0

    async def get_pending_output(self) -> list[Any]:
        """No pending output — this processor does not produce alerts."""
        return []
