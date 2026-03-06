"""ProactiveProcessor — abstract base class for scheduler-driven processors.

Proactive processors differ from channel agents in a fundamental way:

- **Channel agents** are reactive — they wait for an inbound message, process
  it, and return a response.
- **Proactive processors** are scheduler-driven — they wake up on a timer,
  pull data from external sources, evaluate it, and produce structured output
  that main can consume at the appropriate moment.

All proactive processors share the same lifecycle:

1. ``connect()``         — establish external connections
2. ``run_cycle()``       — execute one processing cycle (called on schedule)
3. ``get_pending_output()`` — expose results for main to consume
4. ``disconnect()``      — clean up connections

Security notes
--------------
- Proactive processors NEVER communicate with the user directly.  Output is
  written to a structured store (e.g. alerts.json) and surfaced by main at an
  appropriate time.
- Each processor has a restricted tool allowlist — no access to email, files
  outside its own workspace, or session channels.
- Processing cycles are bounded (``run_cycle`` is not allowed to loop forever).
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any


class ProactiveProcessor(ABC):
    """Scheduler-driven processor that observes external data and produces output.

    Subclasses implement the four abstract methods to define what data is
    consumed, how it is evaluated, and what structured output is produced.
    """

    @property
    @abstractmethod
    def processor_name(self) -> str:
        """Short machine-readable name for this processor (e.g. 'social_secretary')."""
        ...

    @abstractmethod
    async def connect(self) -> None:
        """Establish external connections required for processing.

        Called once before the first ``run_cycle`` call.  Should validate that
        required MCP servers or other dependencies are reachable.

        Raises:
            ConnectionError: If a required dependency cannot be reached.
        """
        ...

    @abstractmethod
    async def disconnect(self) -> None:
        """Release external connections and clean up resources.

        Safe to call even if ``connect()`` was never called or failed.
        """
        ...

    @abstractmethod
    async def run_cycle(self) -> int:
        """Execute one processing cycle.

        The cycle should:
        1. Check whether the processor is in its active window.
        2. Pull data from external sources.
        3. Evaluate the data against user context.
        4. Write structured output (alerts, observations, etc.).
        5. Audit-log cycle completion with stats.

        Returns:
            Number of alerts/observations produced in this cycle.
            Returns 0 if the cycle was skipped (e.g. outside active hours).
        """
        ...

    @abstractmethod
    async def get_pending_output(self) -> list[Any]:
        """Return pending output items for main to consume.

        The caller (main or gateway) reads this list and surfaces the most
        relevant items to the user at the appropriate time.  Items remain in
        the list until explicitly acknowledged.

        Returns:
            List of output items (type is processor-specific).
        """
        ...
