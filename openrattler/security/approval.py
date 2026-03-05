"""Human-in-the-loop approval system — Layer 9 of OpenRattler's security architecture.

When a tool is marked ``requires_approval=True``, execution must not proceed
until an authorised human (or future automated policy) explicitly approves or
denies it.  ``ApprovalManager`` is the broker: it accepts requests from
``ToolExecutor``, notifies a registered handler (e.g. ``CLIApprovalHandler``),
and waits for a resolution with a hard timeout.

FLOW
----
1. ``ToolExecutor`` builds an ``ApprovalRequest`` capturing the operation,
   arguments, and independently-verified provenance (trust_level, agent_id,
   timestamp — not the agent's stated reason).
2. ``ToolExecutor`` calls ``ApprovalManager.request_approval(request)``.
3. ``ApprovalManager`` stores the request, fires the registered handler as a
   background task, then waits on a per-request ``asyncio.Event``.
4a. Handler calls ``ApprovalManager.resolve(approval_id, approved, decided_by)``
    within the timeout → the event is set → ``request_approval`` returns
    ``ApprovalResult(approved=True/False, ...)``.
4b. Timeout fires → ``request_approval`` auto-denies and returns
    ``ApprovalResult(approved=False, decided_by="system:timeout", ...)``.
5. ``ToolExecutor`` allows or blocks execution based on ``result.approved``.

SECURITY NOTES
--------------
- Fail-secure: timeout always results in denial, never in permission.
- Provenance in ``ApprovalRequest`` is populated by the executor from the
  verified ``AgentConfig`` — never from data the agent itself supplies.
- Audit events are written for every request and every resolution so the
  full approval trail is reconstructible.
- ``CLIApprovalHandler`` offloads ``input()`` to a thread executor so it
  does not block the event loop.
- If ``resolve`` is called after a timeout has already decided the request,
  it silently no-ops (the race window is small but real on slow machines).
"""

from __future__ import annotations

import asyncio
import sys
import uuid
from datetime import datetime, timezone
from typing import Any, Callable, Coroutine, Optional

from pydantic import BaseModel, Field

from openrattler.models.audit import AuditEvent
from openrattler.storage.audit import AuditLog

# ---------------------------------------------------------------------------
# Models
# ---------------------------------------------------------------------------


class ApprovalRequest(BaseModel):
    """Describes a pending approval gate.

    Security notes:
    - ``provenance`` is populated by the caller from independently-verified
      data (e.g. ``AgentConfig.trust_level``, not the agent's own claim).
    - ``timeout_seconds`` is enforced by ``ApprovalManager``; the caller
      cannot extend it at resolution time.
    """

    approval_id: str = Field(description="Unique identifier for this approval request")
    operation: str = Field(description="Tool name or operation being approved")
    context: dict[str, Any] = Field(
        default_factory=dict,
        description="Tool arguments or contextual details about the operation",
    )
    requesting_agent: str = Field(description="agent_id of the agent requesting execution")
    session_key: str = Field(description="Session in which the operation was requested")
    provenance: dict[str, Any] = Field(
        description=(
            "Independently-verified request metadata: trust_level, agent_id, timestamp. "
            "Must not be derived from user or agent-supplied data."
        )
    )
    timestamp: datetime = Field(description="UTC timestamp when the request was created")
    timeout_seconds: int = Field(
        default=30,
        description="Seconds to wait for a human decision; approval is auto-denied after this",
    )


class ApprovalResult(BaseModel):
    """Outcome of an approval gate.

    Security notes:
    - ``approved=False`` means the operation must not proceed, regardless
      of whether denial came from a human or from a timeout.
    - ``decided_by`` distinguishes human decisions from automatic ones
      (``"system:timeout"`` for timeouts).
    """

    approval_id: str = Field(description="Matches the ApprovalRequest.approval_id")
    approved: bool = Field(description="True only if a human explicitly approved")
    decided_by: str = Field(
        description=(
            "Identity of the decider: e.g. ``'cli:user'``, ``'system:timeout'``, "
            "or an agent_id for automated policies"
        )
    )
    timestamp: datetime = Field(description="UTC timestamp of the decision")


# ---------------------------------------------------------------------------
# Handler type alias
# ---------------------------------------------------------------------------

#: Async callable signature for approval notification handlers.
#: Called with (request, manager) so the handler can call ``manager.resolve``.
ApprovalHandler = Callable[["ApprovalRequest", "ApprovalManager"], Coroutine[Any, Any, None]]


# ---------------------------------------------------------------------------
# ApprovalManager
# ---------------------------------------------------------------------------


class ApprovalManager:
    """Broker for human-in-the-loop approval gates.

    One ``ApprovalManager`` instance is shared across all tool executions
    that require approval.  It maintains a per-request ``asyncio.Event`` so
    ``request_approval`` can ``await`` the human decision without blocking
    the event loop.

    Args:
        audit_log:               Audit log for request and resolution events.
        default_timeout_seconds: How long to wait before auto-denying.
                                 Individual requests can specify a shorter
                                 timeout via ``ApprovalRequest.timeout_seconds``.

    Security notes:
    - Timeout always denies — never grants.
    - ``resolve`` silently no-ops if the request has already been decided
      (timeout race prevention); it never silently grants a timed-out request.
    - ``list_pending`` returns a snapshot; callers cannot mutate the internal
      store through the returned list.
    """

    def __init__(self, audit_log: AuditLog, default_timeout_seconds: int = 30) -> None:
        self._audit = audit_log
        self.default_timeout_seconds = default_timeout_seconds
        # Keyed by approval_id
        self._pending: dict[str, ApprovalRequest] = {}
        self._events: dict[str, asyncio.Event] = {}
        self._results: dict[str, ApprovalResult] = {}
        # IDs that have already been decided (timeout or resolved); used to
        # make resolve() idempotent when a handler fires after a timeout.
        self._decided: set[str] = set()
        self._handler: Optional[ApprovalHandler] = None

    # ------------------------------------------------------------------
    # Handler registration
    # ------------------------------------------------------------------

    def set_handler(self, handler: ApprovalHandler) -> None:
        """Register the notification handler for new approval requests.

        The handler is called as a background ``asyncio.Task`` with the
        ``ApprovalRequest`` and this manager.  It should eventually call
        ``self.resolve(...)`` to unblock the waiting coroutine.

        Args:
            handler: Async callable ``(request, manager) -> None``.
        """
        self._handler = handler

    # ------------------------------------------------------------------
    # Core approval flow
    # ------------------------------------------------------------------

    async def request_approval(self, request: ApprovalRequest) -> ApprovalResult:
        """Block until the request is approved, denied, or timed out.

        Stores the request, fires the handler as a background task, then
        waits for resolution.  On timeout the request is auto-denied.

        Args:
            request: Fully-constructed ``ApprovalRequest``.

        Returns:
            ``ApprovalResult`` — ``approved=False`` on timeout or denial,
            ``approved=True`` only on explicit human approval.
        """
        approval_id = request.approval_id
        event = asyncio.Event()
        self._pending[approval_id] = request
        self._events[approval_id] = event

        # Audit-log the incoming request.
        await self._audit.log(
            AuditEvent(
                event="approval_requested",
                agent_id=request.requesting_agent,
                session_key=request.session_key,
                details={
                    "approval_id": approval_id,
                    "operation": request.operation,
                    "context": request.context,
                    "provenance": request.provenance,
                    "timeout_seconds": request.timeout_seconds,
                },
            )
        )

        # Notify the handler (non-blocking — it may prompt the user).
        if self._handler is not None:
            asyncio.create_task(self._handler(request, self))

        # Wait with a hard timeout.
        timeout = request.timeout_seconds
        try:
            await asyncio.wait_for(event.wait(), timeout=float(timeout))
        except asyncio.TimeoutError:
            result = ApprovalResult(
                approval_id=approval_id,
                approved=False,
                decided_by="system:timeout",
                timestamp=datetime.now(timezone.utc),
            )
            self._results[approval_id] = result
            self._decided.add(approval_id)
            await self._audit.log(
                AuditEvent(
                    event="approval_resolved",
                    agent_id=request.requesting_agent,
                    session_key=request.session_key,
                    details={
                        "approval_id": approval_id,
                        "approved": False,
                        "decided_by": "system:timeout",
                    },
                )
            )

        # Extract result (must exist after event.wait() or timeout path).
        result = self._results[approval_id]

        # Clean up pending state; keep _decided for idempotency.
        self._pending.pop(approval_id, None)
        self._events.pop(approval_id, None)
        self._results.pop(approval_id, None)

        return result

    async def resolve(self, approval_id: str, approved: bool, decided_by: str) -> None:
        """Resolve a pending approval request.

        Called by a handler (e.g. ``CLIApprovalHandler``) once the user has
        made a decision.

        Args:
            approval_id: Matches ``ApprovalRequest.approval_id``.
            approved:    ``True`` if the operation is permitted.
            decided_by:  Identity string for the decider (e.g. ``"cli:user"``).

        Raises:
            ValueError: If *approval_id* is not currently pending.

        Security notes:
        - If the request was already decided (timeout race), this method
          silently no-ops rather than raising, because the handler task may
          legitimately fire after a very tight timeout.
        """
        if approval_id in self._decided:
            # Already resolved (e.g. timed out before handler responded).
            return

        if approval_id not in self._pending:
            raise ValueError(f"No pending approval for id {approval_id!r}")

        request = self._pending[approval_id]
        result = ApprovalResult(
            approval_id=approval_id,
            approved=approved,
            decided_by=decided_by,
            timestamp=datetime.now(timezone.utc),
        )
        self._results[approval_id] = result
        self._decided.add(approval_id)

        await self._audit.log(
            AuditEvent(
                event="approval_resolved",
                agent_id=request.requesting_agent,
                session_key=request.session_key,
                details={
                    "approval_id": approval_id,
                    "approved": approved,
                    "decided_by": decided_by,
                },
            )
        )

        # Unblock the waiting request_approval coroutine.
        self._events[approval_id].set()

    async def list_pending(self) -> list[ApprovalRequest]:
        """Return a snapshot of all currently-pending approval requests.

        Returns a copy so callers cannot mutate the internal store.
        """
        return list(self._pending.values())


# ---------------------------------------------------------------------------
# CLIApprovalHandler
# ---------------------------------------------------------------------------


class CLIApprovalHandler:
    """Approval handler that prompts the CLI user for a y/n decision.

    Prints the request details (including provenance) to stdout and reads
    the response from stdin inside a thread executor so the event loop is
    not blocked.

    Usage::

        handler = CLIApprovalHandler()
        manager = ApprovalManager(audit_log)
        manager.set_handler(handler)

    Security notes:
    - Provenance is always printed so the user sees the independently-verified
      metadata, not just the agent's stated reason.
    - An empty or unrecognised answer is treated as denial (fail-secure).
    - ``_read_input`` is a static method so tests can patch it without
      blocking on stdin.
    """

    async def __call__(self, request: ApprovalRequest, manager: ApprovalManager) -> None:
        """Print request details and resolve based on user input."""
        self._print_request(request)
        loop = asyncio.get_event_loop()
        answer: str = await loop.run_in_executor(None, self._read_input)
        approved = answer.strip().lower() in ("y", "yes")
        try:
            await manager.resolve(request.approval_id, approved, "cli:user")
        except ValueError:
            # Request already decided (timeout race) — nothing to do.
            pass

    @staticmethod
    def _print_request(request: ApprovalRequest) -> None:
        """Print the approval request summary to stdout."""
        sep = "-" * 60
        print(f"\n{sep}", file=sys.stdout)
        print(f"[APPROVAL REQUIRED]", file=sys.stdout)
        print(f"  Operation : {request.operation}", file=sys.stdout)
        print(f"  Agent     : {request.requesting_agent}", file=sys.stdout)
        print(f"  Session   : {request.session_key}", file=sys.stdout)
        print(f"  Context   : {request.context}", file=sys.stdout)
        print(f"  Provenance: {request.provenance}", file=sys.stdout)
        print(f"  Timeout   : {request.timeout_seconds}s", file=sys.stdout)
        print(f"{sep}", file=sys.stdout)

    @staticmethod
    def _read_input() -> str:
        """Blocking stdin read — run inside a thread executor."""
        return input("Approve? [y/N]: ")
