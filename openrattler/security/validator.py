"""PitchCatch Validator — trust-boundary enforcement for every component.

Every component that receives or emits ``UniversalMessage`` objects should
own a ``PitchCatchValidator`` instance.  Incoming messages are validated
through a multi-step pipeline before the component acts on them; outgoing
messages are packaged into ``UniversalMessage`` objects with the component's
own identity and trust level.

VALIDATION PIPELINE (``validate_incoming``)
--------------------------------------------
1. **Operation check** — reject operations not in the component's allowlist.
2. **Trust level check** — reject messages whose trust rank is below the
   component's minimum required rank.
3. **Required params check** — reject messages missing mandatory parameters
   for the stated operation.
4. **Param stripping (need-to-know)** — remove every param not listed as
   required or optional for the operation; unknown params never reach the
   component.
5. **Rate limiting** — reject messages that exceed the per-minute or
   per-hour limit for the sender.
6. **Audit logging** — every validated message is logged with event type
   ``message_validated``.

On any failure the method raises ``PermissionError`` (recoverable — caller
should return an error response) or ``ValueError`` (bad message structure).
The validator itself never raises unexpectedly.

SECURITY NOTES
--------------
- The trust-level check uses the numeric ``_TRUST_ORDER`` mapping from
  ``openrattler.tools.permissions``.  The component's ``trust_level``
  parameter sets the *minimum acceptable* incoming trust rank.
- Param stripping is the key need-to-know control: a compromised upstream
  component cannot inject extra context that downstream components act on.
- Rate limiting is enforced per ``message.from_agent`` (not per IP) because
  the validator operates at the application layer.
"""

from __future__ import annotations

from typing import Any, Optional

from openrattler.models.agents import TrustLevel
from openrattler.models.messages import UniversalMessage, create_message
from openrattler.storage.audit import AuditLog
from openrattler.tools.permissions import _TRUST_ORDER

from .rate_limiter import RateLimiter


class PitchCatchValidator:
    """Validates incoming messages and packages outgoing messages for a component.

    One instance is created per component.  The component's identity and
    security policy are fixed at construction time.

    Security notes:
    - Param stripping removes unrecognised keys before the component sees the
      message, implementing need-to-know isolation.
    - Trust-level comparisons use ``_TRUST_ORDER`` integer ranks so that
      ``security`` and ``main`` (both rank 2) are treated equivalently.
    - All validation outcomes (pass and fail) are audit-logged.
    - ``validate_incoming`` raises ``PermissionError`` for policy violations
      and ``ValueError`` for structurally invalid messages.  It never raises
      for unexpected reasons — callers can always catch one of these two types.
    """

    def __init__(
        self,
        component_id: str,
        trust_level: TrustLevel,
        allowed_operations: list[str],
        required_params: dict[str, list[str]],
        optional_params: dict[str, list[str]],
        rate_limiter: RateLimiter,
        audit_log: AuditLog,
    ) -> None:
        """Initialise the validator.

        Args:
            component_id:       Identifier of the owning component
                                (used as ``from_agent`` in outgoing messages).
            trust_level:        Minimum trust level that incoming messages
                                must carry.  Messages with a lower trust rank
                                are rejected.
            allowed_operations: Exhaustive list of operation names this
                                component accepts.
            required_params:    Map of operation → list of param names that
                                MUST be present in ``message.params``.
            optional_params:    Map of operation → list of param names that
                                are allowed but not required.  All other params
                                are stripped.
            rate_limiter:       ``RateLimiter`` instance shared across the
                                component's validator.
            audit_log:          ``AuditLog`` that receives a record of every
                                validated (or rejected) message.
        """
        self._component_id = component_id
        self._trust_level = trust_level
        self._min_trust_rank = _TRUST_ORDER[trust_level]
        self._allowed_operations = set(allowed_operations)
        self._required_params = required_params
        self._optional_params = optional_params
        self._rate_limiter = rate_limiter
        self._audit = audit_log

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    async def validate_incoming(self, message: UniversalMessage) -> UniversalMessage:
        """Run the full validation pipeline on *message*.

        Returns the sanitized (param-stripped) message on success.

        Args:
            message: The incoming ``UniversalMessage`` to validate.

        Returns:
            A copy of *message* with unrecognised params removed.

        Raises:
            ValueError:       Operation not in allowlist, or required params
                              missing.
            PermissionError:  Trust level insufficient or rate limit exceeded.
        """
        operation = message.operation

        # 1. Operation allowed?
        if operation not in self._allowed_operations:
            await self._audit_event(
                "message_rejected",
                message,
                reason=f"operation_not_allowed:{operation}",
            )
            raise ValueError(f"Operation not allowed: {operation!r}")

        # 2. Trust level sufficient?
        try:
            incoming_rank = _TRUST_ORDER[TrustLevel(message.trust_level)]
        except ValueError:
            await self._audit_event(
                "message_rejected",
                message,
                reason=f"unknown_trust_level:{message.trust_level}",
            )
            raise ValueError(f"Unknown trust level: {message.trust_level!r}")

        if incoming_rank < self._min_trust_rank:
            await self._audit_event(
                "message_rejected",
                message,
                reason=f"trust_level_insufficient:{message.trust_level}",
            )
            raise PermissionError(
                f"Trust level {message.trust_level!r} is insufficient; "
                f"minimum required is {self._trust_level.value!r}"
            )

        # 3. Required params present?
        required = self._required_params.get(operation, [])
        for param in required:
            if param not in message.params:
                await self._audit_event(
                    "message_rejected",
                    message,
                    reason=f"missing_required_param:{param}",
                )
                raise ValueError(f"Missing required parameter: {param!r}")

        # 4. Strip extraneous params (need-to-know isolation).
        allowed_params = set(required) | set(self._optional_params.get(operation, []))
        stripped_params = {k: v for k, v in message.params.items() if k in allowed_params}

        # Build a new message instance with the stripped params.
        sanitized = message.model_copy(update={"params": stripped_params})

        # 5. Rate limiting.
        if not await self._rate_limiter.check(message.from_agent):
            await self._audit_event(
                "message_rejected",
                sanitized,
                reason="rate_limit_exceeded",
            )
            raise PermissionError(f"Rate limit exceeded for agent {message.from_agent!r}")
        await self._rate_limiter.record(message.from_agent)

        # 6. Audit log successful validation.
        await self._audit_event("message_validated", sanitized)

        return sanitized

    async def structure_outgoing(
        self,
        operation: str,
        params: dict[str, Any],
        to_agent: str,
        session_key: str,
        type: str = "response",  # noqa: A002
        trace_id: Optional[str] = None,
    ) -> UniversalMessage:
        """Package a component output as a ``UniversalMessage``.

        Args:
            operation:   The operation name for the outgoing message.
            params:      The output payload.
            to_agent:    Recipient agent identifier.
            session_key: Session key for routing.
            type:        Message type — ``"response"`` (default), ``"event"``,
                         or ``"error"``.
            trace_id:    Optional trace ID to continue an existing trace.

        Returns:
            A fully-formed ``UniversalMessage`` from this component.
        """
        return create_message(
            from_agent=self._component_id,
            to_agent=to_agent,
            session_key=session_key,
            type=type,  # type: ignore[arg-type]
            operation=operation,
            trust_level=self._trust_level.value,
            params=params,
            trace_id=trace_id,
        )

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    async def _audit_event(
        self,
        event: str,
        message: UniversalMessage,
        reason: Optional[str] = None,
    ) -> None:
        """Write a single audit entry for *message*."""
        details: dict[str, Any] = {
            "operation": message.operation,
            "from_agent": message.from_agent,
            "to_agent": message.to_agent,
        }
        if reason:
            details["reason"] = reason

        from openrattler.models.audit import AuditEvent

        await self._audit.log(
            AuditEvent(
                event=event,
                agent_id=self._component_id,
                session_key=message.session_key,
                trace_id=message.trace_id,
                details=details,
            )
        )
