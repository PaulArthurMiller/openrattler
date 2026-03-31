"""Registry of known UniversalMessage operation names and their metadata.

This module is the single source of truth for which operations OpenRattler
recognises.  Consumers import ``KNOWN_OPERATIONS`` to check whether an
operation string is valid and to retrieve its trust-level requirement or
params schema reference.

DESIGN NOTES
------------
- ``params_schema_ref`` is a dotted module path string rather than a live
  class import to avoid circular dependencies.  Callers that need the class
  can use ``_resolve_params_model(spec)`` for lazy resolution.
- Adding a new operation requires a code change here — no config override
  is possible.  This is intentional: operations define the system's external
  API surface, and expanding that surface silently via config is a security risk.
- The list below is not exhaustive of all string values that may appear as
  ``UniversalMessage.operation`` in practice (adapters may emit arbitrary
  operation strings for legacy reasons).  It represents the set of operations
  that are actively managed and validated by the platform.
"""

from __future__ import annotations

import importlib
from dataclasses import dataclass
from typing import Any, Optional, Type

from pydantic import BaseModel

# ---------------------------------------------------------------------------
# OperationSpec
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class OperationSpec:
    """Metadata for a single recognised operation.

    Attributes:
        name:               Operation name as it appears in UniversalMessage.
        description:        Human-readable description for documentation and
                            approval prompts.
        trust_level_required: Minimum trust level for the *sender* of a UM
                            carrying this operation.
        params_schema_ref:  Dotted path to the Pydantic model that validates
                            the ``params`` block, e.g.
                            ``"openrattler.agents.research.models.ResearchRequest"``.
                            ``None`` means no schema validation is enforced by
                            the operations registry (validation may still happen
                            in the consumer).
    """

    name: str
    description: str
    trust_level_required: str
    params_schema_ref: Optional[str] = None


# ---------------------------------------------------------------------------
# Registry
# ---------------------------------------------------------------------------

KNOWN_OPERATIONS: dict[str, OperationSpec] = {
    # Core messaging
    "user_message": OperationSpec(
        name="user_message",
        description="Inbound user message from a channel adapter",
        trust_level_required="public",
    ),
    # Research
    "research_query": OperationSpec(
        name="research_query",
        description=(
            "Request web research from the ResearchAgent. " "params must parse as ResearchRequest."
        ),
        trust_level_required="main",
        params_schema_ref="openrattler.agents.research.models.ResearchRequest",
    ),
    # Heartbeat
    "heartbeat_response": OperationSpec(
        name="heartbeat_response",
        description="Heartbeat check-in response from the agent",
        trust_level_required="main",
    ),
    # Security
    "security_alert": OperationSpec(
        name="security_alert",
        description="Security alert dispatched out-of-band to channels",
        trust_level_required="security",
    ),
    # Outbound channel operations
    "send_slack_message": OperationSpec(
        name="send_slack_message",
        description="Send a Slack message via the Slack adapter",
        trust_level_required="main",
    ),
    "send_sms": OperationSpec(
        name="send_sms",
        description="Send an SMS via the SMS adapter",
        trust_level_required="main",
    ),
    "send_email": OperationSpec(
        name="send_email",
        description="Send an email via the email adapter",
        trust_level_required="main",
    ),
}


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def is_known_operation(operation: str) -> bool:
    """Return ``True`` if *operation* is in the registry."""
    return operation in KNOWN_OPERATIONS


def get_spec(operation: str) -> Optional[OperationSpec]:
    """Return the ``OperationSpec`` for *operation*, or ``None`` if unknown."""
    return KNOWN_OPERATIONS.get(operation)


def resolve_params_model(spec: OperationSpec) -> Optional[Type[BaseModel]]:
    """Lazily import and return the Pydantic params model for *spec*.

    Returns ``None`` if ``spec.params_schema_ref`` is ``None`` or if the
    class cannot be imported.

    Security note: the ref string comes from this module's source code, not
    from user input — it is safe to import dynamically.
    """
    if spec.params_schema_ref is None:
        return None
    try:
        module_path, class_name = spec.params_schema_ref.rsplit(".", 1)
        module = importlib.import_module(module_path)
        cls: Any = getattr(module, class_name)
        if isinstance(cls, type) and issubclass(cls, BaseModel):
            return cls
        return None
    except (ImportError, AttributeError, ValueError):
        return None
