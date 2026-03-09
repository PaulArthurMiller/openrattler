"""Social tools — main agent tools for interacting with the Social Secretary.

These tools allow the main agent to:
- Acknowledge social alerts after surfacing them to the user
- Adjust how closely the Social Secretary watches a contact
- Log social observations for the Social Secretary to follow up on

All tools require ``TrustLevel.main`` and are unavailable to sandboxed agents.

SECURITY NOTES
--------------
- ``acknowledge_social_alert`` and ``adjust_contact_attention`` operate only
  within the Social Secretary's data store.
- ``add_learning_observation`` passes through ``SocialStore``'s security review
  gate, which catches suspicious content before it reaches persistent storage.
- No social content is forwarded to external services by these tools.
- All three tools are registered explicitly via ``SocialTools.register_all()``;
  they do not auto-register via the ``@tool`` decorator because they require
  a ``SocialStore`` instance bound to the handler.
"""

from __future__ import annotations

import logging
from datetime import date
from typing import TYPE_CHECKING, Any, Optional

from openrattler.models.agents import TrustLevel
from openrattler.models.social import LearningObservation
from openrattler.models.tools import ToolDefinition

if TYPE_CHECKING:
    from openrattler.storage.audit import AuditLog
    from openrattler.storage.social import SocialStore
    from openrattler.tools.registry import ToolRegistry

logger = logging.getLogger(__name__)

#: Session key used in any audit events emitted directly by these tools.
_TOOLS_SESSION_KEY = "agent:main:main"

#: Valid attention level values (mirrors AttentionLevel Literal in models/social.py).
_VALID_ATTENTION_LEVELS: frozenset[str] = frozenset({"watch_closely", "normal", "low"})

#: Valid observation priority values.
_VALID_PRIORITIES: frozenset[str] = frozenset({"blocking", "important", "curious"})

#: Valid observation purpose values.
_VALID_PURPOSES: frozenset[str] = frozenset(
    {"scheduling", "social_obligation", "collaboration", "enrichment"}
)


class SocialTools:
    """Container for social interaction tools registered with the tool registry.

    Args:
        social_store: The ``SocialStore`` instance to read from and write to.
        audit:        Optional audit log; presently unused (the store itself
                      handles audit logging on mutations).

    Usage::

        tools = SocialTools(social_store=store)
        tools.register_all(registry)

    Security notes:
    - All three tools enforce ``TrustLevel.main``.
    - Handler methods are bound to this instance so the store reference is
      never exposed through the registry.
    """

    def __init__(
        self,
        social_store: "SocialStore",
        audit: Optional["AuditLog"] = None,
    ) -> None:
        self._store = social_store
        self._audit = audit

    def register_all(self, registry: "ToolRegistry") -> None:
        """Register all social tools with *registry*.

        Registers:
        - ``acknowledge_social_alert``
        - ``adjust_contact_attention``
        - ``add_learning_observation``
        """
        registry.register(
            ToolDefinition(
                name="acknowledge_social_alert",
                description=("Mark a social alert as seen/handled after surfacing it to the user"),
                parameters={
                    "type": "object",
                    "properties": {"alert_id": {"type": "string"}},
                    "required": ["alert_id"],
                },
                trust_level_required=TrustLevel.main,
                security_notes=(
                    "Operates within Social Secretary data store only. "
                    "Does not expose social content externally."
                ),
            ),
            self.acknowledge_social_alert,
        )
        registry.register(
            ToolDefinition(
                name="adjust_contact_attention",
                description=("Adjust how closely the Social Secretary watches a person"),
                parameters={
                    "type": "object",
                    "properties": {
                        "name": {"type": "string"},
                        "attention_level": {"type": "string"},
                    },
                    "required": ["name", "attention_level"],
                },
                trust_level_required=TrustLevel.main,
                security_notes=(
                    "Validates attention_level literal. Updates known contacts only. "
                    "Write goes through SocialStore security review."
                ),
            ),
            self.adjust_contact_attention,
        )
        registry.register(
            ToolDefinition(
                name="add_learning_observation",
                description=(
                    "Log an observation about the user's social world for the "
                    "Social Secretary to follow up on"
                ),
                parameters={
                    "type": "object",
                    "properties": {
                        "observed": {"type": "string"},
                        "priority": {"type": "string"},
                        "relates_to": {"type": "string"},
                        "purpose": {"type": "string"},
                    },
                    "required": ["observed", "priority", "relates_to", "purpose"],
                },
                trust_level_required=TrustLevel.main,
                security_notes=(
                    "Content passes through SocialStore security review gate. "
                    "Validates priority, relates_to, and purpose literals."
                ),
            ),
            self.add_learning_observation,
        )

    # ------------------------------------------------------------------
    # Tool handlers
    # ------------------------------------------------------------------

    async def acknowledge_social_alert(self, alert_id: str) -> dict[str, Any]:
        """Mark *alert_id* as acknowledged so it is not re-surfaced."""
        success = await self._store.acknowledge_alert(alert_id)
        if success:
            return {"success": True, "alert_id": alert_id}
        return {
            "success": False,
            "error": f"Alert '{alert_id}' not found or already acknowledged",
        }

    async def adjust_contact_attention(self, name: str, attention_level: str) -> dict[str, Any]:
        """Set *attention_level* for the contact named *name*.

        Valid values: ``watch_closely``, ``normal``, ``low``.
        """
        if attention_level not in _VALID_ATTENTION_LEVELS:
            return {
                "success": False,
                "error": (
                    f"Invalid attention_level '{attention_level}'. "
                    f"Must be one of: {', '.join(sorted(_VALID_ATTENTION_LEVELS))}"
                ),
            }
        contact = await self._store.find_contact(name)
        if contact is None:
            return {"success": False, "error": f"Contact '{name}' not found"}

        updated = contact.model_copy(update={"attention_level": attention_level})
        ok, reason = await self._store.upsert_contact(updated)
        if ok:
            return {"success": True, "name": name, "attention_level": attention_level}
        return {"success": False, "error": reason or "Security review rejected the update"}

    async def add_learning_observation(
        self,
        observed: str,
        priority: str,
        relates_to: str,
        purpose: str,
    ) -> dict[str, Any]:
        """Log a social observation for the Social Secretary to follow up on.

        Args:
            observed:   What was noticed (free text, max ~500 chars recommended).
            priority:   ``blocking``, ``important``, or ``curious``.
            relates_to: ``user`` or ``other_person``.
            purpose:    ``scheduling``, ``social_obligation``, ``collaboration``,
                        or ``enrichment``.
        """
        if priority not in _VALID_PRIORITIES:
            return {
                "success": False,
                "error": (
                    f"Invalid priority '{priority}'. "
                    f"Must be one of: {', '.join(sorted(_VALID_PRIORITIES))}"
                ),
            }
        if purpose not in _VALID_PURPOSES:
            return {
                "success": False,
                "error": (
                    f"Invalid purpose '{purpose}'. "
                    f"Must be one of: {', '.join(sorted(_VALID_PURPOSES))}"
                ),
            }
        try:
            obs = LearningObservation(
                observed=observed,
                source_session=_TOOLS_SESSION_KEY,
                source_date=date.today(),
                priority=priority,  # type: ignore[arg-type]  # validated above
                best_context="when_relevant",
                relates_to=relates_to,
                purpose=purpose,
            )
        except Exception as exc:
            return {"success": False, "error": f"Invalid observation data: {exc}"}

        ok, reason = await self._store.add_observation(obs)
        if ok:
            return {"success": True, "observation_id": obs.id}
        return {"success": False, "error": reason or "Security review rejected the observation"}
