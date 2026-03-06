"""Social Secretary proactive processor — social feed scanning and alert generation.

The Social Secretary runs on a configurable schedule, reads social media feeds
via MCP tools, evaluates each post for relevance to the user's social world,
and produces ``SocialAlert`` objects for main to surface at the appropriate time.

PROCESSING CYCLE
----------------
1. Check active hours — skip if outside the configured window.
2. Load contacts and open learning observations for context.
3. For each connected platform (MCP server):
   a. Fetch recent items via the platform's MCP tool.
   b. Sanitise content (truncate, strip URLs, scan for suspicious patterns).
   c. Evaluate each sanitised item with a focused LLM call (no tools).
   d. If relevant, generate a SocialAlert.
   e. Enrich contacts with any new information discovered.
4. Persist alerts, updated contacts, and new observations.
5. Audit-log cycle completion statistics.

SECURITY PROPERTIES
-------------------
- The Social Secretary has its own session key: ``agent:social_secretary:system``.
- It NEVER receives main's conversation history, memory files, or tools.
- LLM evaluation calls have NO tools — pure text-in, text-out assessment.
- Social media content is always wrapped in ``<social_post>…</social_post>``
  delimiters to reduce prompt injection effectiveness.
- Malformed LLM responses are logged and skipped; they never reach the alert
  store.
- Suspicious content patterns are audit-logged but do NOT block processing —
  the attacker gets no signal that detection occurred.
- ``max_post_length_chars`` is enforced BEFORE any content reaches the LLM.
- Each cycle is bounded by ``max_alerts_per_cycle`` to prevent alert floods.
"""

from __future__ import annotations

import json
import logging
import re
from datetime import datetime, timezone
from typing import TYPE_CHECKING, Any, Optional

from openrattler.models.audit import AuditEvent
from openrattler.models.social import (
    ContactEntry,
    ContactsStore,
    SocialAlert,
    SocialSecretaryConfig,
)
from openrattler.processors.base import ProactiveProcessor
from openrattler.security.patterns import scan_for_suspicious_content
from openrattler.storage.social import SocialStore

if TYPE_CHECKING:
    from openrattler.agents.providers.base import LLMProvider
    from openrattler.mcp.manager import MCPManager
    from openrattler.storage.audit import AuditLog

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

#: Session key used for all Social Secretary operations.
_SS_SESSION_KEY = "agent:social_secretary:system"

#: Minimum LLM confidence score required to generate an alert.
_MIN_CONFIDENCE: float = 0.3

#: Regex for stripping URLs from post content.
_URL_RE = re.compile(r"https?://\S+|www\.\S+", re.IGNORECASE)

#: MCP tool name convention for "get latest feed" calls.
_FEED_TOOL_NAME = "get_feed"

#: LLM evaluation system prompt — tightly scoped, no user context.
_EVAL_SYSTEM_PROMPT = """\
You are a social media relevance evaluator. Your job is to assess whether a \
social media post is worth bringing to the user's attention.

You will receive:
- A social media post (text content only, sanitised)
- The poster's name
- Any existing context about this person (relationship, known details)
- The types of events the user wants to be alerted about

Respond with ONLY a JSON object or the word "skip":

If relevant:
{
    "event_type": "birthday|health_update|life_event|career_change|engagement|birth|death|anniversary|post_mention",
    "summary": "Brief summary of what happened (1-2 sentences)",
    "urgency": "immediate|next_interaction|low",
    "recommended_action": "inform_user|suggest_response|log_only",
    "recommended_timing": "immediate|next_natural_interaction|next_heartbeat|when_relevant",
    "confidence": 0.0-1.0,
    "new_details": {"key": "value"}
}

If not relevant: skip

Be conservative. Only flag things the user would genuinely appreciate knowing \
about. Casual posts, memes, shared articles, and routine updates are NOT \
relevant unless they contain a life event."""


# ---------------------------------------------------------------------------
# SocialSecretaryProcessor
# ---------------------------------------------------------------------------


class SocialSecretaryProcessor(ProactiveProcessor):
    """Proactive processor that scans social feeds and generates alerts for main.

    Args:
        config:       Configuration governing cycle frequency, active hours,
                      platforms, and content safety settings.
        social_store: Persistent storage for alerts, contacts, and learning queue.
        mcp_manager:  MCP connection registry used to call platform feed tools.
        provider:     LLM provider for relevance evaluation (no tools attached).
        audit:        Optional audit log for cycle events and security findings.

    Security notes:
    - ``mcp_manager`` is the ONLY external data source.  The processor has no
      access to main's session, memory, email, or filesystem beyond its own
      ``social_store`` base directory.
    - LLM evaluation calls never carry tool definitions — they are pure
      text-in, text-out calls using the cheap evaluation model.
    """

    def __init__(
        self,
        config: SocialSecretaryConfig,
        social_store: SocialStore,
        mcp_manager: "MCPManager",
        provider: "LLMProvider",
        audit: Optional["AuditLog"] = None,
    ) -> None:
        self._config = config
        self._store = social_store
        self._mcp = mcp_manager
        self._provider = provider
        self._audit = audit
        self._cycle_count: int = 0

    # ------------------------------------------------------------------
    # ProactiveProcessor interface
    # ------------------------------------------------------------------

    @property
    def processor_name(self) -> str:
        return "social_secretary"

    async def connect(self) -> None:
        """Validate that configured platform MCP servers are connected.

        Logs a warning for any platform that is not yet connected but does not
        raise — the cycle will skip unconnected platforms gracefully.
        """
        for platform in self._config.connected_platforms:
            try:
                self._mcp.get_connection(platform)
                logger.info("Social Secretary: platform '%s' connected", platform)
            except KeyError:
                logger.warning(
                    "Social Secretary: platform '%s' is not connected — will skip in cycles",
                    platform,
                )
        await self._audit_event("social_secretary_connected")

    async def disconnect(self) -> None:
        """Clean up — no persistent connections owned by the processor itself."""
        await self._audit_event("social_secretary_disconnected")

    async def run_cycle(self) -> int:
        """Execute one Social Secretary processing cycle.

        Returns:
            Number of alerts generated.  0 if outside active hours or no
            relevant items found.
        """
        if not self._in_active_hours():
            logger.debug("Social Secretary: outside active hours — skipping cycle")
            return 0

        contacts_store = await self._store.load_contacts()
        alerts_generated = 0

        for platform in self._config.connected_platforms:
            try:
                items = await self._fetch_feed(platform)
            except Exception as exc:
                logger.warning("Social Secretary: feed fetch failed for '%s': %s", platform, exc)
                await self._audit_event(
                    "social_feed_error",
                    platform=platform,
                    error=type(exc).__name__,
                    message=str(exc)[:200],
                )
                continue

            for item in items:
                if alerts_generated >= self._config.max_alerts_per_cycle:
                    break

                sanitised = await self._sanitise_item(item)
                alert = await self._evaluate_item(sanitised, contacts_store, platform)

                if alert is not None:
                    await self._store.add_alert(alert)
                    alerts_generated += 1

                await self._enrich_contacts(item, alert, contacts_store, platform)

        self._cycle_count += 1

        await self._audit_event(
            "social_cycle_complete",
            cycle_number=self._cycle_count,
            platforms_checked=len(self._config.connected_platforms),
            alerts_generated=alerts_generated,
        )
        return alerts_generated

    async def get_pending_output(self) -> list[SocialAlert]:
        """Return unacknowledged alerts for main to consume."""
        return await self._store.get_pending_alerts()

    # ------------------------------------------------------------------
    # Feed fetching
    # ------------------------------------------------------------------

    async def _fetch_feed(self, platform: str) -> list[dict[str, Any]]:
        """Fetch recent items from a platform via its MCP server.

        Calls ``get_feed`` on the platform's MCP connection.  Returns the raw
        items list from the tool response.

        Raises:
            KeyError: If the platform server is not connected.
            Exception: Propagated from the MCP call — caught in run_cycle.
        """
        conn = self._mcp.get_connection(platform)
        result = await conn.call_tool(_FEED_TOOL_NAME, {})
        items = result.get("items", [])
        if not isinstance(items, list):
            return []
        return items

    # ------------------------------------------------------------------
    # Content sanitisation
    # ------------------------------------------------------------------

    async def _sanitise_item(self, item: dict[str, Any]) -> dict[str, Any]:
        """Apply content safety measures before LLM evaluation.

        Steps:
        1. Truncate text content to ``max_post_length_chars``.
        2. Strip URLs if configured.
        3. Run suspicious content scan — audit-log hits but DO NOT block.
        4. Never pass raw HTML; strip all HTML tags.

        Returns a sanitised copy of the item dict.

        Security notes:
        - Truncation happens BEFORE scanning so the scanner operates on
          bounded-length input.
        - Suspicious content is audit-logged only — the attacker receives no
          signal that detection occurred.
        """
        sanitised = dict(item)

        text = str(item.get("text", item.get("content", item.get("message", ""))))

        # Step 1 — truncate
        if len(text) > self._config.max_post_length_chars:
            text = text[: self._config.max_post_length_chars]

        # Step 2 — strip HTML tags
        text = re.sub(r"<[^>]+>", "", text)

        # Step 3 — strip URLs if configured
        if self._config.strip_urls:
            text = _URL_RE.sub("", text)

        # Step 4 — strip mentions if configured
        if self._config.strip_mentions:
            text = re.sub(r"@\w+", "", text)

        # Step 5 — suspicious content scan (audit-log hits, don't block)
        hits = scan_for_suspicious_content(text)
        if hits:
            categories = list({category for category, _ in hits})
            await self._audit_event(
                "social_suspicious_content",
                platform=item.get("source", "unknown"),
                categories=categories,
                item_id=item.get("id", ""),
            )

        sanitised["_sanitised_text"] = text.strip()
        return sanitised

    # ------------------------------------------------------------------
    # LLM evaluation
    # ------------------------------------------------------------------

    async def _evaluate_item(
        self,
        item: dict[str, Any],
        contacts: ContactsStore,
        platform: str,
    ) -> Optional[SocialAlert]:
        """Use the evaluation LLM to assess whether an item merits an alert.

        The LLM receives ONLY:
        - The sanitised post text (wrapped in delimiters)
        - The poster's name and any matching contact context
        - The configured list of event types to watch for

        The LLM does NOT receive any user conversation history, memory, or
        tools.

        Returns:
            A ``SocialAlert`` if the item is relevant, ``None`` otherwise.
        """
        text = item.get("_sanitised_text", "")
        poster = str(item.get("author", item.get("poster", item.get("user", "Unknown"))))
        item_id = str(item.get("id", ""))

        # Build contact context from the store
        contact = next(
            (c for c in contacts.contacts if c.name.lower() == poster.lower()),
            None,
        )
        contact_ctx: dict[str, Any] = {}
        if contact is not None:
            contact_ctx = {
                "relationship": contact.relationship,
                "attention_level": contact.attention_level,
                "relevant_details": contact.relevant_details,
            }

        user_message = json.dumps(
            {
                "poster": poster,
                "contact_context": contact_ctx,
                "watch_event_types": self._config.watch_event_types,
                "post": f"<social_post>{text}</social_post>",
            },
            ensure_ascii=False,
        )

        messages = [
            {"role": "system", "content": _EVAL_SYSTEM_PROMPT},
            {"role": "user", "content": user_message},
        ]

        try:
            response = await self._provider.complete(
                messages=messages,
                tools=None,
                model=self._config.model,
                max_tokens=512,
            )
            raw = response.content.strip()
        except Exception as exc:
            logger.warning("Social Secretary: LLM evaluation failed: %s", exc)
            return None

        # Parse the response — "skip" or JSON
        if raw.lower() == "skip" or not raw:
            return None

        # Strip markdown code fences if the model wrapped its response
        if raw.startswith("```"):
            raw = re.sub(r"^```[a-zA-Z]*\n?", "", raw)
            raw = re.sub(r"\n?```$", "", raw)
            raw = raw.strip()

        try:
            data = json.loads(raw)
        except json.JSONDecodeError:
            logger.warning(
                "Social Secretary: malformed LLM response (not JSON or 'skip') — skipping item"
            )
            return None

        # Validate required fields
        try:
            confidence = float(data.get("confidence", 0.0))
        except (TypeError, ValueError):
            confidence = 0.0

        if confidence < _MIN_CONFIDENCE:
            return None

        # Build the alert — use model validation to catch invalid literal values
        try:
            alert = SocialAlert(
                source=platform,
                person=poster,
                relationship_strength="unknown",
                relationship_context=contact.relationship if contact else "unknown",
                event_type=data.get("event_type", "life_event"),
                summary=str(data.get("summary", ""))[:500],
                urgency=data.get("urgency", "low"),
                recommended_action=data.get("recommended_action", "inform_user"),
                recommended_timing=data.get("recommended_timing", "next_heartbeat"),
                confidence=confidence,
                raw_reference_id=item_id,
            )
        except Exception as exc:
            logger.warning("Social Secretary: failed to create SocialAlert: %s", exc)
            return None

        return alert

    # ------------------------------------------------------------------
    # Contact enrichment
    # ------------------------------------------------------------------

    async def _enrich_contacts(
        self,
        item: dict[str, Any],
        alert: Optional[SocialAlert],
        contacts: ContactsStore,
        platform: str,
    ) -> None:
        """Update contacts with information discovered during feed scanning.

        Rules:
        - If a known contact posted, update their ``last_updated``.
        - If an unknown person generated an alert, create a minimal entry.
        - If the LLM evaluation returned new ``new_details``, merge them.

        All updates go through ``SocialStore.upsert_contact`` which triggers
        security review.

        Security notes:
        - ``new_details`` values are LLM-generated from sanitised content.
        - The security agent reviews every write — if a post contained an
          injection attempt that leaked through to new_details, the agent will
          catch suspicious patterns.
        """
        poster = str(item.get("author", item.get("poster", item.get("user", "Unknown"))))
        if poster == "Unknown":
            return

        # Find existing contact (case-insensitive)
        existing = next(
            (c for c in contacts.contacts if c.name.lower() == poster.lower()),
            None,
        )

        if existing is None and alert is None:
            # Unknown person, not relevant — don't create a contact entry
            return

        now = datetime.now(timezone.utc)

        if existing is not None:
            # Update last_updated and merge any new details from the LLM
            new_details: dict[str, str] = {}
            if alert is not None:
                raw_nd = item.get("_new_details", {})
                if isinstance(raw_nd, dict):
                    new_details = {str(k): str(v) for k, v in raw_nd.items()}
            updated_contact = existing.model_copy(
                update={
                    "last_updated": now,
                    "relevant_details": {**existing.relevant_details, **new_details},
                }
            )
            ok, _ = await self._store.upsert_contact(updated_contact)
            if ok:
                contacts.contacts = [
                    updated_contact if c.name.lower() == poster.lower() else c
                    for c in contacts.contacts
                ]
        else:
            # Unknown person who generated an alert — create a minimal entry
            platform_id = str(item.get("id", ""))
            new_contact = ContactEntry(
                name=poster,
                relationship="unknown",
                context_learned=f"Generated alert via {platform} feed scan",
                source=platform,
                social_ids={platform: platform_id} if platform_id else {},
                attention_level="normal",
            )
            ok, _ = await self._store.upsert_contact(new_contact)
            if ok:
                contacts.contacts.append(new_contact)

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _in_active_hours(self) -> bool:
        """Return True if the current local time is within the active window."""
        now = datetime.now()
        current = now.hour * 60 + now.minute
        try:
            start_h, start_m = map(int, self._config.active_hours_start.split(":"))
            end_h, end_m = map(int, self._config.active_hours_end.split(":"))
        except (ValueError, AttributeError):
            return True  # Malformed config — allow by default
        start = start_h * 60 + start_m
        end = end_h * 60 + end_m
        return start <= current < end

    async def _audit_event(self, event: str, **details: Any) -> None:
        """Emit an audit event if an audit log is configured."""
        if self._audit is None:
            return
        await self._audit.log(
            AuditEvent(
                event=event,
                agent_id="social_secretary",
                session_key=_SS_SESSION_KEY,
                details=dict(details),
            )
        )
