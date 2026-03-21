"""Outbound channel tools — agent-initiated messaging via connected adapters.

These tools allow the main agent to proactively send messages to the user
through configured channels (SMS, Slack, Email).  They are SEPARATE from the
alert dispatch system: alerts fire automatically from processors, while these
tools are invoked explicitly by the agent in response to user requests or its
own judgment.

SECURITY NOTES
--------------
- All three tools require ``requires_approval=True`` so a human must confirm
  before any message is dispatched.  This is the primary safety gate.
- Recipient validation is strict: E.164 for SMS, ``#channel``/``@user`` for
  Slack, RFC 5322 for email.  Invalid formats are rejected before the adapter
  is called.
- An ``allowed_recipients`` set is built at construction time from the adapter's
  internal configuration so the outbound security posture mirrors the inbound
  allowlist by default.  Only recipients in this set are accepted.
- Message content is length-capped at ``OutboundChannelConfig.max_message_length``
  (default 1600 — Twilio SMS hard limit).  Truncation is audit-logged as
  ``outbound_message_truncated``.
- Audit events record the recipient as a SHA-256 hash (12-char prefix), never
  the raw address.
- Tools are only registered when the corresponding adapter is present in the
  ``adapters`` dict; absent channels produce no tool entry at all.
"""

from __future__ import annotations

import hashlib
import logging
import re
from typing import TYPE_CHECKING, Any

from openrattler.channels.base import ChannelAdapter
from openrattler.models.agents import TrustLevel
from openrattler.models.audit import AuditEvent
from openrattler.models.messages import create_message
from openrattler.models.tools import ToolDefinition

if TYPE_CHECKING:
    from openrattler.config.loader import OutboundChannelConfig
    from openrattler.storage.audit import AuditLog
    from openrattler.tools.registry import ToolRegistry

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Validation patterns
# ---------------------------------------------------------------------------

#: E.164 phone number: + then 8–15 digits.
_E164_RE: re.Pattern[str] = re.compile(r"^\+[1-9]\d{7,14}$")

#: Slack channel (#channel) or user (@user): 1–80 alphanumeric/dash/underscore chars.
_SLACK_RECIPIENT_RE: re.Pattern[str] = re.compile(r"^[#@][a-zA-Z0-9_-]{1,80}$")

#: RFC 5322-ish email: non-whitespace@non-whitespace.non-whitespace.
_EMAIL_RE: re.Pattern[str] = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")

#: Session key used in audit events.
_TOOLS_SESSION_KEY: str = "agent:main:main"

#: Truncation suffix appended when a message is cut short.
_TRUNCATION_SUFFIX: str = "[truncated]"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _hash_recipient(recipient: str) -> str:
    """Return the first 12 chars of the SHA-256 hash of *recipient*.

    Used to record audit events without exposing the raw address/number.
    """
    return hashlib.sha256(recipient.encode()).hexdigest()[:12]


def _truncate_if_needed(message: str, max_length: int) -> tuple[str, bool]:
    """Return *(text, was_truncated)*.

    If *message* fits within *max_length*, returns it unchanged with
    ``was_truncated=False``.  Otherwise truncates to fit a ``[truncated]``
    suffix within the limit.
    """
    if len(message) <= max_length:
        return message, False
    cut = max_length - len(_TRUNCATION_SUFFIX)
    return message[:cut] + _TRUNCATION_SUFFIX, True


# ---------------------------------------------------------------------------
# OutboundChannelTools
# ---------------------------------------------------------------------------


class OutboundChannelTools:
    """Container for agent-initiated outbound messaging tools.

    Each tool is only registered if the corresponding channel adapter is present
    in *adapters*.  The per-channel allowed_recipients set is seeded from the
    adapter's internal configuration so the outbound security posture mirrors
    the inbound allowlist by default.

    Args:
        adapters: Dict of ``channel_name → ChannelAdapter`` for active adapters.
                  Build from ``{a.channel_name: a for a in adapter_list}``.
        audit:    Shared audit log.
        config:   Optional ``OutboundChannelConfig`` carrying enabled flags,
                  max_message_length, and user-supplied extra allowed_recipients.
                  Defaults to ``OutboundChannelConfig()`` (all defaults).

    Security notes:
    - ``_sms_allowed``, ``_slack_allowed``, and ``_email_allowed`` are frozen
      sets built once at construction time — they are never mutated at runtime.
    - If no adapter is configured for a channel, the corresponding allowed set
      stays empty and the tool is not registered, so there is no attack surface.
    """

    def __init__(
        self,
        adapters: dict[str, ChannelAdapter],
        audit: "AuditLog",
        config: "OutboundChannelConfig | None" = None,
    ) -> None:
        from openrattler.channels.email_adapter import EmailAdapter
        from openrattler.channels.slack_adapter import SlackAdapter
        from openrattler.channels.sms_adapter import SMSAdapter
        from openrattler.config.loader import OutboundChannelConfig

        self._adapters = adapters
        self._audit = audit
        cfg = config or OutboundChannelConfig()

        self._sms_enabled: bool = cfg.sms_enabled
        self._slack_enabled: bool = cfg.slack_enabled
        self._email_enabled: bool = cfg.email_enabled
        self._max_message_length: int = cfg.max_message_length

        # ------------------------------------------------------------------
        # Build per-channel allowed_recipients sets.
        # Seeded from adapter internals; extended by user-configured extras.
        # ------------------------------------------------------------------

        sms_seed: set[str] = set(cfg.sms_allowed_recipients)
        sms_adapter = adapters.get("sms")
        if sms_adapter is not None and isinstance(sms_adapter, SMSAdapter):
            sms_seed.add(sms_adapter._from_number)
            sms_seed.update(sms_adapter._sender_allowlist)
            sms_seed.add(sms_adapter._default_to_number)
        self._sms_allowed: frozenset[str] = frozenset(sms_seed)

        slack_seed: set[str] = set(cfg.slack_allowed_recipients)
        slack_adapter = adapters.get("slack")
        if slack_adapter is not None and isinstance(slack_adapter, SlackAdapter):
            ch = slack_adapter._channel_id
            # Normalise bare channel IDs to #-prefixed form.
            if ch and not ch.startswith("#") and not ch.startswith("@"):
                ch = f"#{ch}"
            if ch:
                slack_seed.add(ch)
        self._slack_allowed: frozenset[str] = frozenset(slack_seed)

        email_seed: set[str] = set(cfg.email_allowed_recipients)
        email_adapter = adapters.get("email")
        if email_adapter is not None and isinstance(email_adapter, EmailAdapter):
            email_seed.update(email_adapter._sender_allowlist)
            email_seed.add(email_adapter._default_to_address)
        self._email_allowed: frozenset[str] = frozenset(email_seed)

    # ------------------------------------------------------------------
    # Registration
    # ------------------------------------------------------------------

    def register_all(self, registry: "ToolRegistry") -> None:
        """Register outbound channel tools for adapters present in ``self._adapters``.

        Only registers tools for channels that have a corresponding adapter entry.
        This prevents the agent from discovering a tool it can never execute.
        """
        if "sms" in self._adapters and self._sms_enabled:
            registry.register(
                ToolDefinition(
                    name="send_sms",
                    description=(
                        "Send an SMS message to a phone number. "
                        "Use this to proactively notify the user via text. "
                        "Requires explicit approval before sending."
                    ),
                    parameters={
                        "type": "object",
                        "properties": {
                            "recipient": {
                                "type": "string",
                                "description": (
                                    "Destination phone number in E.164 format "
                                    "(e.g. +15551234567)"
                                ),
                            },
                            "message": {
                                "type": "string",
                                "description": "SMS body text (max 1600 chars)",
                            },
                        },
                        "required": ["recipient", "message"],
                    },
                    requires_approval=True,
                    trust_level_required=TrustLevel.main,
                    security_notes=(
                        "Validates E.164 recipient format. "
                        "Checks recipient against SMS allowed_recipients allowlist. "
                        "Truncates body to max_message_length. "
                        "Recipient stored as SHA-256 hash in audit log."
                    ),
                ),
                self.send_sms,
            )

        if "slack" in self._adapters and self._slack_enabled:
            registry.register(
                ToolDefinition(
                    name="send_slack_message",
                    description=(
                        "Send a Slack message to a channel or user. "
                        "Use this to proactively notify the user via Slack. "
                        "Requires explicit approval before sending."
                    ),
                    parameters={
                        "type": "object",
                        "properties": {
                            "channel_or_user": {
                                "type": "string",
                                "description": (
                                    "Slack channel (e.g. #general) or user (e.g. @alice)"
                                ),
                            },
                            "message": {
                                "type": "string",
                                "description": "Message text to send",
                            },
                        },
                        "required": ["channel_or_user", "message"],
                    },
                    requires_approval=True,
                    trust_level_required=TrustLevel.main,
                    security_notes=(
                        "Validates #channel/@user format. "
                        "Checks recipient against Slack allowed_recipients allowlist. "
                        "Truncates to max_message_length. "
                        "Recipient stored as SHA-256 hash in audit log."
                    ),
                ),
                self.send_slack_message,
            )

        if "email" in self._adapters and self._email_enabled:
            registry.register(
                ToolDefinition(
                    name="send_email",
                    description=(
                        "Send an email to a recipient address. "
                        "Use this to proactively notify the user by email. "
                        "Requires explicit approval before sending."
                    ),
                    parameters={
                        "type": "object",
                        "properties": {
                            "to_address": {
                                "type": "string",
                                "description": "Recipient email address",
                            },
                            "subject": {
                                "type": "string",
                                "description": "Email subject line",
                            },
                            "body": {
                                "type": "string",
                                "description": "Email body text",
                            },
                        },
                        "required": ["to_address", "subject", "body"],
                    },
                    requires_approval=True,
                    trust_level_required=TrustLevel.main,
                    security_notes=(
                        "Validates RFC 5322 email format. "
                        "Checks recipient against email allowed_recipients allowlist. "
                        "Truncates body to max_message_length. "
                        "Recipient stored as SHA-256 hash in audit log."
                    ),
                ),
                self.send_email,
            )

    # ------------------------------------------------------------------
    # Tool handlers
    # ------------------------------------------------------------------

    async def send_sms(self, recipient: str, message: str) -> dict[str, Any]:
        """Send *message* as an SMS to *recipient*.

        Validates format, checks the allowlist, truncates if needed, then
        dispatches through the SMS adapter.

        Args:
            recipient: E.164 phone number (e.g. ``+15551234567``).
            message:   SMS body text.

        Returns:
            Dict with ``success=True`` and ``recipient_hash`` on success, or
            ``success=False`` and ``error`` on validation failure or send error.
        """
        if not _E164_RE.match(recipient):
            return {
                "success": False,
                "error": (
                    f"Invalid SMS recipient '{recipient}': "
                    "must be in E.164 format (e.g. +15551234567)"
                ),
            }

        if recipient not in self._sms_allowed:
            logger.warning(
                "send_sms: recipient not in allowlist (hash=%s)", _hash_recipient(recipient)
            )
            return {
                "success": False,
                "error": (
                    f"Recipient '{recipient}' is not in the SMS allowed_recipients list. "
                    "Add it to outbound_channels.sms_allowed_recipients in config to permit."
                ),
            }

        body, truncated = _truncate_if_needed(message, self._max_message_length)
        if truncated:
            await self._audit.log(
                AuditEvent(
                    event="outbound_message_truncated",
                    agent_id="channel_tools",
                    session_key=_TOOLS_SESSION_KEY,
                    details={
                        "channel": "sms",
                        "original_length": len(message),
                        "max_length": self._max_message_length,
                    },
                )
            )

        adapter = self._adapters.get("sms")
        if adapter is None:
            return {"success": False, "error": "SMS adapter not available"}

        send_msg = create_message(
            from_agent="channel_tools",
            to_agent="sms",
            session_key=_TOOLS_SESSION_KEY,
            type="request",
            operation="send_sms",
            trust_level="main",
            params={"to": recipient, "body": body},
        )

        recipient_hash = _hash_recipient(recipient)
        try:
            await adapter.send(send_msg)
        except Exception as exc:
            logger.exception("send_sms failed for recipient_hash=%s", recipient_hash)
            await self._audit.log(
                AuditEvent(
                    event="outbound_message_failed",
                    agent_id="channel_tools",
                    session_key=_TOOLS_SESSION_KEY,
                    details={
                        "channel": "sms",
                        "recipient_hash": recipient_hash,
                        "message_length": len(body),
                        "error": str(exc),
                    },
                )
            )
            return {"success": False, "error": f"SMS send failed: {exc}"}

        await self._audit.log(
            AuditEvent(
                event="outbound_message_sent",
                agent_id="channel_tools",
                session_key=_TOOLS_SESSION_KEY,
                details={
                    "channel": "sms",
                    "recipient_hash": recipient_hash,
                    "message_length": len(body),
                },
            )
        )
        return {
            "success": True,
            "channel": "sms",
            "recipient_hash": recipient_hash,
            "message_length": len(body),
        }

    async def send_slack_message(self, channel_or_user: str, message: str) -> dict[str, Any]:
        """Send *message* to a Slack *channel_or_user*.

        Args:
            channel_or_user: Slack channel (``#general``) or user (``@alice``).
            message:         Message text.

        Returns:
            Dict with ``success=True`` on success, or ``success=False`` and
            ``error`` on validation failure or send error.
        """
        if not _SLACK_RECIPIENT_RE.match(channel_or_user):
            return {
                "success": False,
                "error": (
                    f"Invalid Slack recipient '{channel_or_user}': "
                    "must be a channel (#general) or user (@alice)"
                ),
            }

        if channel_or_user not in self._slack_allowed:
            logger.warning(
                "send_slack_message: recipient not in allowlist (hash=%s)",
                _hash_recipient(channel_or_user),
            )
            return {
                "success": False,
                "error": (
                    f"Recipient '{channel_or_user}' is not in the Slack allowed_recipients list. "
                    "Add it to outbound_channels.slack_allowed_recipients in config to permit."
                ),
            }

        body, truncated = _truncate_if_needed(message, self._max_message_length)
        if truncated:
            await self._audit.log(
                AuditEvent(
                    event="outbound_message_truncated",
                    agent_id="channel_tools",
                    session_key=_TOOLS_SESSION_KEY,
                    details={
                        "channel": "slack",
                        "original_length": len(message),
                        "max_length": self._max_message_length,
                    },
                )
            )

        adapter = self._adapters.get("slack")
        if adapter is None:
            return {"success": False, "error": "Slack adapter not available"}

        # Strip the #/@ decorator before passing to the adapter — the tool
        # validation format uses "#channel" / "@user" but Slack's API expects
        # bare channel IDs ("C0ABC123") or channel/user names without the prefix.
        slack_channel = channel_or_user.lstrip("#@")
        send_msg = create_message(
            from_agent="channel_tools",
            to_agent="slack",
            session_key=_TOOLS_SESSION_KEY,
            type="request",
            operation="send_slack_message",
            trust_level="main",
            params={"channel": slack_channel, "text": body},
        )

        recipient_hash = _hash_recipient(channel_or_user)
        try:
            await adapter.send(send_msg)
        except Exception as exc:
            logger.exception("send_slack_message failed for recipient_hash=%s", recipient_hash)
            await self._audit.log(
                AuditEvent(
                    event="outbound_message_failed",
                    agent_id="channel_tools",
                    session_key=_TOOLS_SESSION_KEY,
                    details={
                        "channel": "slack",
                        "recipient_hash": recipient_hash,
                        "message_length": len(body),
                        "error": str(exc),
                    },
                )
            )
            return {"success": False, "error": f"Slack send failed: {exc}"}

        await self._audit.log(
            AuditEvent(
                event="outbound_message_sent",
                agent_id="channel_tools",
                session_key=_TOOLS_SESSION_KEY,
                details={
                    "channel": "slack",
                    "recipient_hash": recipient_hash,
                    "message_length": len(body),
                },
            )
        )
        return {
            "success": True,
            "channel": "slack",
            "recipient_hash": recipient_hash,
            "message_length": len(body),
        }

    async def send_email(self, to_address: str, subject: str, body: str) -> dict[str, Any]:
        """Send an email to *to_address* with the given *subject* and *body*.

        Args:
            to_address: Recipient email address.
            subject:    Email subject line.
            body:       Email body text.

        Returns:
            Dict with ``success=True`` on success, or ``success=False`` and
            ``error`` on validation failure or send error.
        """
        if not _EMAIL_RE.match(to_address):
            return {
                "success": False,
                "error": (
                    f"Invalid email address '{to_address}': " "must be in user@domain.tld format"
                ),
            }

        if to_address not in self._email_allowed:
            logger.warning(
                "send_email: recipient not in allowlist (hash=%s)",
                _hash_recipient(to_address),
            )
            return {
                "success": False,
                "error": (
                    f"Recipient '{to_address}' is not in the email allowed_recipients list. "
                    "Add it to outbound_channels.email_allowed_recipients in config to permit."
                ),
            }

        truncated_body, was_truncated = _truncate_if_needed(body, self._max_message_length)
        if was_truncated:
            await self._audit.log(
                AuditEvent(
                    event="outbound_message_truncated",
                    agent_id="channel_tools",
                    session_key=_TOOLS_SESSION_KEY,
                    details={
                        "channel": "email",
                        "original_length": len(body),
                        "max_length": self._max_message_length,
                    },
                )
            )

        adapter = self._adapters.get("email")
        if adapter is None:
            return {"success": False, "error": "Email adapter not available"}

        send_msg = create_message(
            from_agent="channel_tools",
            to_agent="email",
            session_key=_TOOLS_SESSION_KEY,
            type="request",
            operation="send_email",
            trust_level="main",
            params={"to": to_address, "subject": subject, "body": truncated_body},
        )

        recipient_hash = _hash_recipient(to_address)
        try:
            await adapter.send(send_msg)
        except Exception as exc:
            logger.exception("send_email failed for recipient_hash=%s", recipient_hash)
            await self._audit.log(
                AuditEvent(
                    event="outbound_message_failed",
                    agent_id="channel_tools",
                    session_key=_TOOLS_SESSION_KEY,
                    details={
                        "channel": "email",
                        "recipient_hash": recipient_hash,
                        "message_length": len(truncated_body),
                        "error": str(exc),
                    },
                )
            )
            return {"success": False, "error": f"Email send failed: {exc}"}

        await self._audit.log(
            AuditEvent(
                event="outbound_message_sent",
                agent_id="channel_tools",
                session_key=_TOOLS_SESSION_KEY,
                details={
                    "channel": "email",
                    "recipient_hash": recipient_hash,
                    "message_length": len(truncated_body),
                },
            )
        )
        return {
            "success": True,
            "channel": "email",
            "recipient_hash": recipient_hash,
            "message_length": len(truncated_body),
        }
