"""Tests for openrattler.tools.builtin.channel_tools — OutboundChannelTools."""

from __future__ import annotations

from pathlib import Path
from typing import Any
from unittest.mock import AsyncMock, MagicMock

import pytest

from openrattler.channels.base import ChannelAdapter
from openrattler.config.loader import OutboundChannelConfig
from openrattler.models.agents import TrustLevel
from openrattler.storage.audit import AuditLog
from openrattler.tools.builtin.channel_tools import OutboundChannelTools, _hash_recipient
from openrattler.tools.registry import ToolRegistry

# ---------------------------------------------------------------------------
# Fixtures and helpers
# ---------------------------------------------------------------------------


def _make_audit(tmp_path: Path) -> AuditLog:
    return AuditLog(tmp_path / "audit.jsonl")


def _make_registry() -> ToolRegistry:
    return ToolRegistry()


def _make_sms_adapter(
    from_number: str = "+15550001111",
    sender_allowlist: list[str] | None = None,
    default_to_number: str = "+15550001111",
) -> MagicMock:
    """Return a MagicMock resembling a connected SMSAdapter."""
    from openrattler.channels.sms_adapter import SMSAdapter

    adapter = MagicMock(spec=SMSAdapter)
    adapter.channel_name = "sms"
    adapter._connected = True
    adapter._from_number = from_number
    adapter._sender_allowlist = set(sender_allowlist or ["+15550001111"])
    adapter._default_to_number = default_to_number
    adapter.send = AsyncMock(return_value=None)
    return adapter


def _make_slack_adapter(
    channel_id: str = "#general",
    sender_allowlist: list[str] | None = None,
) -> MagicMock:
    from openrattler.channels.slack_adapter import SlackAdapter

    adapter = MagicMock(spec=SlackAdapter)
    adapter.channel_name = "slack"
    adapter._connected = True
    adapter._channel_id = channel_id
    adapter._sender_allowlist = set(sender_allowlist or ["U12345"])
    adapter.send = AsyncMock(return_value=None)
    return adapter


def _make_email_adapter(
    username: str = "me@example.com",
    sender_allowlist: list[str] | None = None,
    default_to_address: str = "me@example.com",
) -> MagicMock:
    from openrattler.channels.email_adapter import EmailAdapter

    adapter = MagicMock(spec=EmailAdapter)
    adapter.channel_name = "email"
    adapter._connected = True
    adapter._username = username
    adapter._sender_allowlist = set(sender_allowlist or ["me@example.com"])
    adapter._default_to_address = default_to_address
    adapter.send = AsyncMock(return_value=None)
    return adapter


def _make_tools(
    tmp_path: Path,
    adapters: dict[str, Any] | None = None,
    config: OutboundChannelConfig | None = None,
) -> tuple[OutboundChannelTools, ToolRegistry, AuditLog]:
    audit = _make_audit(tmp_path)
    registry = _make_registry()
    tools = OutboundChannelTools(
        adapters=adapters or {},
        audit=audit,
        config=config,
    )
    tools.register_all(registry)
    return tools, registry, audit


# ---------------------------------------------------------------------------
# TestOutboundChannelTools
# ---------------------------------------------------------------------------


class TestOutboundChannelTools:
    # ------------------------------------------------------------------
    # Registration
    # ------------------------------------------------------------------

    def test_send_sms_registered_when_adapter_present(self, tmp_path: Path) -> None:
        adapter = _make_sms_adapter()
        _, registry, _ = _make_tools(tmp_path, {"sms": adapter})
        assert registry.get("send_sms") is not None

    def test_send_sms_not_registered_when_no_sms_adapter(self, tmp_path: Path) -> None:
        _, registry, _ = _make_tools(tmp_path, {})
        assert registry.get("send_sms") is None

    def test_send_slack_registered_when_adapter_present(self, tmp_path: Path) -> None:
        adapter = _make_slack_adapter()
        _, registry, _ = _make_tools(tmp_path, {"slack": adapter})
        assert registry.get("send_slack_message") is not None

    def test_send_email_registered_when_adapter_present(self, tmp_path: Path) -> None:
        adapter = _make_email_adapter()
        _, registry, _ = _make_tools(tmp_path, {"email": adapter})
        assert registry.get("send_email") is not None

    def test_all_sends_require_approval_flag(self, tmp_path: Path) -> None:
        sms = _make_sms_adapter()
        slack = _make_slack_adapter()
        email = _make_email_adapter()
        _, registry, _ = _make_tools(tmp_path, {"sms": sms, "slack": slack, "email": email})
        for name in ("send_sms", "send_slack_message", "send_email"):
            tool_def = registry.get(name)
            assert tool_def is not None
            assert tool_def.requires_approval is True, f"{name} must require approval"

    def test_all_sends_require_main_trust_level(self, tmp_path: Path) -> None:
        sms = _make_sms_adapter()
        slack = _make_slack_adapter()
        email = _make_email_adapter()
        _, registry, _ = _make_tools(tmp_path, {"sms": sms, "slack": slack, "email": email})
        for name in ("send_sms", "send_slack_message", "send_email"):
            tool_def = registry.get(name)
            assert tool_def is not None
            assert (
                tool_def.trust_level_required == TrustLevel.main
            ), f"{name} must require main trust level"

    # ------------------------------------------------------------------
    # SMS validation and dispatch
    # ------------------------------------------------------------------

    async def test_send_sms_valid_e164_succeeds(self, tmp_path: Path) -> None:
        adapter = _make_sms_adapter(from_number="+15550001111")
        tools, _, _ = _make_tools(tmp_path, {"sms": adapter})

        result = await tools.send_sms(recipient="+15550001111", message="Hello")

        assert result["success"] is True
        adapter.send.assert_called_once()

    async def test_send_sms_invalid_recipient_returns_error(self, tmp_path: Path) -> None:
        adapter = _make_sms_adapter()
        tools, _, _ = _make_tools(tmp_path, {"sms": adapter})

        result = await tools.send_sms(recipient="not-a-number", message="Hello")

        assert result["success"] is False
        assert "E.164" in result["error"]
        adapter.send.assert_not_called()

    async def test_send_sms_recipient_not_in_allowlist_returns_error(self, tmp_path: Path) -> None:
        adapter = _make_sms_adapter(
            from_number="+15550001111",
            sender_allowlist=["+15550001111"],
            default_to_number="+15550001111",
        )
        tools, _, _ = _make_tools(tmp_path, {"sms": adapter})

        result = await tools.send_sms(recipient="+19999999999", message="Hello")

        assert result["success"] is False
        assert "allowed_recipients" in result["error"]
        adapter.send.assert_not_called()

    async def test_send_sms_message_truncated_at_max_length(self, tmp_path: Path) -> None:
        adapter = _make_sms_adapter(from_number="+15550001111")
        cfg = OutboundChannelConfig(max_message_length=20)
        tools, _, audit = _make_tools(tmp_path, {"sms": adapter}, config=cfg)

        long_msg = "A" * 50
        result = await tools.send_sms(recipient="+15550001111", message=long_msg)

        assert result["success"] is True
        # The sent params should have a truncated body
        sent_msg = adapter.send.call_args[0][0]
        assert len(sent_msg.params["body"]) == 20
        assert sent_msg.params["body"].endswith("[truncated]")

        events = await audit.query(limit=20)
        assert any(e.event == "outbound_message_truncated" for e in events)

    # ------------------------------------------------------------------
    # Slack validation and dispatch
    # ------------------------------------------------------------------

    async def test_send_slack_valid_channel_succeeds(self, tmp_path: Path) -> None:
        adapter = _make_slack_adapter(channel_id="#general")
        tools, _, _ = _make_tools(tmp_path, {"slack": adapter})

        result = await tools.send_slack_message(channel_or_user="#general", message="Hi")

        assert result["success"] is True
        adapter.send.assert_called_once()

    async def test_send_slack_valid_user_succeeds(self, tmp_path: Path) -> None:
        adapter = _make_slack_adapter(channel_id="#general")
        cfg = OutboundChannelConfig(slack_allowed_recipients=["@alice"])
        tools, _, _ = _make_tools(tmp_path, {"slack": adapter}, config=cfg)

        result = await tools.send_slack_message(channel_or_user="@alice", message="Hi")

        assert result["success"] is True

    async def test_send_slack_invalid_recipient_format_returns_error(self, tmp_path: Path) -> None:
        adapter = _make_slack_adapter()
        tools, _, _ = _make_tools(tmp_path, {"slack": adapter})

        result = await tools.send_slack_message(
            channel_or_user="general", message="Hi"  # missing # or @
        )

        assert result["success"] is False
        assert "#channel" in result["error"] or "@" in result["error"]
        adapter.send.assert_not_called()

    # ------------------------------------------------------------------
    # Email validation and dispatch
    # ------------------------------------------------------------------

    async def test_send_email_valid_address_succeeds(self, tmp_path: Path) -> None:
        adapter = _make_email_adapter(default_to_address="me@example.com")
        tools, _, _ = _make_tools(tmp_path, {"email": adapter})

        result = await tools.send_email(to_address="me@example.com", subject="Test", body="Hello")

        assert result["success"] is True
        adapter.send.assert_called_once()

    async def test_send_email_invalid_address_returns_error(self, tmp_path: Path) -> None:
        adapter = _make_email_adapter()
        tools, _, _ = _make_tools(tmp_path, {"email": adapter})

        result = await tools.send_email(to_address="not-an-email", subject="Test", body="Hello")

        assert result["success"] is False
        assert "email address" in result["error"].lower() or "@" in result["error"]
        adapter.send.assert_not_called()

    # ------------------------------------------------------------------
    # Audit events
    # ------------------------------------------------------------------

    async def test_audit_event_written_on_success(self, tmp_path: Path) -> None:
        """Successful send writes outbound_message_sent with hashed recipient."""
        adapter = _make_sms_adapter(from_number="+15550001111")
        tools, _, audit = _make_tools(tmp_path, {"sms": adapter})

        await tools.send_sms(recipient="+15550001111", message="Hello")

        events = await audit.query(limit=20)
        sent_events = [e for e in events if e.event == "outbound_message_sent"]
        assert len(sent_events) == 1
        # Recipient is hashed, not raw
        assert "recipient_hash" in sent_events[0].details
        assert sent_events[0].details["recipient_hash"] == _hash_recipient("+15550001111")
        assert "+15550001111" not in str(sent_events[0].details)

    async def test_audit_event_written_on_failure(self, tmp_path: Path) -> None:
        """Failed send writes outbound_message_failed with hashed recipient."""
        adapter = _make_sms_adapter(from_number="+15550001111")
        adapter.send = AsyncMock(side_effect=RuntimeError("Twilio error"))
        tools, _, audit = _make_tools(tmp_path, {"sms": adapter})

        result = await tools.send_sms(recipient="+15550001111", message="Hello")

        assert result["success"] is False
        events = await audit.query(limit=20)
        failed_events = [e for e in events if e.event == "outbound_message_failed"]
        assert len(failed_events) == 1
        assert "recipient_hash" in failed_events[0].details

    # ------------------------------------------------------------------
    # Approval context
    # ------------------------------------------------------------------

    def test_approval_context_contains_recipient_preview(self, tmp_path: Path) -> None:
        """Tool schema includes recipient and message parameters for the approval prompt."""
        adapter = _make_sms_adapter()
        _, registry, _ = _make_tools(tmp_path, {"sms": adapter})

        tool_def = registry.get("send_sms")
        assert tool_def is not None
        props = tool_def.parameters["properties"]
        # Both recipient and message must be in the schema so the approval
        # context (= tool arguments) always shows what will be sent and to whom.
        assert "recipient" in props
        assert "message" in props

    # ------------------------------------------------------------------
    # Allowlist enforcement
    # ------------------------------------------------------------------

    def test_empty_allowlist_blocks_all_recipients(self, tmp_path: Path) -> None:
        """With no seeded adapter, the allowlist is empty and all sends are blocked."""
        # No adapter configured → no seeding → empty allowlist
        tools = OutboundChannelTools(adapters={}, audit=_make_audit(tmp_path))
        # We can't call send_sms because sms isn't even in adapters,
        # but test the underlying set directly.
        assert tools._sms_allowed == frozenset()
        assert tools._slack_allowed == frozenset()
        assert tools._email_allowed == frozenset()

    async def test_allowlist_with_entry_allows_matching_recipient(self, tmp_path: Path) -> None:
        """An explicitly configured allowed_recipients entry permits that recipient."""
        adapter = _make_sms_adapter(
            from_number="+15550001111",
            sender_allowlist=["+15550001111"],
            default_to_number="+15550001111",
        )
        # Add an extra allowed number via config
        cfg = OutboundChannelConfig(sms_allowed_recipients=["+15559998888"])
        tools, _, _ = _make_tools(tmp_path, {"sms": adapter}, config=cfg)

        result = await tools.send_sms(recipient="+15559998888", message="Test")
        assert result["success"] is True

    # ------------------------------------------------------------------
    # Truncation audit event
    # ------------------------------------------------------------------

    async def test_truncation_audit_event_written(self, tmp_path: Path) -> None:
        adapter = _make_sms_adapter(from_number="+15550001111")
        cfg = OutboundChannelConfig(max_message_length=30)
        tools, _, audit = _make_tools(tmp_path, {"sms": adapter}, config=cfg)

        await tools.send_sms(recipient="+15550001111", message="X" * 100)

        events = await audit.query(limit=20)
        truncation_events = [e for e in events if e.event == "outbound_message_truncated"]
        assert len(truncation_events) == 1
        assert truncation_events[0].details["channel"] == "sms"
        assert truncation_events[0].details["original_length"] == 100

    # ------------------------------------------------------------------
    # Trust level guard (extra)
    # ------------------------------------------------------------------

    def test_tools_trust_level_is_main_not_lower(self, tmp_path: Path) -> None:
        sms = _make_sms_adapter()
        _, registry, _ = _make_tools(tmp_path, {"sms": sms})
        tool_def = registry.get("send_sms")
        assert tool_def is not None
        assert tool_def.trust_level_required == TrustLevel.main
        assert tool_def.trust_level_required != TrustLevel.public
        assert tool_def.trust_level_required != TrustLevel.mcp
