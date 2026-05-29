"""Tests for openrattler.reports.email_delivery.UsageReportDelivery.

Testing focus:
- Happy path: report generated and SMTP send succeeds → send_report() returns True
- Missing smtp settings → returns False without crashing
- Report generator raises → returns False, logs warning
- Subject line contains today's date
- Body passed to SMTP is the text from the generator
- recipient_email override used when provided; fallback to default_to_address
- since= kwarg forwarded to generator; None → computed from report_window_hours
"""

from __future__ import annotations

import asyncio
from datetime import datetime, timezone
from typing import Optional
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from openrattler.config.loader import ChannelConfig, UsageReportConfig
from openrattler.reports.email_delivery import UsageReportDelivery

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


def _make_email_config(
    smtp_host: str = "smtp.example.com",
    username: str = "bot@example.com",
    password: str = "secret",
    default_to_address: str = "paul@example.com",
) -> ChannelConfig:
    """Build a ChannelConfig that has all required email settings."""
    return ChannelConfig(
        enabled=True,
        settings={
            "smtp_host": smtp_host,
            "smtp_port": 587,
            "imap_host": "imap.example.com",
            "username": username,
            "password": password,
            "sender_allowlist": [default_to_address],
            "default_to_address": default_to_address,
        },
    )


def _make_delivery(
    report_text: str = "REPORT BODY",
    email_config: Optional[ChannelConfig] = None,
    report_config: Optional[UsageReportConfig] = None,
) -> UsageReportDelivery:
    """Build a UsageReportDelivery with a mocked generator."""
    generator = MagicMock()
    generator.generate = AsyncMock(return_value=report_text)
    cfg = email_config or _make_email_config()
    rcfg = report_config or UsageReportConfig()
    return UsageReportDelivery(generator=generator, email_config=cfg, report_config=rcfg)


# ---------------------------------------------------------------------------
# Happy path
# ---------------------------------------------------------------------------


class TestSendReportSuccess:
    async def test_returns_true_on_success(self) -> None:
        """send_report() returns True when generation and SMTP both succeed."""
        delivery = _make_delivery()
        with patch("openrattler.reports.email_delivery._smtp_send_report") as mock_smtp:
            result = await delivery.send_report()
        assert result is True
        print(f"[OK] send_report() returned True; smtp called={mock_smtp.called}")

    async def test_smtp_called_with_report_body(self) -> None:
        """The report text from the generator is passed as the email body."""
        report_text = "== Token Report ==\nTotal cost: $0.42\n"
        delivery = _make_delivery(report_text=report_text)
        sent_body: list[str] = []

        def capture_send(*args: object, **kwargs: object) -> None:
            # body is the 7th positional arg: host, port, user, pass, to, subject, body
            sent_body.append(str(args[6]))

        with patch(
            "openrattler.reports.email_delivery._smtp_send_report", side_effect=capture_send
        ):
            await delivery.send_report()

        assert sent_body[0] == report_text
        print(f"[OK] report body passed to SMTP: {sent_body[0][:40]!r}")

    async def test_subject_contains_today_date(self) -> None:
        """Subject line includes today's UTC date."""
        delivery = _make_delivery()
        sent_subjects: list[str] = []

        def capture_send(*args: object, **kwargs: object) -> None:
            sent_subjects.append(str(args[5]))  # subject is 6th positional arg

        with patch(
            "openrattler.reports.email_delivery._smtp_send_report", side_effect=capture_send
        ):
            await delivery.send_report()

        today = datetime.now(timezone.utc).strftime("%Y-%m-%d")
        assert today in sent_subjects[0]
        print(f"[OK] subject={sent_subjects[0]!r} contains date {today}")

    async def test_recipient_uses_default_to_address_when_config_is_none(self) -> None:
        """Recipient falls back to email channel's default_to_address when recipient_email=None."""
        email_cfg = _make_email_config(default_to_address="paul@example.com")
        report_cfg = UsageReportConfig(recipient_email=None)
        delivery = _make_delivery(email_config=email_cfg, report_config=report_cfg)
        sent_to: list[str] = []

        def capture_send(*args: object, **kwargs: object) -> None:
            sent_to.append(str(args[4]))  # to is 5th positional arg

        with patch(
            "openrattler.reports.email_delivery._smtp_send_report", side_effect=capture_send
        ):
            await delivery.send_report()

        assert sent_to[0] == "paul@example.com"
        print(f"[OK] sent to default_to_address: {sent_to[0]}")

    async def test_recipient_override_used_when_set(self) -> None:
        """recipient_email config overrides the channel's default_to_address."""
        email_cfg = _make_email_config(default_to_address="paul@example.com")
        report_cfg = UsageReportConfig(recipient_email="other@example.com")
        delivery = _make_delivery(email_config=email_cfg, report_config=report_cfg)
        sent_to: list[str] = []

        def capture_send(*args: object, **kwargs: object) -> None:
            sent_to.append(str(args[4]))

        with patch(
            "openrattler.reports.email_delivery._smtp_send_report", side_effect=capture_send
        ):
            await delivery.send_report()

        assert sent_to[0] == "other@example.com"
        print(f"[OK] sent to recipient_email override: {sent_to[0]}")

    async def test_since_kwarg_forwarded_to_generator(self) -> None:
        """An explicit since= value is forwarded to the report generator."""
        delivery = _make_delivery()
        explicit_since = datetime(2026, 5, 28, 0, 0, 0, tzinfo=timezone.utc)

        with patch("openrattler.reports.email_delivery._smtp_send_report"):
            await delivery.send_report(since=explicit_since)

        delivery._generator.generate.assert_called_once()
        call_kwargs = delivery._generator.generate.call_args
        assert call_kwargs.kwargs.get("since") == explicit_since or (
            call_kwargs.args and call_kwargs.args[0] == explicit_since
        )
        print(f"[OK] generator called with since={explicit_since}")

    async def test_since_none_uses_report_window_hours(self) -> None:
        """When since=None, the start time is computed from report_window_hours."""
        report_cfg = UsageReportConfig(report_window_hours=12)
        delivery = _make_delivery(report_config=report_cfg)

        with patch("openrattler.reports.email_delivery._smtp_send_report"):
            await delivery.send_report(since=None)

        delivery._generator.generate.assert_called_once()
        call_kwargs = delivery._generator.generate.call_args
        since_used = call_kwargs.kwargs.get("since") or (
            call_kwargs.args[0] if call_kwargs.args else None
        )
        assert since_used is not None
        # Should be approximately 12 hours ago
        now = datetime.now(timezone.utc)
        delta = now - since_used  # type: ignore[operator]
        assert 11.9 * 3600 <= delta.total_seconds() <= 12.1 * 3600
        print(f"[OK] since computed from report_window_hours=12: delta={delta}")


# ---------------------------------------------------------------------------
# Email channel not configured
# ---------------------------------------------------------------------------


class TestEmailNotConfigured:
    async def test_missing_smtp_host_returns_false(self) -> None:
        """When smtp_host is absent, send_report() returns False without raising."""
        email_cfg = ChannelConfig(
            enabled=True,
            settings={"username": "bot@example.com", "password": "secret"},
        )
        delivery = _make_delivery(email_config=email_cfg)
        result = await delivery.send_report()
        assert result is False
        print("[OK] returns False when smtp_host missing")

    async def test_missing_username_returns_false(self) -> None:
        """When username is absent, returns False."""
        email_cfg = ChannelConfig(
            enabled=True,
            settings={"smtp_host": "smtp.example.com", "password": "secret"},
        )
        delivery = _make_delivery(email_config=email_cfg)
        result = await delivery.send_report()
        assert result is False
        print("[OK] returns False when username missing")

    async def test_missing_password_returns_false(self) -> None:
        """When password is absent, returns False."""
        email_cfg = ChannelConfig(
            enabled=True,
            settings={"smtp_host": "smtp.example.com", "username": "bot@example.com"},
        )
        delivery = _make_delivery(email_config=email_cfg)
        result = await delivery.send_report()
        assert result is False
        print("[OK] returns False when password missing")

    async def test_smtp_not_called_when_settings_missing(self) -> None:
        """The SMTP function is never called when channel settings are incomplete."""
        email_cfg = ChannelConfig(enabled=True, settings={})
        delivery = _make_delivery(email_config=email_cfg)
        with patch("openrattler.reports.email_delivery._smtp_send_report") as mock_smtp:
            await delivery.send_report()
        mock_smtp.assert_not_called()
        print("[OK] _smtp_send_report not called when settings missing")


# ---------------------------------------------------------------------------
# Generator failure
# ---------------------------------------------------------------------------


class TestGeneratorFailure:
    async def test_generator_raises_returns_false(self) -> None:
        """When the generator raises, send_report() catches and returns False."""
        generator = MagicMock()
        generator.generate = AsyncMock(side_effect=RuntimeError("store error"))
        delivery = UsageReportDelivery(
            generator=generator,
            email_config=_make_email_config(),
            report_config=UsageReportConfig(),
        )
        with patch("openrattler.reports.email_delivery._smtp_send_report") as mock_smtp:
            result = await delivery.send_report()
        assert result is False
        mock_smtp.assert_not_called()
        print("[OK] generator exception → returns False, SMTP not called")

    async def test_smtp_failure_returns_false(self) -> None:
        """When SMTP send raises, send_report() catches and returns False."""
        delivery = _make_delivery()
        with patch(
            "openrattler.reports.email_delivery._smtp_send_report",
            side_effect=ConnectionError("refused"),
        ):
            result = await delivery.send_report()
        assert result is False
        print("[OK] SMTP exception → returns False")
