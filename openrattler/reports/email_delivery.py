"""Usage report email delivery (piece 45.5).

Generates a token economy report from UsageStore and delivers it via SMTP.
The report summarises per-session token costs, context growth trends, and
active/closed session breakdowns for the configured time window.

Security notes:
- ``password`` is never logged, audited, or included in exception messages.
- Report content contains only aggregate token counts and cost estimates;
  no message body content, user data, or raw LLM responses are included.
- SMTP connection uses STARTTLS (port 587 default).
"""

from __future__ import annotations

import asyncio
import logging
import smtplib
import ssl
from datetime import datetime, timedelta, timezone
from email.mime.text import MIMEText
from typing import Optional

from openrattler.config.loader import ChannelConfig, UsageReportConfig
from openrattler.reports.usage_report import UsageReportGenerator

logger = logging.getLogger(__name__)

#: SMTP connection timeout in seconds.
_SMTP_TIMEOUT: int = 30

#: Default SMTP port (STARTTLS).
_DEFAULT_SMTP_PORT: int = 587


# ---------------------------------------------------------------------------
# Sync SMTP helper (run in thread)
# ---------------------------------------------------------------------------


def _smtp_send_report(
    smtp_host: str,
    smtp_port: int,
    username: str,
    password: str,
    to: str,
    subject: str,
    body: str,
) -> None:
    """Deliver a report email via SMTP with STARTTLS.

    Args:
        smtp_host: SMTP hostname.
        smtp_port: SMTP port (typically 587 for STARTTLS).
        username:  Account login name.  Used as the From address.
        password:  Account password / app password.  Never logged.
        to:        Recipient email address.
        subject:   Message subject line.
        body:      Plain-text message body.

    Raises:
        smtplib.SMTPException or network exception on failure.
    """
    context = ssl.create_default_context()
    with smtplib.SMTP(smtp_host, smtp_port, timeout=_SMTP_TIMEOUT) as server:
        server.ehlo()
        server.starttls(context=context)
        server.ehlo()
        server.login(username, password)
        mime_msg = MIMEText(body, "plain")
        mime_msg["From"] = username
        mime_msg["To"] = to
        mime_msg["Subject"] = subject
        server.send_message(mime_msg)


# ---------------------------------------------------------------------------
# UsageReportDelivery
# ---------------------------------------------------------------------------


class UsageReportDelivery:
    """Generates a token economy report and delivers it via email.

    Args:
        generator:     ``UsageReportGenerator`` that reads from the UsageStore.
        email_config:  ``ChannelConfig`` for the email channel.  Must contain
                       ``smtp_host``, ``username``, and ``password`` in its
                       ``settings`` dict for delivery to work.
        report_config: ``UsageReportConfig`` controlling window size and recipient.
    """

    def __init__(
        self,
        generator: UsageReportGenerator,
        email_config: ChannelConfig,
        report_config: UsageReportConfig,
    ) -> None:
        self._generator = generator
        self._email_config = email_config
        self._report_config = report_config

    async def send_report(self, since: Optional[datetime] = None) -> bool:
        """Generate and email the usage report.

        Args:
            since: Start of the report window (UTC).  Defaults to
                   ``report_config.report_window_hours`` ago.

        Returns:
            True if the report was generated and sent successfully.
            False if the email channel is not configured, generation fails,
            or the SMTP send fails.  Failures are logged at WARNING level
            and never propagate as exceptions.
        """
        settings = self._email_config.settings
        smtp_host = str(settings.get("smtp_host", ""))
        smtp_port = int(settings.get("smtp_port", _DEFAULT_SMTP_PORT))
        username = str(settings.get("username", ""))
        password = str(settings.get("password", ""))
        to_address = self._report_config.recipient_email or str(
            settings.get("default_to_address", username)
        )

        if not smtp_host or not username or not password:
            logger.info(
                "UsageReportDelivery: email channel missing smtp_host/username/password — skipping"
            )
            return False

        if since is None:
            since = datetime.now(timezone.utc) - timedelta(
                hours=self._report_config.report_window_hours
            )

        try:
            report_text = await self._generator.generate(since=since)
        except Exception as exc:
            logger.warning("UsageReportDelivery: report generation failed: %s", exc)
            return False

        date_str = datetime.now(timezone.utc).strftime("%Y-%m-%d")
        subject = f"OpenRattler Token Report — {date_str}"

        try:
            await asyncio.to_thread(
                _smtp_send_report,
                smtp_host,
                smtp_port,
                username,
                password,
                to_address,
                subject,
                report_text,
            )
        except Exception as exc:
            logger.warning("UsageReportDelivery: SMTP send failed: %s", exc)
            return False

        logger.info("UsageReportDelivery: report sent to %s (since=%s)", to_address, since.date())
        return True
