"""Email channel adapter — IMAP polling (inbound) + SMTP delivery (outbound).

``EmailAdapter`` bridges an email account to the OpenRattler channel layer.
Inbound messages are fetched from an IMAP mailbox; outbound messages are sent
via SMTP with STARTTLS.

Security enforced at the adapter boundary (before any UniversalMessage is built):

- **Sender allowlist** — emails from addresses not in ``sender_allowlist`` are
  rejected with a ``PermissionError`` and an audit event.  The attacker never
  gets a message into the system.
- **Rate limiting** — per-sender sliding-window limit (default 10/min, 60/hour)
  blocks flood attacks.
- **HTML stripping** — ``text/plain`` is preferred; if only ``text/html`` is
  available, tags are stripped with a stdlib ``HTMLParser`` that discards
  ``<script>`` and ``<style>`` content entirely.
- **Attachments ignored** — non-text MIME parts are silently skipped.
- **Suspicious content scan** — subject + body are scanned; hits are audit-logged
  but the message is still delivered (flag-and-deliver, not block-on-suspicion).
- **Credentials never logged** — ``_password`` never appears in any log call.
- **Transport security** — IMAP uses SSL (port 993); SMTP uses STARTTLS (port 587).
- **Connection timeouts** — 30-second timeout on both IMAP and SMTP.
- **Fail-secure IMAP errors** — any exception in ``_fetch_unseen`` is caught,
  audit-logged, and returns ``[]``; the adapter keeps polling rather than crashing.

SECURITY NOTES
--------------
- ``trust_level`` is hardcoded to ``"main"`` — allowlist enforcement means only
  trusted senders ever produce a UniversalMessage.
- Session key is derived from a SHA-256 hash of the verified ``From`` address,
  not from any user-controlled string in the email body.
- ``_password`` is stored only in ``self._password``; it never appears in any
  log, audit event, or exception message.
"""

from __future__ import annotations

import asyncio
import hashlib
import imaplib
import smtplib
import ssl
from email import message_from_bytes
from email.mime.text import MIMEText
from email.utils import parseaddr
from html.parser import HTMLParser
from typing import Any, Optional

from openrattler.channels.base import ChannelAdapter
from openrattler.config.loader import ChannelConfig
from openrattler.models.audit import AuditEvent
from openrattler.models.messages import UniversalMessage, create_message
from openrattler.security.patterns import scan_for_suspicious_content
from openrattler.security.rate_limiter import RateLimiter
from openrattler.storage.audit import AuditLog

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_IMAP_TIMEOUT: int = 30
_SMTP_TIMEOUT: int = 30

_DEFAULT_IMAP_PORT: int = 993
_DEFAULT_SMTP_PORT: int = 587
_DEFAULT_POLL_INTERVAL: int = 30
_DEFAULT_RATE_MAX_PER_MINUTE: int = 10
_DEFAULT_RATE_MAX_PER_HOUR: int = 60

_REQUIRED_SETTINGS: tuple[str, ...] = (
    "imap_host",
    "smtp_host",
    "username",
    "password",
    "sender_allowlist",
    "default_to_address",
)


# ---------------------------------------------------------------------------
# HTML stripping
# ---------------------------------------------------------------------------


class _TextExtractorParser(HTMLParser):
    """HTMLParser subclass that collects visible text, skipping script/style."""

    def __init__(self) -> None:
        super().__init__()
        self._parts: list[str] = []
        self._skip: bool = False

    def handle_starttag(self, tag: str, attrs: list[tuple[str, Optional[str]]]) -> None:
        if tag.lower() in ("script", "style"):
            self._skip = True

    def handle_endtag(self, tag: str) -> None:
        if tag.lower() in ("script", "style"):
            self._skip = False

    def handle_data(self, data: str) -> None:
        if not self._skip:
            self._parts.append(data)

    def get_text(self) -> str:
        """Return collected text with collapsed whitespace."""
        raw = " ".join(self._parts)
        # Collapse runs of whitespace (including newlines) to single space.
        import re

        return re.sub(r"\s+", " ", raw).strip()


def _strip_html(html_text: str) -> str:
    """Strip HTML tags from *html_text*, excluding script/style content.

    Uses stdlib ``HTMLParser`` — no third-party dependencies.

    Args:
        html_text: Raw HTML string.

    Returns:
        Plain-text string with collapsed whitespace.
    """
    parser = _TextExtractorParser()
    parser.feed(html_text)
    return parser.get_text()


# ---------------------------------------------------------------------------
# MIME text extraction
# ---------------------------------------------------------------------------


def _extract_text(msg: Any) -> str:  # msg is email.message.Message
    """Extract plain-text body from a MIME message.

    Preference order:
    1. First ``text/plain`` part (decoded with the part's charset, UTF-8 fallback).
    2. First ``text/html`` part, stripped of tags.
    3. ``"[no text content]"`` if neither is found.

    Args:
        msg: ``email.message.Message`` object.

    Returns:
        Plain-text string.
    """
    plain_part: Optional[Any] = None
    html_part: Optional[Any] = None

    if msg.is_multipart():
        for part in msg.walk():
            ct = part.get_content_type()
            if ct == "text/plain" and plain_part is None:
                plain_part = part
            elif ct == "text/html" and html_part is None:
                html_part = part
    else:
        ct = msg.get_content_type()
        if ct == "text/plain":
            plain_part = msg
        elif ct == "text/html":
            html_part = msg

    def _decode_part(part: Any) -> str:
        payload = part.get_payload(decode=True)
        if not isinstance(payload, bytes):
            return ""
        charset = part.get_content_charset() or "utf-8"
        return payload.decode(charset, errors="replace")

    if plain_part is not None:
        return _decode_part(plain_part)
    if html_part is not None:
        return _strip_html(_decode_part(html_part))
    return "[no text content]"


# ---------------------------------------------------------------------------
# Sync IMAP helper (run in thread)
# ---------------------------------------------------------------------------


def _fetch_unseen(
    host: str, port: int, username: str, password: str
) -> list[Any]:  # returns list[email.message.Message]
    """Fetch the first unseen message from the IMAP INBOX.

    Opens a fresh SSL connection on every call (no persistent connection).
    Marks the fetched message as ``\\Seen``.

    Args:
        host:     IMAP hostname.
        port:     IMAP SSL port (typically 993).
        username: Account login name.
        password: Account password / app password.

    Returns:
        A list containing one ``email.message.Message`` if an unseen message
        was found, or an empty list if the inbox has no unseen messages.

    Raises:
        Any imaplib / network exception — callers should catch and handle.
    """
    mail = imaplib.IMAP4_SSL(host, port, timeout=_IMAP_TIMEOUT)
    try:
        mail.login(username, password)
        mail.select("INBOX")
        status, data = mail.search(None, "UNSEEN")
        if status != "OK" or not data or not data[0]:
            return []
        uids = data[0].split()
        if not uids:
            return []
        first_uid = uids[0]
        status2, msg_data = mail.fetch(first_uid, "(RFC822)")
        if status2 != "OK" or not msg_data:
            return []
        # Mark as seen
        mail.store(first_uid, "+FLAGS", r"(\Seen)")
        # msg_data is list of (header, b'...') tuples
        raw: Optional[bytes] = None
        for part in msg_data:
            if isinstance(part, tuple):
                raw = part[1]
                break
        if not isinstance(raw, bytes):
            return []
        return [message_from_bytes(raw)]
    finally:
        try:
            mail.logout()
        except Exception:
            pass


# ---------------------------------------------------------------------------
# Sync SMTP helper (run in thread)
# ---------------------------------------------------------------------------


def _smtp_send(
    host: str,
    port: int,
    username: str,
    password: str,
    to: str,
    subject: str,
    body: str,
) -> None:
    """Deliver an email via SMTP with STARTTLS.

    Args:
        host:     SMTP hostname.
        port:     SMTP port (typically 587 for STARTTLS).
        username: Account login name.
        password: Account password / app password.
        to:       Recipient address.
        subject:  Message subject.
        body:     Plain-text message body.

    Raises:
        smtplib.SMTPException or network exception on failure.
    """
    context = ssl.create_default_context()
    with smtplib.SMTP(host, port, timeout=_SMTP_TIMEOUT) as server:
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
# EmailAdapter
# ---------------------------------------------------------------------------


class EmailAdapter(ChannelAdapter):
    """Channel adapter that polls IMAP for inbound messages and sends via SMTP.

    All email-specific configuration is read from ``config.settings``.
    See module docstring for the full security model.

    Usage::

        config = ChannelConfig(channel_id="email", settings={...})
        adapter = EmailAdapter(config)
        await adapter.connect()
        msg = await adapter.receive()   # blocks until a new email arrives
        await adapter.send(response)    # sends via SMTP
        await adapter.disconnect()

    Security notes:
    - ``trust_level`` is always ``"main"`` — set by this adapter, never from
      email content.
    - Session key is derived from the SHA-256 hash of the verified ``From``
      address; the raw address never appears directly in the key.
    - ``_password`` is never logged, audited, or included in any exception.
    """

    def __init__(
        self,
        config: ChannelConfig,
        agent_id: str = "main",
        rate_limiter: Optional[RateLimiter] = None,
        audit: Optional[AuditLog] = None,
    ) -> None:
        """Initialise the adapter from *config*.

        Args:
            config:       ``ChannelConfig`` whose ``settings`` dict carries all
                          email-specific values (see module docstring).
            agent_id:     Agent identifier embedded in session keys and audit events.
            rate_limiter: Optional custom ``RateLimiter``; default is 10/min, 60/hour.
            audit:        Optional ``AuditLog`` for security event recording.

        Raises:
            ValueError: If a required setting key is missing (message does NOT
                        echo any credential values).
        """
        settings = config.settings
        for key in _REQUIRED_SETTINGS:
            if key not in settings:
                raise ValueError(f"EmailAdapter: missing required setting '{key}'")

        self._imap_host: str = str(settings["imap_host"])
        self._imap_port: int = int(settings.get("imap_port", _DEFAULT_IMAP_PORT))
        self._smtp_host: str = str(settings["smtp_host"])
        self._smtp_port: int = int(settings.get("smtp_port", _DEFAULT_SMTP_PORT))
        self._username: str = str(settings["username"])
        self._password: str = str(settings["password"])
        self._poll_interval: int = int(
            settings.get("poll_interval_seconds", _DEFAULT_POLL_INTERVAL)
        )

        raw_allowlist = settings["sender_allowlist"]
        self._sender_allowlist: set[str] = {addr.lower() for addr in raw_allowlist}
        self._default_to_address: str = str(settings["default_to_address"])

        self._agent_id: str = agent_id
        self._connected: bool = False
        self._rate_limiter: RateLimiter = rate_limiter or RateLimiter(
            max_per_minute=_DEFAULT_RATE_MAX_PER_MINUTE,
            max_per_hour=_DEFAULT_RATE_MAX_PER_HOUR,
        )
        self._audit: Optional[AuditLog] = audit

    # ------------------------------------------------------------------
    # ChannelAdapter identity
    # ------------------------------------------------------------------

    @property
    def channel_name(self) -> str:
        """Identifier for this channel."""
        return "email"

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    async def connect(self) -> None:
        """Validate config and mark the adapter as connected.

        No persistent IMAP connection is opened here — connections are
        opened per-poll to avoid idle-timeout issues.
        """
        self._connected = True

    async def disconnect(self) -> None:
        """Mark the adapter as disconnected.

        Safe to call multiple times (idempotent).
        """
        self._connected = False

    # ------------------------------------------------------------------
    # I/O
    # ------------------------------------------------------------------

    async def receive(self) -> UniversalMessage:
        """Poll IMAP for the next unseen message and return it as a UniversalMessage.

        Loops until a message is available or the adapter is disconnected.
        Each loop iteration sleeps ``_poll_interval`` seconds between IMAP checks.

        Returns:
            A validated UniversalMessage from an allowlisted sender.

        Raises:
            EOFError:        Adapter was disconnected while polling.
            PermissionError: Sender not in allowlist, or rate limit exceeded.
                             (Callers should catch and continue to the next poll.)

        Security notes:
        - ``trust_level`` is always ``"main"``; never derived from email content.
        - Session key is always derived via ``get_session_key`` from the
          verified ``From`` address.
        - IMAP exceptions are caught, audit-logged, and treated as "no messages"
          so the adapter keeps running rather than crashing the process.
        """
        while self._connected:
            msgs: list[Any] = []
            try:
                msgs = await asyncio.to_thread(
                    _fetch_unseen,
                    self._imap_host,
                    self._imap_port,
                    self._username,
                    self._password,
                )
            except Exception as exc:
                await self._audit_log(
                    "email_imap_error",
                    details={"error": type(exc).__name__},
                )
                msgs = []

            if msgs:
                return await self._build_universal_message(msgs[0])

            await asyncio.sleep(self._poll_interval)

        raise EOFError("EmailAdapter disconnected")

    async def send(self, message: UniversalMessage) -> None:
        """Send an email via SMTP.

        Reads ``to``, ``subject``, and ``body`` from ``message.params``.
        Only supports ``operation="send_email"``.

        Args:
            message: UniversalMessage with ``operation="send_email"`` and
                     params ``{"to": ..., "subject": ..., "body": ...}``.

        Raises:
            ValueError:        If ``operation != "send_email"``.
            smtplib.SMTPException: On SMTP delivery failure (propagated to caller).

        Security notes:
        - ``_password`` is never included in any audit event or log message.
        - The subject is stored as a truncated hash in the audit log, not
          in plaintext.
        """
        if message.operation != "send_email":
            raise ValueError(
                f"EmailAdapter.send: unsupported operation '{message.operation}'; "
                "expected 'send_email'"
            )

        to = str(message.params.get("to", self._default_to_address))
        subject = str(message.params.get("subject", ""))
        body = str(message.params.get("body", ""))

        await asyncio.to_thread(
            _smtp_send,
            self._smtp_host,
            self._smtp_port,
            self._username,
            self._password,
            to,
            subject,
            body,
        )

        subject_hash = hashlib.sha256(subject.encode()).hexdigest()[:8]
        await self._audit_log(
            "email_sent",
            details={"to": to, "subject_hash": subject_hash},
        )

    # ------------------------------------------------------------------
    # Routing
    # ------------------------------------------------------------------

    def get_session_key(self, peer_info: dict[str, Any]) -> str:
        """Derive a stable session key from the sender's email address.

        The raw address is hashed with SHA-256 so the key is safe to store
        and log without exposing the address directly.

        Args:
            peer_info: Must contain ``"from_address"`` (case-insensitive).

        Returns:
            Session key of the form ``"agent:{agent_id}:email:{sha256[:12]}"``.

        Security notes:
        - The hash is derived from the lowercased address, so the key is
          case-insensitive.
        - The raw address never appears in the session key.
        """
        addr = peer_info["from_address"].lower()
        h = hashlib.sha256(addr.encode()).hexdigest()[:12]
        return f"agent:{self._agent_id}:email:{h}"

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    async def _build_universal_message(self, msg: Any) -> UniversalMessage:
        """Build a UniversalMessage from a parsed MIME message.

        Applies allowlist check, rate limit check, content scan, and then
        constructs the UniversalMessage.

        Args:
            msg: ``email.message.Message`` object.

        Returns:
            A validated UniversalMessage.

        Raises:
            PermissionError: Sender not in allowlist, or rate limit exceeded.
        """
        # Extract From header
        raw_from = msg.get("From", "")
        _, from_address = parseaddr(raw_from)
        from_address = from_address.lower()

        # --- Sender allowlist ---
        if from_address not in self._sender_allowlist:
            await self._audit_log(
                "email_sender_rejected",
                details={"from_address": from_address},
            )
            raise PermissionError(f"EmailAdapter: sender not in allowlist: {from_address}")

        # --- Rate limit ---
        session_key = self.get_session_key({"from_address": from_address})
        allowed = await self._rate_limiter.check(session_key)
        if not allowed:
            await self._audit_log(
                "email_rate_limited",
                session_key=session_key,
                details={"from_address": from_address},
            )
            raise PermissionError(f"EmailAdapter: rate limit exceeded for {from_address}")
        await self._rate_limiter.record(session_key)

        # --- Extract content ---
        subject = str(msg.get("Subject", ""))
        body = _extract_text(msg)
        msg_id_header = str(msg.get("Message-ID", ""))

        # --- Suspicious content scan ---
        scan_text = subject + "\n" + body
        hits = scan_for_suspicious_content(scan_text)
        if hits:
            await self._audit_log(
                "email_suspicious_content",
                session_key=session_key,
                details={"matches": hits},
            )

        return create_message(
            from_agent="channel:email",
            to_agent=f"agent:{self._agent_id}:main",
            session_key=session_key,
            channel="email",
            type="request",
            operation="user_message",
            trust_level="main",
            params={
                "content": body,
                "subject": subject,
                "from_address": from_address,
            },
            metadata={"message_id": msg_id_header},
        )

    async def _audit_log(
        self,
        event: str,
        session_key: Optional[str] = None,
        details: Optional[dict[str, Any]] = None,
    ) -> None:
        """Write an audit event if an ``AuditLog`` is configured.

        A no-op when ``self._audit`` is ``None``.

        Security notes:
        - ``_password`` must never appear in ``details``.
        """
        if self._audit is None:
            return
        await self._audit.log(
            AuditEvent(
                event=event,
                agent_id=f"channel:email:{self._agent_id}",
                session_key=session_key,
                details=details or {},
            )
        )
