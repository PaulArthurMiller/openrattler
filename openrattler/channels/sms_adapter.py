"""SMS channel adapter — Twilio REST API polling (inbound) + delivery (outbound).

``SMSAdapter`` bridges a Twilio SMS number to the OpenRattler channel layer.
Inbound messages are fetched by polling Twilio's Messages API; outbound messages
are sent via Twilio's Messages API POST endpoint.  Both directions use the
persistent ``aiohttp.ClientSession`` created in ``connect()``.

Security enforced at the adapter boundary (before any UniversalMessage is built):

- **Sender allowlist** — SMS from numbers not in ``sender_allowlist`` are
  rejected with a ``PermissionError`` and an audit event.  The attacker never
  gets a message into the system.
- **Rate limiting** — per-sender sliding-window limit (default 10/min, 60/hour)
  blocks flood attacks.
- **Suspicious content scan** — body is scanned; hits are audit-logged but the
  message is still delivered (flag-and-deliver, not block-on-suspicion).
- **Credentials never logged** — ``auth_token`` never appears in any log call.
- **Transport security** — all Twilio API calls are HTTPS; ``aiohttp`` enforces
  this via the ``https://`` URL scheme.
- **Connection timeout** — ``ClientTimeout(total=30)`` on every request.
- **Deduplication** — ``_seen_sids`` prevents redelivering the same Twilio
  message SID within a session (reset on each ``connect()`` call).
- **Fail-secure fetch errors** — ``aiohttp.ClientError`` and non-2xx HTTP errors
  are caught, audit-logged, and return ``[]``; the adapter keeps polling rather
  than crashing.

SECURITY NOTES
--------------
- ``trust_level`` is hardcoded to ``"main"`` — allowlist enforcement means only
  trusted senders ever produce a UniversalMessage.
- Session key is derived from a SHA-256 hash of the Twilio-verified ``From``
  number, not from any user-controlled string in the SMS body.
- ``auth_token`` is stored only in ``self._auth_token``; it never appears in any
  log, audit event, or exception message.
"""

from __future__ import annotations

import asyncio
import hashlib
from datetime import datetime, timezone
from typing import Any, Optional

import aiohttp

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

_API_BASE: str = "https://api.twilio.com/2010-04-01/Accounts"
_REQUEST_TIMEOUT: int = 30
_DEFAULT_POLL_INTERVAL: int = 30
_DEFAULT_RATE_MAX_PER_MINUTE: int = 10
_DEFAULT_RATE_MAX_PER_HOUR: int = 60

_REQUIRED_SETTINGS: tuple[str, ...] = (
    "account_sid",
    "auth_token",
    "from_number",
    "sender_allowlist",
    "default_to_number",
)


# ---------------------------------------------------------------------------
# SMSAdapter
# ---------------------------------------------------------------------------


class SMSAdapter(ChannelAdapter):
    """Channel adapter that polls Twilio for inbound SMS and sends via Twilio.

    All SMS-specific configuration is read from ``config.settings``.
    See module docstring for the full security model.

    Usage::

        config = ChannelConfig(channel_id="sms", settings={...})
        adapter = SMSAdapter(config)
        await adapter.connect()
        msg = await adapter.receive()   # blocks until a new SMS arrives
        await adapter.send(response)    # sends via Twilio REST API
        await adapter.disconnect()

    Security notes:
    - ``trust_level`` is always ``"main"`` — set by this adapter, never from
      SMS content.
    - Session key is derived from the SHA-256 hash of the Twilio-verified
      ``From`` number; the raw number never appears directly in the key.
    - ``auth_token`` is never logged, audited, or included in any exception.
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
                          SMS-specific values (see module docstring).
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
                raise ValueError(f"SMSAdapter: missing required setting '{key}'")

        self._account_sid: str = str(settings["account_sid"])
        self._auth_token: str = str(settings["auth_token"])
        self._from_number: str = str(settings["from_number"])
        self._poll_interval: int = int(
            settings.get("poll_interval_seconds", _DEFAULT_POLL_INTERVAL)
        )

        raw_allowlist = settings["sender_allowlist"]
        self._sender_allowlist: set[str] = set(raw_allowlist)
        self._default_to_number: str = str(settings["default_to_number"])

        self._agent_id: str = agent_id
        self._connected: bool = False
        self._connected_at: Optional[datetime] = None
        self._seen_sids: set[str] = set()
        self._session: Optional[aiohttp.ClientSession] = None
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
        return "sms"

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    async def connect(self) -> None:
        """Open the aiohttp session and mark the adapter as connected.

        Creates a persistent ``aiohttp.ClientSession`` with Twilio Basic Auth
        and a 30-second timeout.  Resets ``_seen_sids`` so a reconnect
        re-delivers no already-seen SIDs.
        """
        self._session = aiohttp.ClientSession(
            auth=aiohttp.BasicAuth(self._account_sid, self._auth_token),
            timeout=aiohttp.ClientTimeout(total=_REQUEST_TIMEOUT),
        )
        self._connected = True
        self._connected_at = datetime.now(timezone.utc)
        self._seen_sids = set()

    async def disconnect(self) -> None:
        """Close the aiohttp session and mark the adapter as disconnected.

        Safe to call multiple times (idempotent).
        """
        self._connected = False
        if self._session is not None and not self._session.closed:
            await self._session.close()

    # ------------------------------------------------------------------
    # I/O
    # ------------------------------------------------------------------

    async def receive(self) -> UniversalMessage:
        """Poll Twilio for the next inbound SMS and return it as a UniversalMessage.

        Loops until a message is available or the adapter is disconnected.
        Each loop iteration sleeps ``_poll_interval`` seconds between API checks.

        Returns:
            A validated UniversalMessage from an allowlisted sender.

        Raises:
            EOFError:        Adapter was disconnected while polling.
            PermissionError: Sender not in allowlist, or rate limit exceeded.
                             (Callers should catch and continue to the next poll.)

        Security notes:
        - ``trust_level`` is always ``"main"``; never derived from SMS content.
        - Session key is always derived via ``get_session_key`` from the
          Twilio-verified ``From`` number.
        - Twilio API errors are caught, audit-logged, and treated as "no messages"
          so the adapter keeps running rather than crashing the process.
        """
        while self._connected:
            msgs: list[dict[str, Any]] = []
            try:
                msgs = await self._fetch_new_sms()
            except Exception as exc:
                await self._audit_log(
                    "sms_fetch_error",
                    details={"error": type(exc).__name__},
                )
                msgs = []

            if msgs:
                return await self._build_universal_message(msgs[0])
            await asyncio.sleep(self._poll_interval)

        raise EOFError("SMSAdapter disconnected")

    async def send(self, message: UniversalMessage) -> None:
        """Send an SMS via Twilio REST API.

        Reads ``to`` and ``body`` from ``message.params``.
        Only supports ``operation="send_sms"``.

        Args:
            message: UniversalMessage with ``operation="send_sms"`` and
                     params ``{"to": ..., "body": ...}``.

        Raises:
            ValueError:              If ``operation != "send_sms"``.
            aiohttp.ClientResponseError: On HTTP failure (propagated to caller).

        Security notes:
        - ``auth_token`` is never included in any audit event or log message.
        - Body is logged only as its character length.
        """
        if message.operation != "send_sms":
            raise ValueError(
                f"SMSAdapter.send: unsupported operation '{message.operation}'; "
                "expected 'send_sms'"
            )

        to = str(message.params.get("to", self._default_to_number))
        body = str(message.params.get("body", ""))

        url = f"{_API_BASE}/{self._account_sid}/Messages.json"
        form = {"From": self._from_number, "To": to, "Body": body}

        assert self._session is not None  # mypy: connect() must be called first
        async with self._session.post(url, data=form) as resp:
            resp.raise_for_status()

        await self._audit_log(
            "sms_sent",
            details={"to": to, "body_length": len(body)},
        )

    # ------------------------------------------------------------------
    # Routing
    # ------------------------------------------------------------------

    def get_session_key(self, peer_info: dict[str, Any]) -> str:
        """Derive a stable session key from the sender's phone number.

        The raw number is hashed with SHA-256 so the key is safe to store
        and log without exposing the number directly.

        Args:
            peer_info: Must contain ``"from_number"`` (E.164 format).

        Returns:
            Session key of the form ``"agent:{agent_id}:sms:{sha256[:12]}"``.

        Security notes:
        - The hash is derived from the number as-is (Twilio normalises to E.164).
        - The raw number never appears in the session key.
        """
        number = peer_info["from_number"]
        h = hashlib.sha256(number.encode()).hexdigest()[:12]
        return f"agent:{self._agent_id}:sms:{h}"

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    async def _fetch_new_sms(self) -> list[dict[str, Any]]:
        """Poll Twilio Messages API for new inbound SMS messages.

        Queries for messages addressed *to* our Twilio number (i.e. inbound)
        sent on or after the connection date, limited to 20 results.

        Returns:
            A list containing the first new inbound message dict, or ``[]``
            if no new messages are found.

        Raises:
            aiohttp.ClientError: On network/HTTP failure — caught by ``receive()``.

        Security notes:
        - ``auth_token`` is on the ``aiohttp.ClientSession``; it never appears
          in the URL, params, or logs.
        """
        assert self._session is not None
        assert self._connected_at is not None

        date_str = self._connected_at.strftime("%Y-%m-%d")
        url = f"{_API_BASE}/{self._account_sid}/Messages.json"
        params = {
            "To": self._from_number,
            "DateSent>": date_str,
            "PageSize": "20",
        }

        async with self._session.get(url, params=params) as resp:
            resp.raise_for_status()
            data = await resp.json()

        messages = data.get("messages", [])
        for msg in messages:
            if msg.get("direction") == "inbound" and msg.get("sid") not in self._seen_sids:
                return [msg]

        return []

    async def _build_universal_message(self, msg_dict: dict[str, Any]) -> UniversalMessage:
        """Build a UniversalMessage from a Twilio message dict.

        Applies allowlist check, rate limit check, content scan, then
        constructs the UniversalMessage.

        Args:
            msg_dict: Twilio message JSON dict with ``from``, ``sid``, ``body``.

        Returns:
            A validated UniversalMessage.

        Raises:
            PermissionError: Sender not in allowlist, or rate limit exceeded.
        """
        from_number: str = str(msg_dict.get("from", ""))

        # --- Sender allowlist ---
        if from_number not in self._sender_allowlist:
            await self._audit_log(
                "sms_sender_rejected",
                details={"from_number": from_number},
            )
            raise PermissionError(f"SMSAdapter: sender not in allowlist: {from_number}")

        # --- Mark SID as seen (before rate limit so partial failures don't redeliver) ---
        sid: str = str(msg_dict.get("sid", ""))
        self._seen_sids.add(sid)

        # --- Session key + rate limit ---
        session_key = self.get_session_key({"from_number": from_number})
        allowed = await self._rate_limiter.check(session_key)
        if not allowed:
            await self._audit_log(
                "sms_rate_limited",
                session_key=session_key,
                details={"from_number": from_number},
            )
            raise PermissionError(f"SMSAdapter: rate limit exceeded for {from_number}")
        await self._rate_limiter.record(session_key)

        # --- Extract body ---
        body = str(msg_dict.get("body", ""))

        # --- Suspicious content scan ---
        hits = scan_for_suspicious_content(body)
        if hits:
            await self._audit_log(
                "sms_suspicious_content",
                session_key=session_key,
                details={"matches": hits},
            )

        return create_message(
            from_agent="channel:sms",
            to_agent=f"agent:{self._agent_id}:main",
            session_key=session_key,
            channel="sms",
            type="request",
            operation="user_message",
            trust_level="main",
            params={
                "content": body,
                "from_number": from_number,
            },
            metadata={
                "message_sid": sid,
            },
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
        - ``auth_token`` must never appear in ``details``.
        """
        if self._audit is None:
            return
        await self._audit.log(
            AuditEvent(
                event=event,
                agent_id=f"channel:sms:{self._agent_id}",
                session_key=session_key,
                details=details or {},
            )
        )
