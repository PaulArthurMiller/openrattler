"""Slack channel adapter — Slack Web API polling (inbound) + delivery (outbound).

``SlackAdapter`` bridges a Slack channel to the OpenRattler channel layer.
Inbound messages are fetched by polling Slack's ``conversations.history`` API;
outbound messages are sent via Slack's ``chat.postMessage`` API.  Both directions
use the persistent ``aiohttp.ClientSession`` created in ``connect()``.

Security enforced at the adapter boundary (before any UniversalMessage is built):

- **Sender allowlist** — Messages from Slack user IDs (``U...``) or bot IDs
  (``B...``) not in ``sender_allowlist`` are rejected with a ``PermissionError``
  and an audit event.  The attacker never gets a message into the system.
- **Rate limiting** — per-sender sliding-window limit (default 10/min, 60/hour)
  blocks flood attacks.
- **Suspicious content scan** — text is scanned; hits are audit-logged but the
  message is still delivered (flag-and-deliver, not block-on-suspicion).
- **Credentials never logged** — ``bot_token`` never appears in any log call.
- **Transport security** — all Slack API calls are HTTPS; ``aiohttp`` enforces
  this via the ``https://`` URL scheme.
- **Connection timeout** — ``ClientTimeout(total=30)`` on every request.
- **Deduplication** — ``_seen_ts`` prevents redelivering the same Slack message
  timestamp within a session (reset on each ``connect()`` call).
- **Fail-secure fetch errors** — all exceptions from ``_fetch_new_messages`` are
  caught, audit-logged, and return ``[]``; the adapter keeps polling rather than
  crashing.
- **Bot message gating** — messages with a ``bot_id`` field are accepted only when
  ``allow_bot_messages=True`` in config.  By default only human user messages are
  delivered, protecting against bot-to-bot injection attacks.

SECURITY NOTES
--------------
- ``trust_level`` is hardcoded to ``"main"`` — allowlist enforcement means only
  trusted senders ever produce a UniversalMessage.
- Session key is derived from a SHA-256 hash of the Slack-verified ``user`` or
  ``bot_id`` field, not from any user-controlled string in the message body.
- ``bot_token`` is stored only in ``self._bot_token``; it never appears in any
  log, audit event, or exception message.
- Slack always returns HTTP 200 even for errors.  The ``"ok"`` field in the JSON
  response is the authoritative success indicator.
"""

from __future__ import annotations

import asyncio
import hashlib
from datetime import datetime, timezone
from typing import Any, Optional

import aiohttp
from aiohttp import ClientTimeout

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

_SLACK_API_BASE: str = "https://slack.com/api"
_REQUEST_TIMEOUT: int = 30
_DEFAULT_POLL_INTERVAL: int = 10
_DEFAULT_RATE_MAX_PER_MINUTE: int = 10
_DEFAULT_RATE_MAX_PER_HOUR: int = 60

_REQUIRED_SETTINGS: tuple[str, ...] = (
    "bot_token",
    "channel_id",
    "sender_allowlist",
)


# ---------------------------------------------------------------------------
# SlackAdapter
# ---------------------------------------------------------------------------


class SlackAdapter(ChannelAdapter):
    """Channel adapter that polls Slack for inbound messages and sends via Slack API.

    All Slack-specific configuration is read from ``config.settings``.
    See module docstring for the full security model.

    Usage::

        config = ChannelConfig(channel_id="slack", settings={...})
        adapter = SlackAdapter(config)
        await adapter.connect()
        msg = await adapter.receive()   # blocks until a new Slack message arrives
        await adapter.send(response)    # sends via Slack chat.postMessage
        await adapter.disconnect()

    Security notes:
    - ``trust_level`` is always ``"main"`` — set by this adapter, never from
      Slack message content.
    - Session key is derived from the SHA-256 hash of the Slack-verified
      ``user`` or ``bot_id`` field; the raw ID never appears directly in the key.
    - ``bot_token`` is never logged, audited, or included in any exception.
    - Bot messages (``bot_id`` field present) are filtered by default; enable
      with ``allow_bot_messages=True`` in config.
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
                          Slack-specific values (see module docstring).
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
                raise ValueError(f"SlackAdapter: missing required setting '{key}'")

        self._bot_token: str = str(settings["bot_token"])
        self._channel_id: str = str(settings["channel_id"])
        self._poll_interval: int = int(
            settings.get("poll_interval_seconds", _DEFAULT_POLL_INTERVAL)
        )

        raw_allowlist = settings["sender_allowlist"]
        self._sender_allowlist: set[str] = set(raw_allowlist)
        self._allow_bot_messages: bool = bool(settings.get("allow_bot_messages", False))

        self._agent_id: str = agent_id
        self._connected: bool = False
        self._oldest_ts: Optional[str] = None
        self._seen_ts: set[str] = set()
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
        return "slack"

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    async def connect(self) -> None:
        """Open the aiohttp session and mark the adapter as connected.

        Creates a persistent ``aiohttp.ClientSession`` with the Slack Bearer
        token in the Authorization header and a 30-second timeout.  Resets
        ``_seen_ts`` so a reconnect re-delivers no already-seen message timestamps.
        Sets ``_oldest_ts`` to the current UTC timestamp so only messages received
        after ``connect()`` are delivered.
        """
        self._session = aiohttp.ClientSession(
            headers={"Authorization": f"Bearer {self._bot_token}"},
            timeout=ClientTimeout(total=_REQUEST_TIMEOUT),
        )
        self._connected = True
        self._seen_ts = set()
        self._oldest_ts = str(datetime.now(timezone.utc).timestamp())

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
        """Poll Slack for the next inbound message and return it as a UniversalMessage.

        Loops until a message is available or the adapter is disconnected.
        Each loop iteration sleeps ``_poll_interval`` seconds between API checks.

        Returns:
            A validated UniversalMessage from an allowlisted sender.

        Raises:
            EOFError:        Adapter was disconnected while polling.
            PermissionError: Sender not in allowlist, or rate limit exceeded.
                             (Callers should catch and continue to the next poll.)

        Security notes:
        - ``trust_level`` is always ``"main"``; never derived from Slack content.
        - Session key is always derived via ``get_session_key`` from the
          Slack-verified ``user`` or ``bot_id`` field.
        - Slack API errors are caught, audit-logged, and treated as "no messages"
          so the adapter keeps running rather than crashing the process.
        """
        while self._connected:
            msgs: list[dict[str, Any]] = []
            try:
                msgs = await self._fetch_new_messages()
            except Exception as exc:
                await self._audit_log(
                    "slack_fetch_error",
                    details={"error": type(exc).__name__},
                )
                msgs = []

            if msgs:
                return await self._build_universal_message(msgs[0])
            await asyncio.sleep(self._poll_interval)

        raise EOFError("SlackAdapter disconnected")

    async def send(self, message: UniversalMessage) -> None:
        """Send a message via Slack chat.postMessage API.

        Reads ``channel`` (optional, defaults to ``_channel_id``) and ``text``
        from ``message.params``.  Only supports ``operation="send_slack_message"``.

        Args:
            message: UniversalMessage with ``operation="send_slack_message"`` and
                     params ``{"text": ..., "channel": ...}``.

        Raises:
            ValueError:    If ``operation != "send_slack_message"``.
            RuntimeError:  If Slack returns ``ok=False`` in the response JSON.

        Security notes:
        - ``bot_token`` is never included in any audit event or log message.
        - Body is logged only as its character length.
        - Slack always returns HTTP 200; the ``"ok"`` field indicates success.
        """
        if message.operation != "send_slack_message":
            raise ValueError(
                f"SlackAdapter.send: unsupported operation '{message.operation}'; "
                "expected 'send_slack_message'"
            )

        channel = str(message.params.get("channel", self._channel_id))
        text = str(message.params.get("text", ""))

        url = f"{_SLACK_API_BASE}/chat.postMessage"
        payload = {"channel": channel, "text": text}

        assert self._session is not None  # mypy: connect() must be called first
        async with self._session.post(url, json=payload) as resp:
            data = await resp.json()

        if not data.get("ok"):
            raise RuntimeError(f"Slack API error: {data.get('error', 'unknown')}")

        await self._audit_log(
            "slack_sent",
            details={"channel_id": channel, "body_length": len(text)},
        )

    # ------------------------------------------------------------------
    # Routing
    # ------------------------------------------------------------------

    def get_session_key(self, peer_info: dict[str, Any]) -> str:
        """Derive a stable session key from the sender's Slack ID.

        The raw ID is hashed with SHA-256 so the key is safe to store
        and log without exposing the Slack user or bot ID directly.

        Args:
            peer_info: Must contain ``"sender_id"`` (Slack user ID or bot ID).

        Returns:
            Session key of the form ``"agent:{agent_id}:slack:{sha256[:12]}"``.

        Security notes:
        - No case-folding — Slack IDs are already normalised opaque strings.
        - The raw ID never appears in the session key.
        """
        sender_id = peer_info["sender_id"]
        h = hashlib.sha256(sender_id.encode()).hexdigest()[:12]
        return f"agent:{self._agent_id}:slack:{h}"

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    async def _fetch_new_messages(self) -> list[dict[str, Any]]:
        """Poll Slack conversations.history API for new messages.

        Queries for messages in ``_channel_id`` since ``_oldest_ts``, limited
        to 20 results.  Filters via ``_is_valid_message`` and deduplicates
        against ``_seen_ts``.

        Returns:
            A list containing the first new valid message dict, or ``[]``
            if no new messages are found.

        Raises:
            RuntimeError: If Slack returns ``ok=False`` — caught by ``receive()``.

        Security notes:
        - ``bot_token`` is on the ``aiohttp.ClientSession`` header; it never
          appears in the URL, params, or logs.
        - Slack always returns HTTP 200; errors must be detected via ``data["ok"]``.
        """
        assert self._session is not None
        assert self._oldest_ts is not None  # set by connect()

        url = f"{_SLACK_API_BASE}/conversations.history"
        params: dict[str, str | int] = {
            "channel": self._channel_id,
            "oldest": self._oldest_ts,
            "limit": 20,
        }

        async with self._session.get(url, params=params) as resp:
            data = await resp.json()

        if not data.get("ok"):
            raise RuntimeError(f"Slack API error: {data.get('error', 'unknown')}")

        for msg in data.get("messages", []):
            if not self._is_valid_message(msg):
                continue
            ts = msg.get("ts", "")
            if ts in self._seen_ts:
                continue
            return [msg]

        return []

    def _is_valid_message(self, msg: dict[str, Any]) -> bool:
        """Determine whether a Slack message dict should be delivered.

        Handles four cases:
        - Regular human message (``user`` present, no ``subtype``) → accepted.
        - Bot message (``bot_id`` present) → accepted only when
          ``allow_bot_messages=True``.
        - System events (``channel_join``, ``message_changed``, etc.) → always
          rejected.
        - Human message with a subtype (edits, etc.) → rejected (safest default).

        Args:
            msg: Slack message dict from conversations.history.

        Returns:
            ``True`` if the message should be delivered; ``False`` otherwise.
        """
        if msg.get("type") != "message":
            return False
        # Human message: user field present, no subtype
        if "user" in msg and "subtype" not in msg:
            return True
        # Bot message: only when configured
        if self._allow_bot_messages and "bot_id" in msg:
            return True
        return False

    async def _build_universal_message(self, msg_dict: dict[str, Any]) -> UniversalMessage:
        """Build a UniversalMessage from a Slack message dict.

        Applies allowlist check, marks ts as seen, rate limit check, content
        scan, then constructs the UniversalMessage.

        Args:
            msg_dict: Slack message JSON dict with ``user``/``bot_id``, ``ts``, ``text``.

        Returns:
            A validated UniversalMessage.

        Raises:
            PermissionError: Sender not in allowlist, or rate limit exceeded.
        """
        sender_id = str(msg_dict.get("user") or msg_dict.get("bot_id", ""))

        # --- Sender allowlist ---
        if sender_id not in self._sender_allowlist:
            await self._audit_log(
                "slack_sender_rejected",
                details={"sender_id": sender_id},
            )
            raise PermissionError(f"SlackAdapter: sender not in allowlist: {sender_id}")

        # --- Mark ts as seen (after allowlist, before rate limit) ---
        ts: str = str(msg_dict.get("ts", ""))
        self._seen_ts.add(ts)

        # --- Session key + rate limit ---
        session_key = self.get_session_key({"sender_id": sender_id})
        allowed = await self._rate_limiter.check(session_key)
        if not allowed:
            await self._audit_log(
                "slack_rate_limited",
                session_key=session_key,
                details={"sender_id": sender_id},
            )
            raise PermissionError(f"SlackAdapter: rate limit exceeded for {sender_id}")
        await self._rate_limiter.record(session_key)

        # --- Extract text ---
        text = str(msg_dict.get("text", ""))

        # --- Suspicious content scan ---
        hits = scan_for_suspicious_content(text)
        if hits:
            await self._audit_log(
                "slack_suspicious_content",
                session_key=session_key,
                details={"matches": hits},
            )

        return create_message(
            from_agent="channel:slack",
            to_agent=f"agent:{self._agent_id}:main",
            session_key=session_key,
            channel="slack",
            type="request",
            operation="user_message",
            trust_level="main",
            params={
                "content": text,
                "sender_id": sender_id,
            },
            metadata={
                "message_ts": ts,
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
        - ``bot_token`` must never appear in ``details``.
        """
        if self._audit is None:
            return
        await self._audit.log(
            AuditEvent(
                event=event,
                agent_id=f"channel:slack:{self._agent_id}",
                session_key=session_key,
                details=details or {},
            )
        )
