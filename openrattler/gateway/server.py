"""WebSocket Gateway server — the only external-facing component in OpenRattler.

The Gateway is a thin, security-hardened routing layer between channel adapters
(Telegram, CLI, Slack…) and the internal agent runtime.  It is the primary
attack surface for infrastructure-level exploitation, so the implementation
follows all SU-007 requirements:

SU-007 COMPLIANCE
-----------------
1. Authentication is mandatory — no connection is accepted without a valid
   Bearer token.  There is no configuration option to disable auth.
2. Protocol version enforcement — connections requesting a version below
   ``MIN_PROTOCOL_VERSION`` are rejected with HTTP 400 and logged.
3. Reverse proxy trust — ``X-Forwarded-For`` is only honoured from IPs in
   ``trusted_proxies``; all other proxy headers are ignored.
4. Connection-level rate limiting — enforced per IP *before* any message
   processing, separate from the per-operation Layer 8 rate limiting.
5. Endpoint minimization — exactly two endpoints:
   - ``GET /ws``     authenticated WebSocket endpoint
   - ``GET /health`` unauthenticated, returns only ``"ok"``
   No REST endpoints, no debug endpoints, no session listing.
6. Session transcript protection — transcripts are never accessible via the
   Gateway API at any endpoint.

COMPONENT WIRING
----------------
``Gateway`` owns:
- ``TokenAuth``            — validates Bearer tokens before WS upgrade
- ``ConnectionRateLimiter`` — per-IP connection rate enforcement
- ``AuditLog``             — records auth failures, connects, disconnects

``AgentRuntime`` + ``Session`` are injected via ``set_runtime()`` after
construction (or replaced at any time to swap agents).  Tests can inject a
mock runtime without starting the server.
"""

from __future__ import annotations

import json
import time
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Optional

from aiohttp import WSMsgType, web

from openrattler.agents.runtime import AgentRuntime
from openrattler.config.loader import AppConfig
from openrattler.gateway.auth import TokenAuth
from openrattler.models.audit import AuditEvent
from openrattler.models.messages import UniversalMessage, create_message
from openrattler.models.sessions import Session
from openrattler.storage.audit import AuditLog

# ---------------------------------------------------------------------------
# Protocol constants
# ---------------------------------------------------------------------------

#: Minimum protocol version accepted by the Gateway.  Connections advertising
#: a lower version are rejected and logged as downgrade attempts (SU-007 §2).
MIN_PROTOCOL_VERSION: int = 1

#: Current protocol version advertised by this Gateway.
CURRENT_PROTOCOL_VERSION: int = 1

# ---------------------------------------------------------------------------
# Rate-limit constants
# ---------------------------------------------------------------------------

_MAX_CONNECTIONS_PER_IP: int = 5
_MAX_ATTEMPTS_PER_MINUTE: int = 10
_MAX_FAILED_AUTH: int = 5
_FAILED_AUTH_LOCKOUT_MINUTES: int = 15


# ---------------------------------------------------------------------------
# Connection info
# ---------------------------------------------------------------------------


@dataclass
class ConnectionInfo:
    """Metadata about a single authenticated WebSocket connection."""

    ws: web.WebSocketResponse
    channel_id: str
    connected_at: datetime
    remote_ip: str


# ---------------------------------------------------------------------------
# Per-IP rate-limit state
# ---------------------------------------------------------------------------


@dataclass
class _IPState:
    active: int = 0
    attempt_times: list[float] = field(default_factory=list)
    failed_auth: int = 0
    lockout_until: float = 0.0


class ConnectionRateLimiter:
    """Track per-IP connection counts and enforce rate / lockout limits.

    Limits (SU-007 §4):
    - ``max_connections_per_ip``        — concurrent active WS connections
    - ``max_attempts_per_minute``       — total connection attempts (sliding window)
    - ``max_failed_auth``               — failed auth before lockout
    - ``failed_auth_lockout_minutes``   — lockout duration after too many failures

    Security notes:
    - This is a transport-level guard that runs *before* any message processing.
    - Lockout prevents brute-force attacks against the authentication endpoint.
    - ``can_attempt`` records the attempt time, so it must be called exactly
      once per incoming connection request.
    """

    def __init__(
        self,
        max_connections_per_ip: int = _MAX_CONNECTIONS_PER_IP,
        max_attempts_per_minute: int = _MAX_ATTEMPTS_PER_MINUTE,
        max_failed_auth: int = _MAX_FAILED_AUTH,
        failed_auth_lockout_minutes: int = _FAILED_AUTH_LOCKOUT_MINUTES,
    ) -> None:
        self._max_connections = max_connections_per_ip
        self._max_attempts = max_attempts_per_minute
        self._max_failed = max_failed_auth
        self._lockout_seconds = failed_auth_lockout_minutes * 60
        self._state: dict[str, _IPState] = defaultdict(lambda: _IPState())

    def _get(self, ip: str) -> _IPState:
        return self._state[ip]

    def is_locked_out(self, ip: str) -> bool:
        """Return ``True`` if *ip* is currently in a failed-auth lockout."""
        return time.time() < self._get(ip).lockout_until

    def can_attempt(self, ip: str) -> bool:
        """Return ``True`` if a new connection from *ip* should be allowed.

        Side effect: records the current time as an attempt for *ip* so the
        sliding-window counter stays accurate.
        """
        if self.is_locked_out(ip):
            return False
        s = self._get(ip)
        now = time.time()
        # Purge attempts older than 60 s (sliding window)
        s.attempt_times = [t for t in s.attempt_times if now - t < 60.0]
        if len(s.attempt_times) >= self._max_attempts:
            return False
        if s.active >= self._max_connections:
            return False
        s.attempt_times.append(now)
        return True

    def record_connected(self, ip: str) -> None:
        """Increment the active connection counter for *ip*."""
        self._get(ip).active += 1

    def record_disconnected(self, ip: str) -> None:
        """Decrement the active connection counter for *ip* (floor at 0)."""
        s = self._get(ip)
        s.active = max(0, s.active - 1)

    def record_auth_failure(self, ip: str) -> None:
        """Record a failed auth attempt and apply lockout if threshold is hit."""
        s = self._get(ip)
        s.failed_auth += 1
        if s.failed_auth >= self._max_failed:
            s.lockout_until = time.time() + self._lockout_seconds

    def record_auth_success(self, ip: str) -> None:
        """Clear the failed-auth counter and any active lockout for *ip*."""
        s = self._get(ip)
        s.failed_auth = 0
        s.lockout_until = 0.0


# ---------------------------------------------------------------------------
# Gateway
# ---------------------------------------------------------------------------


class Gateway:
    """WebSocket Gateway — routes inbound channel messages to the agent runtime.

    Lifecycle::

        auth = TokenAuth(secret="...", expiry_seconds=3600)
        gw = Gateway(host="127.0.0.1", port=8765, config=cfg, audit_log=al, auth=auth)
        gw.set_runtime(runtime, session)   # wire in the agent
        await gw.start()                   # bind and listen
        await gw.stop()                    # graceful shutdown

    For testing, call ``_build_app()`` to get the ``web.Application`` and pass
    it to ``aiohttp.test_utils.TestServer`` without actually binding a port::

        app = gw._build_app()
        async with TestClient(TestServer(app)) as client:
            ...

    Security notes:
    - Authentication happens via HTTP ``Authorization: Bearer <token>`` header
      **before** the WebSocket upgrade (SU-007 §1).
    - Protocol version is checked via ``X-Protocol-Version`` header (SU-007 §2).
    - Only ``/ws`` and ``/health`` are registered; no other routes exist (SU-007 §5).
    - Session transcripts are never exposed through this API (SU-007 §6).
    """

    def __init__(
        self,
        host: str,
        port: int,
        config: AppConfig,
        audit_log: AuditLog,
        auth: TokenAuth,
        *,
        trusted_proxies: Optional[list[str]] = None,
    ) -> None:
        self._host = host
        self._port = port
        self._config = config
        self._audit_log = audit_log
        self._auth = auth
        #: Only these IPs are trusted to supply X-Forwarded-For headers.
        self._trusted_proxies: list[str] = (
            trusted_proxies if trusted_proxies is not None else ["127.0.0.1", "::1"]
        )
        self._connections: dict[str, ConnectionInfo] = {}
        self._rate_limiter = ConnectionRateLimiter()
        self._runtime: Optional[AgentRuntime] = None
        self._session: Optional[Session] = None
        self._app: Optional[web.Application] = None
        self._runner: Optional[web.AppRunner] = None

    # ------------------------------------------------------------------
    # Runtime injection
    # ------------------------------------------------------------------

    def set_runtime(self, runtime: AgentRuntime, session: Session) -> None:
        """Register the ``AgentRuntime`` and ``Session`` that handle messages.

        Can be called before or after ``start()``.  Calling it again replaces
        the current runtime (useful for hot-swapping agents in tests).
        """
        self._runtime = runtime
        self._session = session

    # ------------------------------------------------------------------
    # IP resolution (SU-007 §3)
    # ------------------------------------------------------------------

    def get_client_ip(self, request: web.Request) -> str:
        """Return the real client IP, honouring *trusted_proxies* only.

        If the direct remote address is in ``trusted_proxies``, the first
        value in ``X-Forwarded-For`` is used.  Otherwise, the direct remote
        address is returned regardless of forwarding headers.

        Security notes:
        - Prevents auth bypass via forged proxy headers (SU-007 §3).
        - ``request.remote`` may be ``None`` on test servers; falls back to
          ``"unknown"`` so rate-limiter logic remains intact.
        """
        remote: str = request.remote or "unknown"
        if remote in self._trusted_proxies:
            forwarded = request.headers.get("X-Forwarded-For", "")
            if forwarded:
                return forwarded.split(",")[0].strip()
        return remote

    # ------------------------------------------------------------------
    # Authentication (SU-007 §1)
    # ------------------------------------------------------------------

    async def authenticate(self, request: web.Request) -> Optional[str]:
        """Validate the ``Authorization: Bearer <token>`` header.

        Returns the ``channel_id`` encoded in the token, or ``None`` if the
        header is absent, malformed, the signature is invalid, or the token
        has expired.

        Security notes:
        - Called *before* the WebSocket upgrade so unauthenticated connections
          are rejected at the HTTP layer without consuming WS resources.
        - The raw token value is never logged.
        """
        header = request.headers.get("Authorization", "")
        if not header.startswith("Bearer "):
            return None
        token = header[len("Bearer ") :]
        return self._auth.validate_token(token)

    # ------------------------------------------------------------------
    # Server lifecycle
    # ------------------------------------------------------------------

    def _build_app(self) -> web.Application:
        """Create and return the ``web.Application`` with all routes registered.

        Separated from ``start()`` so tests can pass the app to
        ``aiohttp.test_utils.TestServer`` without binding a real port.
        """
        app = web.Application()
        app.router.add_get("/health", self._handle_health)
        app.router.add_get("/ws", self._handle_ws)
        self._app = app
        return app

    async def start(self) -> None:
        """Build the app and bind the TCP server on ``(host, port)``."""
        app = self._build_app()
        runner = web.AppRunner(app)
        await runner.setup()
        site = web.TCPSite(runner, self._host, self._port)
        await site.start()
        self._runner = runner

    async def stop(self) -> None:
        """Gracefully close all active connections and stop the server."""
        for info in list(self._connections.values()):
            await info.ws.close()
        self._connections.clear()
        if self._runner:
            await self._runner.cleanup()
            self._runner = None

    # ------------------------------------------------------------------
    # Message routing
    # ------------------------------------------------------------------

    async def route_message(self, message: UniversalMessage) -> UniversalMessage:
        """Dispatch *message* to the registered ``AgentRuntime``.

        Returns an error ``UniversalMessage`` if no runtime has been
        registered via ``set_runtime()``.
        """
        if self._runtime is None or self._session is None:
            return create_message(
                from_agent="gateway",
                to_agent=message.from_agent,
                session_key=message.session_key,
                type="error",
                operation="route_error",
                trust_level="main",
                params={},
                error={"code": "NO_RUNTIME", "message": "No agent runtime registered"},
            )
        return await self._runtime.process_message(self._session, message)

    # ------------------------------------------------------------------
    # Connection handling
    # ------------------------------------------------------------------

    async def handle_connection(
        self, ws: web.WebSocketResponse, channel_id: str, remote_ip: str
    ) -> None:
        """Drive the message loop for an already-authenticated WebSocket.

        Registers the connection in ``_connections``, increments the IP
        counter, then loops over messages until the socket closes.  Always
        cleans up on exit, even if an unhandled exception propagates.

        Args:
            ws:         The already-prepared ``WebSocketResponse``.
            channel_id: Authenticated channel identity from the Bearer token.
            remote_ip:  Resolved client IP (after proxy trust check).
        """
        info = ConnectionInfo(
            ws=ws,
            channel_id=channel_id,
            connected_at=datetime.now(timezone.utc),
            remote_ip=remote_ip,
        )
        self._connections[channel_id] = info
        self._rate_limiter.record_connected(remote_ip)

        try:
            async for msg in ws:
                if msg.type == WSMsgType.TEXT:
                    response_json = await self._process_ws_message(msg.data, channel_id)
                    await ws.send_str(response_json)
                elif msg.type in (WSMsgType.ERROR, WSMsgType.CLOSE):
                    break
        finally:
            self._connections.pop(channel_id, None)
            self._rate_limiter.record_disconnected(remote_ip)
            await self._audit_log.log(
                AuditEvent(
                    event="gateway_disconnect",
                    agent_id=channel_id,
                    session_key=None,
                    details={"remote_ip": remote_ip},
                )
            )

    async def _process_ws_message(self, raw: str, channel_id: str) -> str:
        """Parse *raw* JSON, route to the runtime, return JSON response."""
        try:
            data: Any = json.loads(raw)
            message = UniversalMessage.model_validate(data)
        except Exception as exc:
            err = create_message(
                from_agent="gateway",
                to_agent=channel_id,
                session_key="agent:main:main",
                type="error",
                operation="parse_error",
                trust_level="main",
                params={},
                error={"code": "PARSE_ERROR", "message": str(exc)},
            )
            return err.model_dump_json()
        response = await self.route_message(message)
        return response.model_dump_json()

    # ------------------------------------------------------------------
    # HTTP handlers
    # ------------------------------------------------------------------

    async def _handle_health(self, request: web.Request) -> web.Response:
        """Health check — returns ``"ok"`` with no version or config info (SU-007 §5)."""
        return web.Response(text="ok")

    async def _handle_ws(self, request: web.Request) -> web.StreamResponse:
        """WebSocket endpoint — authenticates *before* upgrading (SU-007 §1).

        Sequence:
        1. Rate-limit check (rejects if IP is over limit or locked out).
        2. Protocol version check (rejects below ``MIN_PROTOCOL_VERSION``).
        3. Auth check (rejects with 401 if token is invalid/expired).
        4. Upgrade to WebSocket.
        5. Log connect event.
        6. Delegate to ``handle_connection()``.
        """
        remote_ip = self.get_client_ip(request)

        # --- Step 1: rate limit (before auth to prevent enumeration) ---
        if not self._rate_limiter.can_attempt(remote_ip):
            return web.Response(status=429, text="Too many connection attempts")

        # --- Step 2: protocol version (SU-007 §2) ---
        proto_str = request.headers.get("X-Protocol-Version", str(MIN_PROTOCOL_VERSION))
        try:
            proto_ver = int(proto_str)
        except ValueError:
            return web.Response(status=400, text="Invalid X-Protocol-Version header")

        if proto_ver < MIN_PROTOCOL_VERSION:
            await self._audit_log.log(
                AuditEvent(
                    event="gateway_protocol_downgrade_attempt",
                    agent_id="unknown",
                    session_key=None,
                    details={"remote_ip": remote_ip, "requested_version": proto_ver},
                )
            )
            return web.Response(
                status=400,
                text=f"Protocol version {proto_ver} below minimum ({MIN_PROTOCOL_VERSION})",
            )

        # --- Step 3: auth (SU-007 §1) — BEFORE WebSocket upgrade ---
        channel_id = await self.authenticate(request)
        if channel_id is None:
            self._rate_limiter.record_auth_failure(remote_ip)
            await self._audit_log.log(
                AuditEvent(
                    event="gateway_auth_failure",
                    agent_id="unknown",
                    session_key=None,
                    details={"remote_ip": remote_ip},
                )
            )
            return web.Response(status=401, text="Authentication required")

        self._rate_limiter.record_auth_success(remote_ip)

        # --- Step 4: upgrade to WebSocket ---
        ws = web.WebSocketResponse()
        await ws.prepare(request)

        # --- Step 5: audit log ---
        await self._audit_log.log(
            AuditEvent(
                event="gateway_connect",
                agent_id=channel_id,
                session_key=None,
                details={"remote_ip": remote_ip},
            )
        )

        # --- Step 6: message loop ---
        await self.handle_connection(ws, channel_id, remote_ip)
        return ws
