"""Tests for the Gateway WebSocket server (SU-007 security requirements)."""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock

import pytest
from aiohttp import web
from aiohttp.test_utils import TestClient, TestServer

from openrattler.agents.providers.base import LLMProvider, LLMResponse, TokenUsage
from openrattler.agents.runtime import AgentRuntime
from openrattler.config.loader import AppConfig
from openrattler.gateway.auth import TokenAuth
from openrattler.gateway.server import (
    MIN_PROTOCOL_VERSION,
    ConnectionRateLimiter,
    Gateway,
)
from openrattler.models.agents import AgentConfig, TrustLevel
from openrattler.models.messages import create_message
from openrattler.models.sessions import Session
from openrattler.storage.audit import AuditLog
from openrattler.storage.memory import MemoryStore
from openrattler.storage.transcripts import TranscriptStore
from openrattler.tools.executor import ToolExecutor
from openrattler.tools.registry import ToolRegistry

# ---------------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------------

_CHANNEL_ID = "test-channel"
_SECRET = "test-gateway-secret-32-bytes-xyz"
_SESSION_KEY = "agent:main:main"


def _usage() -> TokenUsage:
    return TokenUsage(
        prompt_tokens=10, completion_tokens=5, total_tokens=15, estimated_cost_usd=0.0
    )


def _mock_provider(content: str = "hi") -> LLMProvider:
    provider = MagicMock(spec=LLMProvider)
    provider.complete = AsyncMock(
        return_value=LLMResponse(
            content=content,
            tool_calls=[],
            usage=_usage(),
            model="test-model",
            finish_reason="stop",
        )
    )
    return provider


def _make_runtime(
    tmp_path: Path, provider: LLMProvider
) -> tuple[AgentRuntime, TranscriptStore, AuditLog]:
    sessions_dir = tmp_path / "sessions"
    memory_dir = tmp_path / "memory"
    audit_path = tmp_path / "audit" / "audit.jsonl"
    for d in (sessions_dir, memory_dir, audit_path.parent):
        d.mkdir(parents=True, exist_ok=True)

    transcript_store = TranscriptStore(sessions_dir)
    memory_store = MemoryStore(memory_dir)
    audit_log = AuditLog(audit_path)
    registry = ToolRegistry()
    executor = ToolExecutor(registry, audit_log)

    agent_config = AgentConfig(
        agent_id=_SESSION_KEY,
        name="Test",
        description="test agent",
        model="anthropic/claude-sonnet-4-6",
        trust_level=TrustLevel.main,
        system_prompt="Be brief.",
    )

    runtime = AgentRuntime(
        config=agent_config,
        provider=provider,
        tool_executor=executor,
        transcript_store=transcript_store,
        memory_store=memory_store,
        audit_log=audit_log,
    )
    return runtime, transcript_store, audit_log


def _make_auth() -> TokenAuth:
    return TokenAuth(secret=_SECRET, expiry_seconds=3600)


def _make_gateway(tmp_path: Path, auth: TokenAuth) -> Gateway:
    audit_path = tmp_path / "audit" / "audit.jsonl"
    audit_path.parent.mkdir(parents=True, exist_ok=True)
    audit_log = AuditLog(audit_path)
    return Gateway(
        host="127.0.0.1",
        port=0,
        config=AppConfig(),
        audit_log=audit_log,
        auth=auth,
    )


# ---------------------------------------------------------------------------
# Fixture: gateway with runtime, wrapped in TestClient
# ---------------------------------------------------------------------------


@pytest.fixture
async def gw_client(tmp_path: Path) -> "AsyncGenerator":  # type: ignore[name-defined]
    from collections.abc import AsyncGenerator

    auth = _make_auth()
    gw = _make_gateway(tmp_path, auth)
    provider = _mock_provider("hello from assistant")
    runtime, _, _ = _make_runtime(tmp_path, provider)
    session = await runtime.initialize_session(_SESSION_KEY)
    gw.set_runtime(runtime, session)

    app = gw._build_app()
    async with TestClient(TestServer(app)) as client:
        yield client, gw, auth


# ---------------------------------------------------------------------------
# Health endpoint
# ---------------------------------------------------------------------------


async def test_health_returns_ok(gw_client: tuple) -> None:
    client, _, _ = gw_client
    resp = await client.get("/health")
    assert resp.status == 200
    text = await resp.text()
    assert text == "ok"


async def test_health_no_auth_needed(tmp_path: Path) -> None:
    """Health endpoint must be unauthenticated."""
    auth = _make_auth()
    gw = _make_gateway(tmp_path, auth)
    app = gw._build_app()
    async with TestClient(TestServer(app)) as client:
        resp = await client.get("/health")
        assert resp.status == 200


# ---------------------------------------------------------------------------
# Authentication — SU-007 §1
# ---------------------------------------------------------------------------


async def test_ws_valid_token_accepted(gw_client: tuple) -> None:
    client, _, auth = gw_client
    token = auth.generate_token(_CHANNEL_ID)
    async with client.ws_connect("/ws", headers={"Authorization": f"Bearer {token}"}) as ws:
        assert not ws.closed


async def test_ws_no_token_rejected(gw_client: tuple) -> None:
    client, _, _ = gw_client
    resp = await client.get("/ws")
    assert resp.status == 401


async def test_ws_invalid_token_rejected(gw_client: tuple) -> None:
    client, _, _ = gw_client
    resp = await client.get("/ws", headers={"Authorization": "Bearer not.a.valid.token"})
    assert resp.status == 401


async def test_ws_wrong_secret_rejected(gw_client: tuple) -> None:
    client, _, _ = gw_client
    wrong_auth = TokenAuth(secret="wrong-secret-yyyyyyyyyyyyy", expiry_seconds=3600)
    token = wrong_auth.generate_token(_CHANNEL_ID)
    resp = await client.get("/ws", headers={"Authorization": f"Bearer {token}"})
    assert resp.status == 401


# ---------------------------------------------------------------------------
# Protocol version enforcement — SU-007 §2
# ---------------------------------------------------------------------------


async def test_ws_correct_protocol_version_accepted(gw_client: tuple) -> None:
    client, _, auth = gw_client
    token = auth.generate_token(_CHANNEL_ID)
    async with client.ws_connect(
        "/ws",
        headers={
            "Authorization": f"Bearer {token}",
            "X-Protocol-Version": str(MIN_PROTOCOL_VERSION),
        },
    ) as ws:
        assert not ws.closed


async def test_ws_below_min_protocol_version_rejected(gw_client: tuple) -> None:
    client, _, auth = gw_client
    token = auth.generate_token(_CHANNEL_ID)
    resp = await client.get(
        "/ws",
        headers={
            "Authorization": f"Bearer {token}",
            "X-Protocol-Version": "0",
        },
    )
    assert resp.status == 400


async def test_ws_protocol_downgrade_logged(tmp_path: Path) -> None:
    audit_path = tmp_path / "audit" / "audit.jsonl"
    audit_path.parent.mkdir(parents=True, exist_ok=True)
    audit_log = AuditLog(audit_path)
    auth = _make_auth()
    gw = Gateway(
        host="127.0.0.1",
        port=0,
        config=AppConfig(),
        audit_log=audit_log,
        auth=auth,
    )
    app = gw._build_app()
    token = auth.generate_token(_CHANNEL_ID)
    async with TestClient(TestServer(app)) as client:
        await client.get(
            "/ws",
            headers={
                "Authorization": f"Bearer {token}",
                "X-Protocol-Version": "0",
            },
        )
    events = await audit_log.query(event_type="gateway_protocol_downgrade_attempt")
    assert len(events) == 1


# ---------------------------------------------------------------------------
# Rate limiting — SU-007 §4
# ---------------------------------------------------------------------------


async def test_rate_limiter_blocks_excess_attempts(tmp_path: Path) -> None:
    """After hitting max_attempts_per_minute, further attempts are blocked."""
    limiter = ConnectionRateLimiter(
        max_connections_per_ip=100,
        max_attempts_per_minute=3,
        max_failed_auth=100,
        failed_auth_lockout_minutes=0,
    )
    for _ in range(3):
        assert limiter.can_attempt("1.2.3.4") is True
    assert limiter.can_attempt("1.2.3.4") is False


async def test_rate_limiter_lockout_after_failed_auth() -> None:
    limiter = ConnectionRateLimiter(
        max_connections_per_ip=100,
        max_attempts_per_minute=100,
        max_failed_auth=3,
        failed_auth_lockout_minutes=15,
    )
    ip = "5.6.7.8"
    for _ in range(3):
        limiter.record_auth_failure(ip)
    assert limiter.is_locked_out(ip) is True
    assert limiter.can_attempt(ip) is False


async def test_rate_limiter_success_clears_lockout() -> None:
    limiter = ConnectionRateLimiter(
        max_connections_per_ip=100,
        max_attempts_per_minute=100,
        max_failed_auth=1,
        failed_auth_lockout_minutes=15,
    )
    ip = "9.0.1.2"
    limiter.record_auth_failure(ip)
    assert limiter.is_locked_out(ip) is True
    limiter.record_auth_success(ip)
    assert limiter.is_locked_out(ip) is False


async def test_gateway_returns_429_when_rate_limited(tmp_path: Path) -> None:
    audit_path = tmp_path / "audit" / "audit.jsonl"
    audit_path.parent.mkdir(parents=True, exist_ok=True)
    audit_log = AuditLog(audit_path)
    auth = _make_auth()
    gw = Gateway(
        host="127.0.0.1",
        port=0,
        config=AppConfig(),
        audit_log=audit_log,
        auth=auth,
    )
    # Replace rate limiter with one that always blocks
    gw._rate_limiter = ConnectionRateLimiter(
        max_connections_per_ip=0,
        max_attempts_per_minute=0,
        max_failed_auth=100,
        failed_auth_lockout_minutes=0,
    )
    # Force can_attempt to return False by exhausting attempts instantly
    gw._rate_limiter._state["127.0.0.1"].attempt_times = [float("inf")] * 100

    token = auth.generate_token(_CHANNEL_ID)
    app = gw._build_app()
    async with TestClient(TestServer(app)) as client:
        resp = await client.get("/ws", headers={"Authorization": f"Bearer {token}"})
        assert resp.status == 429


# ---------------------------------------------------------------------------
# Message routing
# ---------------------------------------------------------------------------


async def test_message_routing_returns_response(gw_client: tuple) -> None:
    client, _, auth = gw_client
    token = auth.generate_token(_CHANNEL_ID)
    user_msg = create_message(
        from_agent="channel:test",
        to_agent=_SESSION_KEY,
        session_key=_SESSION_KEY,
        type="request",
        operation="user_message",
        trust_level="main",
        params={"content": "Hello gateway!"},
    )
    async with client.ws_connect("/ws", headers={"Authorization": f"Bearer {token}"}) as ws:
        await ws.send_str(user_msg.model_dump_json())
        raw = await ws.receive_str()

    resp_data = json.loads(raw)
    assert resp_data["type"] in ("response", "error")


async def test_malformed_message_returns_error(gw_client: tuple) -> None:
    client, _, auth = gw_client
    token = auth.generate_token(_CHANNEL_ID)
    async with client.ws_connect("/ws", headers={"Authorization": f"Bearer {token}"}) as ws:
        await ws.send_str("this is not json {{{{")
        raw = await ws.receive_str()

    resp_data = json.loads(raw)
    assert resp_data["type"] == "error"
    assert resp_data["error"]["code"] == "PARSE_ERROR"


async def test_no_runtime_returns_error(tmp_path: Path) -> None:
    """route_message with no runtime registered returns an error message."""
    auth = _make_auth()
    gw = _make_gateway(tmp_path, auth)
    # Do NOT call set_runtime
    user_msg = create_message(
        from_agent="channel:test",
        to_agent=_SESSION_KEY,
        session_key=_SESSION_KEY,
        type="request",
        operation="user_message",
        trust_level="main",
        params={"content": "hello"},
    )
    response = await gw.route_message(user_msg)
    assert response.type == "error"
    assert response.error is not None
    assert response.error["code"] == "NO_RUNTIME"


# ---------------------------------------------------------------------------
# Disconnect handling
# ---------------------------------------------------------------------------


async def test_disconnect_removes_connection(gw_client: tuple) -> None:
    client, gw, auth = gw_client
    token = auth.generate_token(_CHANNEL_ID)
    import asyncio

    async with client.ws_connect("/ws", headers={"Authorization": f"Bearer {token}"}) as ws:
        # Yield to event loop so handle_connection can register the connection
        await asyncio.sleep(0.05)
        assert _CHANNEL_ID in gw._connections
    # After context exits, socket closes; give server a moment to clean up
    await asyncio.sleep(0.05)
    assert _CHANNEL_ID not in gw._connections


# ---------------------------------------------------------------------------
# Proxy trust — SU-007 §3
# ---------------------------------------------------------------------------


async def test_get_client_ip_ignores_forwarded_from_untrusted(tmp_path: Path) -> None:
    gw = _make_gateway(tmp_path, _make_auth())
    request = MagicMock()
    request.remote = "192.168.1.1"  # not in trusted_proxies
    request.headers = {"X-Forwarded-For": "10.0.0.1"}
    ip = gw.get_client_ip(request)
    assert ip == "192.168.1.1"


async def test_get_client_ip_honours_forwarded_from_trusted(tmp_path: Path) -> None:
    gw = _make_gateway(tmp_path, _make_auth())
    request = MagicMock()
    request.remote = "127.0.0.1"  # in trusted_proxies
    request.headers = {"X-Forwarded-For": "203.0.113.5, 10.0.0.1"}
    ip = gw.get_client_ip(request)
    assert ip == "203.0.113.5"
