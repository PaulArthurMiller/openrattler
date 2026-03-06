"""Tests for openrattler.mcp.connection — MCPServerConnection."""

from __future__ import annotations

import asyncio
import contextlib
import os
from contextlib import asynccontextmanager
from typing import Any, AsyncGenerator
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from openrattler.mcp.connection import MCPServerConnection, _build_safe_env
from openrattler.models.mcp import MCPServerManifest

# ---------------------------------------------------------------------------
# Fixtures and helpers
# ---------------------------------------------------------------------------


def _stdio_manifest(**kwargs: Any) -> MCPServerManifest:
    defaults: dict[str, Any] = dict(
        server_id="test-mcp",
        version="1.0.0",
        publisher="Test",
        transport="stdio",
        command="/usr/bin/test-mcp",
    )
    defaults.update(kwargs)
    return MCPServerManifest(**defaults)


def _http_manifest(**kwargs: Any) -> MCPServerManifest:
    defaults: dict[str, Any] = dict(
        server_id="test-mcp",
        version="1.0.0",
        publisher="Test",
        transport="streamable_http",
        url="https://mcp.example.com",
    )
    defaults.update(kwargs)
    return MCPServerManifest(**defaults)


class _FakeClientSession:
    """Async context manager wrapping a mock session object."""

    def __init__(self, session: AsyncMock) -> None:
        self._session = session

    async def __aenter__(self) -> AsyncMock:
        return self._session

    async def __aexit__(self, *args: Any) -> None:
        pass


class _FakeClientSessionFactory:
    """Callable that produces _FakeClientSession, capturing constructor args."""

    def __init__(self, session: AsyncMock) -> None:
        self._session = session
        self.read: Any = None
        self.write: Any = None

    def __call__(self, read: Any, write: Any) -> _FakeClientSession:
        self.read = read
        self.write = write
        return _FakeClientSession(self._session)


def _make_mock_session(
    tools: list[Any] | None = None,
    call_result: Any = None,
) -> AsyncMock:
    """Return a configured mock ClientSession."""
    session = AsyncMock()
    session.initialize = AsyncMock(return_value=None)

    # list_tools result
    list_result = MagicMock()
    list_result.tools = tools or []
    session.list_tools = AsyncMock(return_value=list_result)

    # call_tool result
    if call_result is None:
        call_result = MagicMock()
        call_result.isError = False
        call_result.model_dump = MagicMock(return_value={"content": [], "isError": False})
    session.call_tool = AsyncMock(return_value=call_result)

    return session


def _make_fake_stdio(captured_params: list[Any] | None = None) -> Any:
    """Return a fake stdio_client context manager factory."""

    @asynccontextmanager
    async def _transport(server_params: Any) -> AsyncGenerator[tuple[Any, Any], None]:
        if captured_params is not None:
            captured_params.append(server_params)
        yield MagicMock(), MagicMock()

    return _transport


def _make_fake_http() -> Any:
    """Return a fake streamablehttp_client context manager factory."""

    @asynccontextmanager
    async def _transport(*, url: str, **kwargs: Any) -> AsyncGenerator[tuple[Any, Any, None], None]:
        yield MagicMock(), MagicMock(), None

    return _transport


@contextlib.asynccontextmanager
async def _connected(
    manifest: MCPServerManifest,
    session: AsyncMock,
    *,
    timeout: int = 5,
    stdio: bool = True,
) -> AsyncGenerator[MCPServerConnection, None]:
    """Connect a MCPServerConnection using fake transports, yield it, then disconnect."""
    conn = MCPServerConnection(manifest, timeout_seconds=timeout)
    factory = _FakeClientSessionFactory(session)
    transport = _make_fake_stdio() if stdio else _make_fake_http()
    transport_path = (
        "openrattler.mcp.connection.stdio_client"
        if stdio
        else "openrattler.mcp.connection.streamablehttp_client"
    )
    with (
        patch(transport_path, transport),
        patch("openrattler.mcp.connection.ClientSession", factory),
    ):
        await conn.connect()
        try:
            yield conn
        finally:
            await conn.disconnect()


# ---------------------------------------------------------------------------
# TestStdioConnection
# ---------------------------------------------------------------------------


class TestStdioConnection:
    async def test_connect_succeeds(self) -> None:
        session = _make_mock_session()
        async with _connected(_stdio_manifest(), session) as conn:
            assert conn.is_connected

    async def test_connect_calls_initialize(self) -> None:
        session = _make_mock_session()
        async with _connected(_stdio_manifest(), session) as conn:
            session.initialize.assert_awaited_once()

    async def test_disconnect_clears_connected(self) -> None:
        session = _make_mock_session()
        conn = MCPServerConnection(_stdio_manifest(), timeout_seconds=5)
        factory = _FakeClientSessionFactory(session)
        with (
            patch("openrattler.mcp.connection.stdio_client", _make_fake_stdio()),
            patch("openrattler.mcp.connection.ClientSession", factory),
        ):
            await conn.connect()
            assert conn.is_connected
            await conn.disconnect()
            assert not conn.is_connected

    async def test_subprocess_receives_filtered_env(self) -> None:
        captured: list[Any] = []
        manifest = _stdio_manifest(env={"MY_API_KEY": "secret123"})
        session = _make_mock_session()
        factory = _FakeClientSessionFactory(session)
        conn = MCPServerConnection(manifest, timeout_seconds=5)
        with (
            patch("openrattler.mcp.connection.stdio_client", _make_fake_stdio(captured)),
            patch("openrattler.mcp.connection.ClientSession", factory),
        ):
            await conn.connect()
            await conn.disconnect()

        assert len(captured) == 1
        env = captured[0].env
        # Manifest env var is present
        assert env.get("MY_API_KEY") == "secret123"
        # OpenRattler secrets are not leaked
        assert "OPENAI_API_KEY" not in env
        assert "ANTHROPIC_API_KEY" not in env

    async def test_init_timeout_raises_timeout_error(self) -> None:
        """If initialization hangs, TimeoutError is raised.

        The delay is placed in the transport's __aenter__ so that the
        background task is genuinely blocked before signalling _initialized.
        (AsyncMock side_effect with a lambda returning a coroutine does NOT
        await the coroutine — use an async def instead.)
        """

        @asynccontextmanager
        async def _slow_transport(server_params: Any) -> AsyncGenerator[tuple[Any, Any], None]:
            # Hang here long enough that the 0.1-second timeout fires.
            await asyncio.sleep(10)
            yield MagicMock(), MagicMock()  # pragma: no cover

        slow_session = AsyncMock()
        slow_session.initialize = AsyncMock(return_value=None)

        class _SlowFactory:
            def __call__(self, read: Any, write: Any) -> _FakeClientSession:
                return _FakeClientSession(slow_session)  # pragma: no cover

        conn = MCPServerConnection(_stdio_manifest(), timeout_seconds=0.1)  # type: ignore[arg-type]
        with (
            patch("openrattler.mcp.connection.stdio_client", _slow_transport),
            patch("openrattler.mcp.connection.ClientSession", _SlowFactory()),
        ):
            with pytest.raises(TimeoutError, match="initialization timed out"):
                await conn.connect()

    async def test_init_error_raised_as_connection_error(self) -> None:
        """If the SDK raises during initialize, ConnectionError is propagated."""
        session = AsyncMock()
        session.initialize = AsyncMock(side_effect=RuntimeError("transport broken"))

        conn = MCPServerConnection(_stdio_manifest(), timeout_seconds=5)
        with (
            patch("openrattler.mcp.connection.stdio_client", _make_fake_stdio()),
            patch("openrattler.mcp.connection.ClientSession", _FakeClientSessionFactory(session)),
        ):
            with pytest.raises(ConnectionError, match="initialization failed"):
                await conn.connect()


# ---------------------------------------------------------------------------
# TestHTTPConnection
# ---------------------------------------------------------------------------


class TestHTTPConnection:
    async def test_connect_succeeds(self) -> None:
        session = _make_mock_session()
        async with _connected(_http_manifest(), session, stdio=False) as conn:
            assert conn.is_connected

    async def test_connect_calls_initialize(self) -> None:
        session = _make_mock_session()
        async with _connected(_http_manifest(), session, stdio=False) as conn:
            session.initialize.assert_awaited_once()

    async def test_disconnect_clears_connected(self) -> None:
        session = _make_mock_session()
        conn = MCPServerConnection(_http_manifest(), timeout_seconds=5)
        with (
            patch("openrattler.mcp.connection.streamablehttp_client", _make_fake_http()),
            patch(
                "openrattler.mcp.connection.ClientSession",
                _FakeClientSessionFactory(session),
            ),
        ):
            await conn.connect()
            assert conn.is_connected
            await conn.disconnect()
            assert not conn.is_connected

    async def test_init_error_raised_as_connection_error(self) -> None:
        session = AsyncMock()
        session.initialize = AsyncMock(side_effect=OSError("HTTP unreachable"))

        conn = MCPServerConnection(_http_manifest(), timeout_seconds=5)
        with (
            patch("openrattler.mcp.connection.streamablehttp_client", _make_fake_http()),
            patch(
                "openrattler.mcp.connection.ClientSession",
                _FakeClientSessionFactory(session),
            ),
        ):
            with pytest.raises(ConnectionError, match="initialization failed"):
                await conn.connect()


# ---------------------------------------------------------------------------
# TestListTools
# ---------------------------------------------------------------------------


class TestListTools:
    def _make_tool(self, name: str, description: str = "") -> MagicMock:
        tool = MagicMock()
        tool.name = name
        tool.description = description
        tool.inputSchema = {"type": "object", "properties": {}}
        return tool

    async def test_returns_tool_definitions(self) -> None:
        tools = [
            self._make_tool("get_forecast", "Get weather forecast"),
            self._make_tool("get_radar", "Get radar image"),
        ]
        session = _make_mock_session(tools=tools)
        async with _connected(_stdio_manifest(), session) as conn:
            result = await conn.list_tools()

        assert len(result) == 2
        assert result[0]["name"] == "get_forecast"
        assert result[0]["description"] == "Get weather forecast"
        assert result[1]["name"] == "get_radar"

    async def test_includes_input_schema(self) -> None:
        schema = {"type": "object", "properties": {"city": {"type": "string"}}}
        tool = self._make_tool("get_forecast")
        tool.inputSchema = schema
        session = _make_mock_session(tools=[tool])
        async with _connected(_stdio_manifest(), session) as conn:
            result = await conn.list_tools()

        assert result[0]["inputSchema"] == schema

    async def test_empty_tool_list(self) -> None:
        session = _make_mock_session(tools=[])
        async with _connected(_stdio_manifest(), session) as conn:
            result = await conn.list_tools()

        assert result == []

    async def test_none_description_becomes_empty_string(self) -> None:
        tool = self._make_tool("get_forecast")
        tool.description = None
        session = _make_mock_session(tools=[tool])
        async with _connected(_stdio_manifest(), session) as conn:
            result = await conn.list_tools()

        assert result[0]["description"] == ""

    async def test_raises_when_not_connected(self) -> None:
        conn = MCPServerConnection(_stdio_manifest())
        with pytest.raises(ConnectionError, match="not connected"):
            await conn.list_tools()


# ---------------------------------------------------------------------------
# TestCallTool
# ---------------------------------------------------------------------------


class TestCallTool:
    def _make_success_result(self, data: dict[str, Any]) -> MagicMock:
        result = MagicMock()
        result.isError = False
        result.model_dump = MagicMock(return_value=data)
        return result

    def _make_error_result(self, message: str) -> MagicMock:
        result = MagicMock()
        result.isError = True
        content_item = MagicMock()
        content_item.text = message
        result.content = [content_item]
        return result

    async def test_successful_call_returns_dict(self) -> None:
        expected = {"content": [{"type": "text", "text": "22°C"}], "isError": False}
        call_result = self._make_success_result(expected)
        session = _make_mock_session(call_result=call_result)
        async with _connected(_stdio_manifest(), session) as conn:
            result = await conn.call_tool("get_forecast", {"city": "London"})

        assert result == expected
        session.call_tool.assert_awaited_once_with("get_forecast", {"city": "London"})

    async def test_server_error_result_raises_runtime_error(self) -> None:
        error_result = self._make_error_result("API rate limit exceeded")
        session = _make_mock_session(call_result=error_result)
        async with _connected(_stdio_manifest(), session) as conn:
            with pytest.raises(RuntimeError, match="API rate limit exceeded"):
                await conn.call_tool("get_forecast", {})

    async def test_call_timeout_raises_timeout_error(self) -> None:
        """call_tool raises TimeoutError when the server does not respond in time.

        Uses an asyncio.Event that is never set so the mock call_tool hangs
        indefinitely — then a very short timeout triggers the error.
        (AsyncMock side_effect with a lambda returning a coroutine does NOT
        await the coroutine — use a proper async def instead.)
        """
        never_resolves: asyncio.Event = asyncio.Event()

        async def _hanging_call(*args: Any, **kwargs: Any) -> None:
            await never_resolves.wait()  # blocks until disconnect cancels the task

        session = AsyncMock()
        session.initialize = AsyncMock(return_value=None)
        session.call_tool = AsyncMock(side_effect=_hanging_call)

        conn = MCPServerConnection(_stdio_manifest(), timeout_seconds=5)
        factory = _FakeClientSessionFactory(session)
        with (
            patch("openrattler.mcp.connection.stdio_client", _make_fake_stdio()),
            patch("openrattler.mcp.connection.ClientSession", factory),
        ):
            await conn.connect()
            conn._timeout = 0.1  # type: ignore[assignment]  # short timeout for the call
            with pytest.raises(TimeoutError, match="timed out"):
                await conn.call_tool("slow_tool", {})
            conn._timeout = 5  # restore for clean disconnect
            await conn.disconnect()

    async def test_raises_when_not_connected(self) -> None:
        conn = MCPServerConnection(_stdio_manifest())
        with pytest.raises(ConnectionError, match="not connected"):
            await conn.call_tool("get_forecast", {})

    async def test_passes_arguments_to_session(self) -> None:
        call_result = self._make_success_result({})
        session = _make_mock_session(call_result=call_result)
        async with _connected(_stdio_manifest(), session) as conn:
            await conn.call_tool("place_order", {"item": "pizza", "qty": 2})

        session.call_tool.assert_awaited_once_with("place_order", {"item": "pizza", "qty": 2})


# ---------------------------------------------------------------------------
# TestEnvironmentFiltering
# ---------------------------------------------------------------------------


class TestEnvironmentFiltering:
    def test_includes_manifest_declared_vars(self) -> None:
        env = _build_safe_env({"WEATHER_API_KEY": "abc123", "LOCALE": "en_US"})
        assert env["WEATHER_API_KEY"] == "abc123"
        assert env["LOCALE"] == "en_US"

    def test_excludes_openai_api_key(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("OPENAI_API_KEY", "sk-secret")
        env = _build_safe_env({})
        assert "OPENAI_API_KEY" not in env

    def test_excludes_anthropic_api_key(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant-secret")
        env = _build_safe_env({})
        assert "ANTHROPIC_API_KEY" not in env

    def test_excludes_arbitrary_secret(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("DATABASE_PASSWORD", "hunter2")
        env = _build_safe_env({})
        assert "DATABASE_PASSWORD" not in env

    def test_includes_path_if_present(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("PATH", "/usr/bin:/bin")
        env = _build_safe_env({})
        assert env.get("PATH") == "/usr/bin:/bin"

    def test_manifest_env_overlays_safe_base(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Manifest vars can override safe-base vars (e.g. custom PATH)."""
        monkeypatch.setenv("PATH", "/usr/bin")
        env = _build_safe_env({"PATH": "/custom/bin:/usr/bin"})
        assert env["PATH"] == "/custom/bin:/usr/bin"

    def test_empty_manifest_env(self) -> None:
        env = _build_safe_env({})
        # Should contain only safe-base keys that exist in current environment.
        for key in env:
            assert key in (
                "PATH",
                "HOME",
                "USER",
                "LANG",
                "TERM",
                "PYTHONPATH",
                "VIRTUAL_ENV",
                "SystemRoot",
                "COMSPEC",
                "TMPDIR",
                "TMP",
                "TEMP",
            ), f"Unexpected key in safe env: {key}"

    def test_manifest_env_can_add_new_keys(self) -> None:
        env = _build_safe_env({"CUSTOM_VAR": "value", "ANOTHER": "42"})
        assert env["CUSTOM_VAR"] == "value"
        assert env["ANOTHER"] == "42"


# ---------------------------------------------------------------------------
# TestConnectionLifecycle
# ---------------------------------------------------------------------------


class TestConnectionLifecycle:
    async def test_double_connect_is_idempotent(self) -> None:
        session = _make_mock_session()
        conn = MCPServerConnection(_stdio_manifest(), timeout_seconds=5)
        factory = _FakeClientSessionFactory(session)
        with (
            patch("openrattler.mcp.connection.stdio_client", _make_fake_stdio()),
            patch("openrattler.mcp.connection.ClientSession", factory),
        ):
            await conn.connect()
            assert conn.is_connected
            await conn.connect()  # Second connect — should be a no-op
            assert conn.is_connected
            # initialize called only once
            session.initialize.assert_awaited_once()
            await conn.disconnect()

    async def test_double_disconnect_is_safe(self) -> None:
        session = _make_mock_session()
        conn = MCPServerConnection(_stdio_manifest(), timeout_seconds=5)
        factory = _FakeClientSessionFactory(session)
        with (
            patch("openrattler.mcp.connection.stdio_client", _make_fake_stdio()),
            patch("openrattler.mcp.connection.ClientSession", factory),
        ):
            await conn.connect()
            await conn.disconnect()
            await conn.disconnect()  # Second disconnect — should be a no-op
        assert not conn.is_connected

    async def test_call_after_disconnect_raises(self) -> None:
        session = _make_mock_session()
        conn = MCPServerConnection(_stdio_manifest(), timeout_seconds=5)
        factory = _FakeClientSessionFactory(session)
        with (
            patch("openrattler.mcp.connection.stdio_client", _make_fake_stdio()),
            patch("openrattler.mcp.connection.ClientSession", factory),
        ):
            await conn.connect()
            await conn.disconnect()

        with pytest.raises(ConnectionError, match="not connected"):
            await conn.call_tool("get_forecast", {})

    async def test_list_tools_after_disconnect_raises(self) -> None:
        session = _make_mock_session()
        conn = MCPServerConnection(_stdio_manifest(), timeout_seconds=5)
        factory = _FakeClientSessionFactory(session)
        with (
            patch("openrattler.mcp.connection.stdio_client", _make_fake_stdio()),
            patch("openrattler.mcp.connection.ClientSession", factory),
        ):
            await conn.connect()
            await conn.disconnect()

        with pytest.raises(ConnectionError, match="not connected"):
            await conn.list_tools()

    async def test_server_id_property(self) -> None:
        conn = MCPServerConnection(_stdio_manifest(server_id="weather-mcp"))
        assert conn.server_id == "weather-mcp"

    async def test_not_connected_initially(self) -> None:
        conn = MCPServerConnection(_stdio_manifest())
        assert not conn.is_connected
