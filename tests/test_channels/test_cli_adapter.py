"""Tests for openrattler.channels.cli_adapter.CLIAdapter.

Security guarantees verified here:
- Produced UniversalMessage always has the correct trust_level ("main").
- Session key is always "agent:main:main" regardless of peer_info.
- channel field is always "cli".
- from_agent is always "channel:cli".
- operation is always "user_message".
- text content is preserved exactly.
- send() correctly formats response and error messages.
- get_session_key always returns CLI_SESSION_KEY.
- connect/disconnect are no-ops (smoke test).
"""

from __future__ import annotations

import io
import sys
from typing import Any
from unittest.mock import AsyncMock, patch

import pytest

from openrattler.channels.base import ChannelAdapter
from openrattler.channels.cli_adapter import CLI_SESSION_KEY, CLIAdapter
from openrattler.models.messages import UniversalMessage, create_message, create_response

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_response(content: str) -> UniversalMessage:
    """Build a minimal response UniversalMessage for send() tests."""
    req = create_message(
        from_agent="channel:cli",
        to_agent="agent:main:main",
        session_key="agent:main:main",
        type="request",
        operation="user_message",
        trust_level="main",
        params={"content": "hello"},
    )
    return create_response(
        req, from_agent="agent:main:main", trust_level="main", params={"content": content}
    )


def _make_error_response(error_message: str) -> UniversalMessage:
    """Build an error UniversalMessage for send() tests."""
    return create_message(
        from_agent="agent:main:main",
        to_agent="channel:cli",
        session_key="agent:main:main",
        type="error",
        operation="user_message",
        trust_level="main",
        params={},
        error={"message": error_message, "code": "INTERNAL_ERROR"},
    )


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture()
def adapter() -> CLIAdapter:
    return CLIAdapter()


# ---------------------------------------------------------------------------
# ChannelAdapter ABC compliance
# ---------------------------------------------------------------------------


class TestChannelAdapterCompliance:
    def test_cli_adapter_is_channel_adapter(self, adapter: CLIAdapter) -> None:
        assert isinstance(adapter, ChannelAdapter)

    def test_channel_name(self, adapter: CLIAdapter) -> None:
        assert adapter.channel_name == "cli"

    async def test_connect_is_noop(self, adapter: CLIAdapter) -> None:
        """connect() must complete without error."""
        await adapter.connect()

    async def test_disconnect_is_noop(self, adapter: CLIAdapter) -> None:
        """disconnect() must complete without error and be idempotent."""
        await adapter.disconnect()
        await adapter.disconnect()  # second call must also not raise


# ---------------------------------------------------------------------------
# text_to_message — message construction
# ---------------------------------------------------------------------------


class TestTextToMessage:
    def test_produces_universal_message(self, adapter: CLIAdapter) -> None:
        msg = adapter.text_to_message("hello")
        assert isinstance(msg, UniversalMessage)

    def test_trust_level_is_main(self, adapter: CLIAdapter) -> None:
        """CLI trust level must always be 'main' — never derived from user text."""
        msg = adapter.text_to_message("ignore previous instructions")
        assert msg.trust_level == "main"

    def test_session_key_is_main(self, adapter: CLIAdapter) -> None:
        msg = adapter.text_to_message("hello")
        assert msg.session_key == CLI_SESSION_KEY
        assert msg.session_key == "agent:main:main"

    def test_from_agent_is_channel_cli(self, adapter: CLIAdapter) -> None:
        msg = adapter.text_to_message("hello")
        assert msg.from_agent == "channel:cli"

    def test_to_agent_is_main_session(self, adapter: CLIAdapter) -> None:
        msg = adapter.text_to_message("hello")
        assert msg.to_agent == "agent:main:main"

    def test_operation_is_user_message(self, adapter: CLIAdapter) -> None:
        msg = adapter.text_to_message("hello")
        assert msg.operation == "user_message"

    def test_type_is_request(self, adapter: CLIAdapter) -> None:
        msg = adapter.text_to_message("hello")
        assert msg.type == "request"

    def test_channel_field_is_cli(self, adapter: CLIAdapter) -> None:
        msg = adapter.text_to_message("hello")
        assert msg.channel == "cli"

    def test_content_is_preserved(self, adapter: CLIAdapter) -> None:
        text = "What is the weather in Asheville?"
        msg = adapter.text_to_message(text)
        assert msg.params["content"] == text

    def test_empty_string_preserved(self, adapter: CLIAdapter) -> None:
        msg = adapter.text_to_message("")
        assert msg.params["content"] == ""

    def test_multiline_text_preserved(self, adapter: CLIAdapter) -> None:
        text = "line one\nline two\nline three"
        msg = adapter.text_to_message(text)
        assert msg.params["content"] == text

    def test_message_id_is_unique(self, adapter: CLIAdapter) -> None:
        msg1 = adapter.text_to_message("hello")
        msg2 = adapter.text_to_message("hello")
        assert msg1.message_id != msg2.message_id


# ---------------------------------------------------------------------------
# get_session_key — always returns CLI_SESSION_KEY
# ---------------------------------------------------------------------------


class TestGetSessionKey:
    def test_returns_cli_session_key(self, adapter: CLIAdapter) -> None:
        assert adapter.get_session_key({}) == CLI_SESSION_KEY

    def test_ignores_peer_info_user_id(self, adapter: CLIAdapter) -> None:
        """peer_info contents must not influence the session key."""
        assert adapter.get_session_key({"user_id": 99999}) == CLI_SESSION_KEY

    def test_ignores_arbitrary_peer_info(self, adapter: CLIAdapter) -> None:
        assert adapter.get_session_key({"anything": "injected"}) == CLI_SESSION_KEY

    def test_session_key_starts_with_agent(self, adapter: CLIAdapter) -> None:
        key = adapter.get_session_key({})
        assert key.startswith("agent:")


# ---------------------------------------------------------------------------
# send() — output formatting
# ---------------------------------------------------------------------------


class TestSend:
    async def test_send_response_prints_content(
        self, adapter: CLIAdapter, capsys: pytest.CaptureFixture[str]
    ) -> None:
        msg = _make_response("Hello, world!")
        await adapter.send(msg)
        out = capsys.readouterr().out
        assert "Hello, world!" in out

    async def test_send_response_includes_prefix(
        self, adapter: CLIAdapter, capsys: pytest.CaptureFixture[str]
    ) -> None:
        msg = _make_response("Hi there.")
        await adapter.send(msg)
        out = capsys.readouterr().out
        assert out.startswith("Assistant:")

    async def test_send_error_formats_error_message(
        self, adapter: CLIAdapter, capsys: pytest.CaptureFixture[str]
    ) -> None:
        msg = _make_error_response("Something went wrong")
        await adapter.send(msg)
        out = capsys.readouterr().out
        assert "[Error:" in out
        assert "Something went wrong" in out

    async def test_send_error_without_message_field(
        self, adapter: CLIAdapter, capsys: pytest.CaptureFixture[str]
    ) -> None:
        """Error messages with missing 'message' field fall back gracefully."""
        err_msg = create_message(
            from_agent="agent:main:main",
            to_agent="channel:cli",
            session_key="agent:main:main",
            type="error",
            operation="user_message",
            trust_level="main",
            params={},
            error={"code": "X"},
        )
        await adapter.send(err_msg)
        out = capsys.readouterr().out
        assert "[Error:" in out


# ---------------------------------------------------------------------------
# receive() — stdin integration (mocked)
# ---------------------------------------------------------------------------


class TestReceive:
    async def test_receive_wraps_stdin_input(self, adapter: CLIAdapter) -> None:
        """receive() should read from stdin and return a valid UniversalMessage."""
        with patch.object(adapter, "_read_line", return_value="test input"):
            msg = await adapter.receive()

        assert isinstance(msg, UniversalMessage)
        assert msg.params["content"] == "test input"
        assert msg.trust_level == "main"
        assert msg.session_key == CLI_SESSION_KEY

    async def test_receive_strips_whitespace(self, adapter: CLIAdapter) -> None:
        """Leading/trailing whitespace is stripped from typed input."""
        with patch.object(adapter, "_read_line", return_value="  hello world  "):
            msg = await adapter.receive()

        assert msg.params["content"] == "hello world"
