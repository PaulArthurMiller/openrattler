"""Tests for CLIChat — the CLI channel adapter."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import AsyncMock, MagicMock

import pytest

from openrattler.agents.providers.base import LLMProvider, LLMResponse, TokenUsage
from openrattler.cli.chat import CLI_SESSION_KEY, CLIChat

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _usage() -> TokenUsage:
    return TokenUsage(
        prompt_tokens=10, completion_tokens=5, total_tokens=15, estimated_cost_usd=0.0
    )


def _mock_provider(content: str = "Hello from assistant") -> LLMProvider:
    """Return an LLMProvider mock that always responds with *content*."""
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


# ---------------------------------------------------------------------------
# open() — component initialisation
# ---------------------------------------------------------------------------


async def test_open_creates_storage_dirs(tmp_path: Path) -> None:
    chat = CLIChat(workspace_dir=tmp_path, provider=_mock_provider())
    await chat.open()
    for subdir in ("sessions", "memory", "audit"):
        assert (tmp_path / subdir).is_dir(), f"missing storage dir: {subdir}"


async def test_open_is_idempotent(tmp_path: Path) -> None:
    chat = CLIChat(workspace_dir=tmp_path, provider=_mock_provider())
    await chat.open()
    # Second open must not raise
    await chat.open()


# ---------------------------------------------------------------------------
# send() — message processing
# ---------------------------------------------------------------------------


async def test_send_returns_assistant_content(tmp_path: Path) -> None:
    expected = "Hello from assistant"
    chat = CLIChat(workspace_dir=tmp_path, provider=_mock_provider(expected))
    await chat.open()
    result = await chat.send("Hi!")
    assert result == expected


async def test_send_calls_llm_provider(tmp_path: Path) -> None:
    provider = _mock_provider()
    chat = CLIChat(workspace_dir=tmp_path, provider=provider)
    await chat.open()
    await chat.send("Test message")
    assert provider.complete.called  # type: ignore[attr-defined]


async def test_send_without_open_raises(tmp_path: Path) -> None:
    chat = CLIChat(workspace_dir=tmp_path, provider=_mock_provider())
    with pytest.raises(RuntimeError, match="open()"):
        await chat.send("hello")


async def test_send_multiple_turns(tmp_path: Path) -> None:
    responses = ["First response", "Second response", "Third response"]
    provider = MagicMock(spec=LLMProvider)
    provider.complete = AsyncMock(
        side_effect=[
            LLMResponse(
                content=r,
                tool_calls=[],
                usage=_usage(),
                model="test-model",
                finish_reason="stop",
            )
            for r in responses
        ]
    )
    chat = CLIChat(workspace_dir=tmp_path, provider=provider)
    await chat.open()
    for expected in responses:
        result = await chat.send("a message")
        assert result == expected


# ---------------------------------------------------------------------------
# Transcript persistence
# ---------------------------------------------------------------------------


async def test_send_persists_transcript(tmp_path: Path) -> None:
    chat = CLIChat(workspace_dir=tmp_path, provider=_mock_provider())
    await chat.open()
    await chat.send("Remember this")

    # The session transcript file must exist after a turn
    sessions_dir = tmp_path / "sessions"
    jsonl_files = list(sessions_dir.rglob("*.jsonl"))
    assert len(jsonl_files) == 1, f"expected 1 JSONL file, found: {jsonl_files}"


# ---------------------------------------------------------------------------
# Session key
# ---------------------------------------------------------------------------


async def test_session_key_is_cli_constant(tmp_path: Path) -> None:
    chat = CLIChat(workspace_dir=tmp_path, provider=_mock_provider())
    await chat.open()
    assert chat._session is not None
    assert chat._session.key == CLI_SESSION_KEY


# ---------------------------------------------------------------------------
# _handle_command — slash commands
# ---------------------------------------------------------------------------


async def test_handle_command_quit(tmp_path: Path) -> None:
    chat = CLIChat(workspace_dir=tmp_path, provider=_mock_provider())
    await chat.open()
    result = await chat._handle_command("/quit")
    assert result == "quit"


async def test_handle_command_exit(tmp_path: Path) -> None:
    chat = CLIChat(workspace_dir=tmp_path, provider=_mock_provider())
    await chat.open()
    result = await chat._handle_command("/exit")
    assert result == "quit"


async def test_handle_command_help(
    tmp_path: Path, capsys: pytest.CaptureFixture  # type: ignore[type-arg]
) -> None:
    chat = CLIChat(workspace_dir=tmp_path, provider=_mock_provider())
    await chat.open()
    result = await chat._handle_command("/help")
    assert result == ""
    out = capsys.readouterr().out
    assert "/quit" in out


async def test_handle_command_session(
    tmp_path: Path, capsys: pytest.CaptureFixture  # type: ignore[type-arg]
) -> None:
    chat = CLIChat(workspace_dir=tmp_path, provider=_mock_provider())
    await chat.open()
    await chat._handle_command("/session")
    out = capsys.readouterr().out
    assert CLI_SESSION_KEY in out


async def test_handle_command_history(
    tmp_path: Path, capsys: pytest.CaptureFixture  # type: ignore[type-arg]
) -> None:
    chat = CLIChat(workspace_dir=tmp_path, provider=_mock_provider("assistant reply"))
    await chat.open()
    await chat.send("user message")
    capsys.readouterr()  # discard send output
    await chat._handle_command("/history 10")
    out = capsys.readouterr().out
    assert "user message" in out or "assistant reply" in out


async def test_handle_command_unknown(
    tmp_path: Path, capsys: pytest.CaptureFixture  # type: ignore[type-arg]
) -> None:
    chat = CLIChat(workspace_dir=tmp_path, provider=_mock_provider())
    await chat.open()
    result = await chat._handle_command("/nonexistent")
    assert result == ""
    out = capsys.readouterr().out
    assert "Unknown command" in out
