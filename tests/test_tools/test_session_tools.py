"""Tests for the built-in sessions_history tool."""

from __future__ import annotations

from pathlib import Path

import pytest

from openrattler.models.messages import create_message
from openrattler.storage.transcripts import TranscriptStore
from openrattler.tools.builtin.session_tools import (
    configure_transcript_store,
    sessions_history,
)

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

_SESSION = "agent:main:main"


def _msg(content: str) -> object:
    return create_message(
        from_agent="main",
        to_agent="main",
        session_key=_SESSION,
        type="request",
        operation="chat",
        trust_level="main",
        params={"content": content},
    )


@pytest.fixture(autouse=True)
def reset_session_store() -> object:
    """Reset the module-level store after each test."""
    yield
    configure_transcript_store(None)


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


class TestSessionsHistory:
    async def test_returns_messages_as_list_of_dicts(self, tmp_path: Path) -> None:
        store = TranscriptStore(tmp_path)
        configure_transcript_store(store)
        await store.append(_SESSION, _msg("hello"))  # type: ignore[arg-type]
        result = await sessions_history(_SESSION)
        assert isinstance(result, list)
        assert len(result) == 1
        assert isinstance(result[0], dict)

    async def test_message_dict_has_expected_fields(self, tmp_path: Path) -> None:
        store = TranscriptStore(tmp_path)
        configure_transcript_store(store)
        await store.append(_SESSION, _msg("ping"))  # type: ignore[arg-type]
        result = await sessions_history(_SESSION)
        entry = result[0]
        assert "message_id" in entry
        assert "session_key" in entry
        assert entry["session_key"] == _SESSION

    async def test_respects_n_limit(self, tmp_path: Path) -> None:
        store = TranscriptStore(tmp_path)
        configure_transcript_store(store)
        for i in range(5):
            await store.append(_SESSION, _msg(f"msg{i}"))  # type: ignore[arg-type]
        result = await sessions_history(_SESSION, n=3)
        assert len(result) == 3

    async def test_default_n_is_ten(self, tmp_path: Path) -> None:
        store = TranscriptStore(tmp_path)
        configure_transcript_store(store)
        for i in range(15):
            await store.append(_SESSION, _msg(f"msg{i}"))  # type: ignore[arg-type]
        result = await sessions_history(_SESSION)
        assert len(result) == 10

    async def test_returns_most_recent_messages(self, tmp_path: Path) -> None:
        store = TranscriptStore(tmp_path)
        configure_transcript_store(store)
        for i in range(5):
            await store.append(_SESSION, _msg(f"msg{i}"))  # type: ignore[arg-type]
        result = await sessions_history(_SESSION, n=2)
        # load_recent returns the last n, so we should get msg3 and msg4
        params_list = [entry["params"]["content"] for entry in result]
        assert "msg3" in params_list
        assert "msg4" in params_list

    async def test_raises_when_store_not_configured(self) -> None:
        # No configure_transcript_store call — default is None.
        with pytest.raises(RuntimeError, match="TranscriptStore not configured"):
            await sessions_history(_SESSION)

    async def test_empty_session_returns_empty_list(self, tmp_path: Path) -> None:
        store = TranscriptStore(tmp_path)
        configure_transcript_store(store)
        result = await sessions_history(_SESSION)
        assert result == []

    async def test_invalid_session_key_raises(self, tmp_path: Path) -> None:
        store = TranscriptStore(tmp_path)
        configure_transcript_store(store)
        with pytest.raises(ValueError):
            await sessions_history("not-a-valid-key")

    def test_tool_definition_attached(self) -> None:
        assert hasattr(sessions_history, "_tool_definition")
        assert sessions_history._tool_definition.name == "sessions_history"  # type: ignore[attr-defined]

    def test_tool_requires_approval(self) -> None:
        assert sessions_history._tool_definition.requires_approval is True  # type: ignore[attr-defined]
