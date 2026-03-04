"""Tests for openrattler.security.sanitize — path, session key, and agent ID validation.

These tests are critical security guarantees:
- No path traversal is possible
- Session keys with injection characters are rejected
- Agent IDs are constrained to safe identifiers
"""

from __future__ import annotations

import os
from pathlib import Path

import pytest

from openrattler.security.sanitize import sanitize_path, sanitize_session_key, validate_agent_id

# ---------------------------------------------------------------------------
# sanitize_path
# ---------------------------------------------------------------------------


class TestSanitizePath:
    """Tests for sanitize_path."""

    def test_valid_path_within_allowed_dir(self, tmp_path: Path) -> None:
        """A file inside an allowed directory is accepted and returned resolved."""
        inner = tmp_path / "subdir" / "file.txt"
        inner.parent.mkdir(parents=True)
        inner.touch()
        result = sanitize_path(str(inner), [tmp_path])
        assert result == inner.resolve()

    def test_dotdot_traversal_rejected(self, tmp_path: Path) -> None:
        """Paths containing .. components are rejected immediately."""
        with pytest.raises(ValueError, match="traversal"):
            sanitize_path(str(tmp_path / ".." / "other"), [tmp_path])

    def test_path_outside_allowed_dir_rejected(self, tmp_path: Path) -> None:
        """A path outside the allowed directory is rejected."""
        allowed = tmp_path / "allowed"
        allowed.mkdir()
        outside = tmp_path / "forbidden" / "file.txt"
        with pytest.raises(ValueError):
            sanitize_path(str(outside), [allowed])

    def test_multiple_allowed_dirs_second_matches(self, tmp_path: Path) -> None:
        """A path inside the second allowed directory is accepted."""
        dir_a = tmp_path / "a"
        dir_b = tmp_path / "b"
        dir_a.mkdir()
        dir_b.mkdir()
        target = dir_b / "file.txt"
        target.touch()
        result = sanitize_path(str(target), [dir_a, dir_b])
        assert result == target.resolve()

    def test_empty_path_rejected(self, tmp_path: Path) -> None:
        """An empty path string raises ValueError."""
        with pytest.raises(ValueError):
            sanitize_path("", [tmp_path])

    def test_relative_path_within_allowed_dir(self, tmp_path: Path) -> None:
        """Relative paths that resolve inside an allowed directory are accepted."""
        (tmp_path / "file.txt").touch()
        result = sanitize_path(str(tmp_path / "file.txt"), [tmp_path])
        assert result.is_absolute()

    def test_absolute_path_outside_all_allowed_dirs(self, tmp_path: Path) -> None:
        """An absolute path that is outside all allowed directories is rejected."""
        dir_a = tmp_path / "a"
        dir_b = tmp_path / "b"
        dir_a.mkdir()
        dir_b.mkdir()
        outside = tmp_path / "c" / "file.txt"
        with pytest.raises(ValueError):
            sanitize_path(str(outside), [dir_a, dir_b])

    def test_symlink_outside_allowed_dir_rejected(self, tmp_path: Path) -> None:
        """A symlink inside the allowed dir that points outside it is rejected."""
        allowed = tmp_path / "allowed"
        allowed.mkdir()
        secret = tmp_path / "secret"
        secret.mkdir()
        (secret / "data.txt").write_text("sensitive")
        link = allowed / "link"
        try:
            link.symlink_to(secret / "data.txt")
        except (OSError, NotImplementedError):
            pytest.skip("Cannot create symlinks on this platform/environment")
        # resolve() exposes the real (symlink target) path, outside allowed.
        with pytest.raises(ValueError):
            sanitize_path(str(link), [allowed])


# ---------------------------------------------------------------------------
# sanitize_session_key
# ---------------------------------------------------------------------------


class TestSanitizeSessionKey:
    """Tests for sanitize_session_key."""

    def test_valid_minimal_key(self) -> None:
        """A minimal 3-segment key is accepted unchanged."""
        assert sanitize_session_key("agent:main:main") == "agent:main:main"

    def test_valid_key_with_channel_and_group(self) -> None:
        """A full 5-segment key (with channel and peer) is accepted."""
        key = "agent:main:telegram:group:123"
        assert sanitize_session_key(key) == key

    def test_valid_key_with_hyphens(self) -> None:
        """Hyphens and underscores in segments are allowed."""
        key = "agent:main:subagent:abc-123"
        assert sanitize_session_key(key) == key

    def test_empty_key_rejected(self) -> None:
        """An empty string is rejected."""
        with pytest.raises(ValueError):
            sanitize_session_key("")

    def test_key_with_slash_rejected(self) -> None:
        """Slashes are not allowed in session keys (path injection)."""
        with pytest.raises(ValueError):
            sanitize_session_key("agent/main/main")

    def test_key_with_semicolon_rejected(self) -> None:
        """Semicolons are not allowed (command injection)."""
        with pytest.raises(ValueError):
            sanitize_session_key("agent:main;rm -rf /")

    def test_key_with_space_rejected(self) -> None:
        """Spaces are not allowed in session keys."""
        with pytest.raises(ValueError):
            sanitize_session_key("agent:main :main")

    def test_key_with_only_two_segments_rejected(self) -> None:
        """Keys with fewer than three colon-separated segments are rejected."""
        with pytest.raises(ValueError):
            sanitize_session_key("agent:main")

    def test_key_with_special_chars_rejected(self) -> None:
        """Special characters like @ and # are not allowed."""
        with pytest.raises(ValueError):
            sanitize_session_key("agent:main@evil:main")


# ---------------------------------------------------------------------------
# validate_agent_id
# ---------------------------------------------------------------------------


class TestValidateAgentId:
    """Tests for validate_agent_id."""

    def test_valid_simple_id(self) -> None:
        """A simple alphabetic ID is accepted."""
        assert validate_agent_id("main") == "main"

    def test_valid_id_with_hyphen(self) -> None:
        """Hyphens are allowed in agent IDs."""
        assert validate_agent_id("my-agent") == "my-agent"

    def test_valid_id_with_underscore(self) -> None:
        """Underscores are allowed in agent IDs."""
        assert validate_agent_id("agent_123") == "agent_123"

    def test_valid_alphanumeric_id(self) -> None:
        """Pure alphanumeric IDs are accepted."""
        assert validate_agent_id("agent42") == "agent42"

    def test_empty_id_rejected(self) -> None:
        """An empty string is rejected."""
        with pytest.raises(ValueError):
            validate_agent_id("")

    def test_id_with_colon_rejected(self) -> None:
        """Colons are not allowed — agent IDs must be single-segment."""
        with pytest.raises(ValueError):
            validate_agent_id("agent:main")

    def test_id_with_slash_rejected(self) -> None:
        """Slashes are not allowed (path injection)."""
        with pytest.raises(ValueError):
            validate_agent_id("../etc/passwd")

    def test_id_with_space_rejected(self) -> None:
        """Spaces are not allowed in agent IDs."""
        with pytest.raises(ValueError):
            validate_agent_id("my agent")

    def test_id_with_special_char_rejected(self) -> None:
        """Special characters like $ are rejected."""
        with pytest.raises(ValueError):
            validate_agent_id("agent$")
