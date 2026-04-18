"""Tests for CCSubprocessManager and CCOutputParser (piece 40.3).

All subprocess tests mock at the ``asyncio.create_subprocess_exec`` boundary
so no real Claude Code binary is required.
"""

from __future__ import annotations

import asyncio
import json
from pathlib import Path
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from openrattler.config.loader import CCConfig
from openrattler.security.action_levels import DeadStopError
from openrattler.tools.claude_code.output_parser import CCOutputParser, CCParsedOutput
from openrattler.tools.claude_code.subprocess_mgr import CCResult, CCSubprocessManager

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_PROJECT_PATH = Path("C:/fake/workspace/or-test-project")

_VALID_ENV: dict[str, str] = {
    "CLAUDE_CONFIG_DIR": "C:/fake/workspace/.claude",
    "GIT_AUTHOR_NAME": "Test Assistant",
    "GIT_AUTHOR_EMAIL": "test@local",
}


def _make_config(**overrides: Any) -> CCConfig:
    defaults: dict[str, Any] = dict(
        enabled=True,
        workspace_root="C:/fake/workspace",
        assistant_name="TestBot",
        project_prefix="tb",
        git_author_name="TestBot (Claude Code)",
        git_author_email="testbot@local",
        max_concurrent_sessions=2,
        session_timeout_seconds=30,
        claude_binary="claude",
    )
    defaults.update(overrides)
    return CCConfig(**defaults)


def _make_mock_process(
    stdout: bytes = b"",
    returncode: int = 0,
) -> MagicMock:
    """Return a mock that looks like asyncio.subprocess.Process."""
    proc = MagicMock()
    proc.returncode = returncode
    proc.communicate = AsyncMock(return_value=(stdout, b""))
    proc.kill = MagicMock()
    return proc


# ---------------------------------------------------------------------------
# CCSubprocessManager._validate_args
# ---------------------------------------------------------------------------


class TestValidateArgs:
    def test_clean_argv_passes(self) -> None:
        mgr = CCSubprocessManager(_make_config())
        mgr._validate_args(
            ["claude", "-p", "do something", "--output-format", "json"]
        )  # must not raise

    def test_dangerously_skip_permissions_raises_dead_stop(self) -> None:
        mgr = CCSubprocessManager(_make_config())
        with pytest.raises(DeadStopError) as exc_info:
            mgr._validate_args(["claude", "-p", "task", "--dangerously-skip-permissions"])
        assert exc_info.value.action == "cc_bypass_permissions"

    def test_no_permissions_raises_dead_stop(self) -> None:
        mgr = CCSubprocessManager(_make_config())
        with pytest.raises(DeadStopError):
            mgr._validate_args(["claude", "--no-permissions", "-p", "task"])

    def test_permission_mode_bypass_raises_dead_stop(self) -> None:
        mgr = CCSubprocessManager(_make_config())
        with pytest.raises(DeadStopError) as exc_info:
            mgr._validate_args(["claude", "-p", "task", "--permission-mode", "bypass"])
        assert exc_info.value.action == "cc_bypass_permissions"

    def test_permission_mode_non_bypass_passes(self) -> None:
        mgr = CCSubprocessManager(_make_config())
        mgr._validate_args(
            ["claude", "-p", "task", "--permission-mode", "default"]
        )  # must not raise

    def test_forbidden_flag_embedded_in_larger_argv_is_caught(self) -> None:
        mgr = CCSubprocessManager(_make_config())
        with pytest.raises(DeadStopError):
            mgr._validate_args(
                [
                    "claude",
                    "-p",
                    "do work",
                    "--output-format",
                    "json",
                    "--dangerously-skip-permissions",
                    "--allowedTools",
                    "Read",
                ]
            )


# ---------------------------------------------------------------------------
# CCSubprocessManager._build_argv
# ---------------------------------------------------------------------------


class TestBuildArgv:
    def test_argv_starts_with_configured_binary(self) -> None:
        mgr = CCSubprocessManager(_make_config(claude_binary="claude"))
        argv = mgr._build_argv("fix the bug", _PROJECT_PATH, ["Read", "Write"])
        assert argv[0] == "claude"

    def test_argv_contains_p_flag_with_task(self) -> None:
        mgr = CCSubprocessManager(_make_config())
        argv = mgr._build_argv("fix the bug", _PROJECT_PATH, ["Read"])
        assert "-p" in argv
        assert "fix the bug" in argv

    def test_argv_contains_output_format_json(self) -> None:
        mgr = CCSubprocessManager(_make_config())
        argv = mgr._build_argv("task", _PROJECT_PATH, ["Read"])
        assert "--output-format" in argv
        idx = argv.index("--output-format")
        assert argv[idx + 1] == "json"

    def test_argv_contains_allowed_tools_joined(self) -> None:
        mgr = CCSubprocessManager(_make_config())
        argv = mgr._build_argv("task", _PROJECT_PATH, ["Read", "Glob", "Grep"])
        assert "--allowedTools" in argv
        idx = argv.index("--allowedTools")
        assert argv[idx + 1] == "Read,Glob,Grep"

    def test_argv_contains_add_dir_with_project_path(self) -> None:
        mgr = CCSubprocessManager(_make_config())
        argv = mgr._build_argv("task", _PROJECT_PATH, ["Read"])
        assert "--add-dir" in argv
        idx = argv.index("--add-dir")
        assert argv[idx + 1] == str(_PROJECT_PATH)

    def test_custom_binary_used_in_argv(self) -> None:
        mgr = CCSubprocessManager(_make_config(claude_binary="/usr/local/bin/claude"))
        argv = mgr._build_argv("task", _PROJECT_PATH, ["Read"])
        assert argv[0] == "/usr/local/bin/claude"


# ---------------------------------------------------------------------------
# CCSubprocessManager.spawn — session limit
# ---------------------------------------------------------------------------


class TestSpawnSessionLimit:
    async def test_spawn_within_limit_succeeds(self) -> None:
        mgr = CCSubprocessManager(_make_config(max_concurrent_sessions=2))
        stdout_json = json.dumps({"result": "done", "is_error": False}).encode()
        mock_proc = _make_mock_process(stdout=stdout_json, returncode=0)

        with patch(
            "openrattler.tools.claude_code.subprocess_mgr.asyncio.create_subprocess_exec",
            new=AsyncMock(return_value=mock_proc),
        ):
            result = await mgr.spawn("task", _PROJECT_PATH, ["Read"], _VALID_ENV)

        assert result.error is None
        assert result.returncode == 0

    async def test_spawn_at_limit_returns_error_immediately(self) -> None:
        mgr = CCSubprocessManager(_make_config(max_concurrent_sessions=1))
        # Pre-fill the active sessions dict to simulate a running session.
        mgr._active_sessions["fake-session-id"] = MagicMock()

        result = await mgr.spawn("task", _PROJECT_PATH, ["Read"], _VALID_ENV)

        assert result.error is not None
        assert "limit" in result.error.lower()

    async def test_spawn_third_when_limit_is_two_returns_error(self) -> None:
        mgr = CCSubprocessManager(_make_config(max_concurrent_sessions=2))
        mgr._active_sessions["s1"] = MagicMock()
        mgr._active_sessions["s2"] = MagicMock()

        result = await mgr.spawn("task", _PROJECT_PATH, ["Read"], _VALID_ENV)

        assert result.error is not None

    async def test_session_removed_from_active_after_completion(self) -> None:
        mgr = CCSubprocessManager(_make_config())
        stdout_json = json.dumps({"result": "done", "is_error": False}).encode()
        mock_proc = _make_mock_process(stdout=stdout_json, returncode=0)

        with patch(
            "openrattler.tools.claude_code.subprocess_mgr.asyncio.create_subprocess_exec",
            new=AsyncMock(return_value=mock_proc),
        ):
            await mgr.spawn("task", _PROJECT_PATH, ["Read"], _VALID_ENV)

        assert len(mgr._active_sessions) == 0


# ---------------------------------------------------------------------------
# CCSubprocessManager.spawn — timeout
# ---------------------------------------------------------------------------


def _make_timeout_proc() -> MagicMock:
    """Return a mock process whose communicate() returns immediately (used in timeout tests).

    The real timeout is simulated by patching asyncio.wait_for to raise
    TimeoutError directly.  The communicate mock must return quickly so the
    cleanup path (``await process.communicate()`` after kill) doesn't hang.
    """
    proc = MagicMock()
    proc.returncode = None
    proc.kill = MagicMock()
    proc.communicate = AsyncMock(return_value=(b"", b""))
    return proc


class TestSpawnTimeout:
    async def test_timeout_returns_error_result(self) -> None:
        mgr = CCSubprocessManager(_make_config(session_timeout_seconds=10))
        slow_proc = _make_timeout_proc()

        with patch(
            "openrattler.tools.claude_code.subprocess_mgr.asyncio.create_subprocess_exec",
            new=AsyncMock(return_value=slow_proc),
        ):
            with patch(
                "openrattler.tools.claude_code.subprocess_mgr.asyncio.wait_for",
                side_effect=asyncio.TimeoutError,
            ):
                result = await mgr.spawn("slow task", _PROJECT_PATH, ["Read"], _VALID_ENV)

        assert result.error is not None
        assert "timed out" in result.error.lower()

    async def test_timeout_kills_process(self) -> None:
        mgr = CCSubprocessManager(_make_config(session_timeout_seconds=10))
        slow_proc = _make_timeout_proc()

        with patch(
            "openrattler.tools.claude_code.subprocess_mgr.asyncio.create_subprocess_exec",
            new=AsyncMock(return_value=slow_proc),
        ):
            with patch(
                "openrattler.tools.claude_code.subprocess_mgr.asyncio.wait_for",
                side_effect=asyncio.TimeoutError,
            ):
                await mgr.spawn("slow task", _PROJECT_PATH, ["Read"], _VALID_ENV)

        slow_proc.kill.assert_called_once()

    async def test_timeout_session_removed_from_active(self) -> None:
        mgr = CCSubprocessManager(_make_config(session_timeout_seconds=10))
        slow_proc = _make_timeout_proc()

        with patch(
            "openrattler.tools.claude_code.subprocess_mgr.asyncio.create_subprocess_exec",
            new=AsyncMock(return_value=slow_proc),
        ):
            with patch(
                "openrattler.tools.claude_code.subprocess_mgr.asyncio.wait_for",
                side_effect=asyncio.TimeoutError,
            ):
                await mgr.spawn("slow task", _PROJECT_PATH, ["Read"], _VALID_ENV)

        assert len(mgr._active_sessions) == 0


# ---------------------------------------------------------------------------
# CCSubprocessManager.spawn — forbidden flag raises DeadStopError
# ---------------------------------------------------------------------------


class TestSpawnDeadStop:
    async def test_forbidden_flag_in_binary_name_raises_dead_stop(self) -> None:
        """_validate_args fires before create_subprocess_exec is ever called."""
        mgr = CCSubprocessManager(_make_config())

        with patch(
            "openrattler.tools.claude_code.subprocess_mgr.asyncio.create_subprocess_exec",
            new=AsyncMock(),
        ) as mock_exec:
            # Patch _validate_args to raise directly (simulates forbidden flag in argv).
            with patch.object(
                mgr,
                "_validate_args",
                side_effect=DeadStopError("cc_bypass_permissions"),
            ):
                with pytest.raises(DeadStopError) as exc_info:
                    await mgr.spawn("task", _PROJECT_PATH, ["Read"], _VALID_ENV)

            mock_exec.assert_not_called()

        assert exc_info.value.action == "cc_bypass_permissions"


# ---------------------------------------------------------------------------
# CCSubprocessManager.spawn — binary not found
# ---------------------------------------------------------------------------


class TestSpawnBinaryNotFound:
    async def test_missing_binary_returns_error_result(self) -> None:
        mgr = CCSubprocessManager(_make_config(claude_binary="nonexistent-binary"))

        with patch(
            "openrattler.tools.claude_code.subprocess_mgr.asyncio.create_subprocess_exec",
            side_effect=FileNotFoundError("no such file"),
        ):
            result = await mgr.spawn("task", _PROJECT_PATH, ["Read"], _VALID_ENV)

        assert result.error is not None
        assert "nonexistent-binary" in result.error


# ---------------------------------------------------------------------------
# CCSubprocessManager.kill_all
# ---------------------------------------------------------------------------


class TestKillAll:
    async def test_kill_all_kills_all_tracked_processes(self) -> None:
        mgr = CCSubprocessManager(_make_config())
        proc1 = MagicMock()
        proc1.kill = MagicMock()
        proc1.communicate = AsyncMock(return_value=(b"", b""))
        proc2 = MagicMock()
        proc2.kill = MagicMock()
        proc2.communicate = AsyncMock(return_value=(b"", b""))

        mgr._active_sessions["s1"] = proc1
        mgr._active_sessions["s2"] = proc2

        await mgr.kill_all()

        proc1.kill.assert_called_once()
        proc2.kill.assert_called_once()

    async def test_kill_all_clears_active_sessions(self) -> None:
        mgr = CCSubprocessManager(_make_config())
        proc = MagicMock()
        proc.kill = MagicMock()
        proc.communicate = AsyncMock(return_value=(b"", b""))
        mgr._active_sessions["s1"] = proc

        await mgr.kill_all()

        assert len(mgr._active_sessions) == 0

    async def test_kill_all_no_op_when_no_active_sessions(self) -> None:
        mgr = CCSubprocessManager(_make_config())
        await mgr.kill_all()  # must not raise


# ---------------------------------------------------------------------------
# CCOutputParser.parse
# ---------------------------------------------------------------------------


class TestCCOutputParser:
    def test_parses_full_success_output(self) -> None:
        parser = CCOutputParser()
        raw = json.dumps(
            {
                "type": "result",
                "subtype": "success",
                "result": "All done.",
                "session_id": "abc123",
                "cost_usd": 0.0042,
                "num_turns": 3,
                "is_error": False,
            }
        )
        parsed = parser.parse(raw)
        assert parsed.result == "All done."
        assert parsed.session_id == "abc123"
        assert parsed.cost_usd == pytest.approx(0.0042)
        assert parsed.num_turns == 3
        assert parsed.is_error is False
        assert parsed.error is None

    def test_parses_output_missing_cost_usd(self) -> None:
        parser = CCOutputParser()
        raw = json.dumps({"result": "done", "is_error": False})
        parsed = parser.parse(raw)
        assert parsed.cost_usd is None
        assert parsed.error is None

    def test_parses_output_missing_session_id(self) -> None:
        parser = CCOutputParser()
        raw = json.dumps({"result": "done", "is_error": False})
        parsed = parser.parse(raw)
        assert parsed.session_id is None

    def test_parses_output_missing_num_turns(self) -> None:
        parser = CCOutputParser()
        raw = json.dumps({"result": "done", "is_error": False})
        parsed = parser.parse(raw)
        assert parsed.num_turns is None

    def test_is_error_true_sets_error_field(self) -> None:
        parser = CCOutputParser()
        raw = json.dumps({"result": "Something went wrong.", "is_error": True})
        parsed = parser.parse(raw)
        assert parsed.is_error is True
        assert parsed.error is not None
        assert "Something went wrong." in parsed.error

    def test_is_error_true_with_empty_result_uses_fallback_message(self) -> None:
        parser = CCOutputParser()
        raw = json.dumps({"result": "", "is_error": True})
        parsed = parser.parse(raw)
        assert parsed.error is not None
        assert len(parsed.error) > 0

    def test_empty_string_returns_error(self) -> None:
        parser = CCOutputParser()
        parsed = parser.parse("")
        assert parsed.error is not None
        assert parsed.result == ""

    def test_whitespace_only_returns_error(self) -> None:
        parser = CCOutputParser()
        parsed = parser.parse("   \n  ")
        assert parsed.error is not None

    def test_invalid_json_returns_error(self) -> None:
        parser = CCOutputParser()
        parsed = parser.parse("this is not json {")
        assert parsed.error is not None
        assert "JSON" in parsed.error or "json" in parsed.error.lower()

    def test_unknown_fields_are_ignored(self) -> None:
        parser = CCOutputParser()
        raw = json.dumps(
            {
                "result": "ok",
                "is_error": False,
                "future_field": "some_value",
                "another_unknown": 42,
            }
        )
        parsed = parser.parse(raw)
        assert parsed.result == "ok"
        assert parsed.error is None

    def test_raw_string_preserved_in_output(self) -> None:
        parser = CCOutputParser()
        raw = json.dumps({"result": "hi", "is_error": False})
        parsed = parser.parse(raw)
        assert parsed.raw == raw

    def test_cost_usd_zero_is_not_treated_as_missing(self) -> None:
        parser = CCOutputParser()
        raw = json.dumps({"result": "ok", "is_error": False, "cost_usd": 0.0})
        parsed = parser.parse(raw)
        assert parsed.cost_usd == pytest.approx(0.0)

    def test_returns_ccparsedoutput_instance(self) -> None:
        parser = CCOutputParser()
        raw = json.dumps({"result": "done", "is_error": False})
        parsed = parser.parse(raw)
        assert isinstance(parsed, CCParsedOutput)
