"""CCSubprocessManager — spawn, monitor, and kill Claude Code subprocesses.

Responsibility:
- Build the CC argv (binary + task flags + path fence).
- Validate args for forbidden flags before any process is started.
- Enforce the concurrent-session limit.
- Await process stdout with a configurable timeout; kill on timeout.
- Track and clean up active sessions.
- Provide ``kill_all()`` for graceful shutdown.

This module has no dependency on the approval system or tool registry —
it is a pure process-management layer.  Tests mock at the
``asyncio.create_subprocess_exec`` boundary so no real CC binary is needed.

Security notes:
- CC is always spawned with ``asyncio.create_subprocess_exec`` (never
  ``shell=True``), so the argv is passed directly to the OS without shell
  interpolation.  This prevents shell-injection via task text.
- ``_validate_args`` scans for forbidden flags before spawn.  This is
  defense-in-depth alongside the ``cc_bypass_permissions`` dead stop; both
  must independently block permission bypasses.
- ``CLAUDE_CONFIG_DIR`` and git identity env vars are injected via
  ``WorkspaceManager.get_env()`` so CC uses the isolated workspace config,
  not the human user's ``~/.claude``.
"""

from __future__ import annotations

import asyncio
import logging
import os
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING, Optional
from uuid import uuid4

from openrattler.security.action_levels import DeadStopError

if TYPE_CHECKING:
    from openrattler.config.loader import CCConfig

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Forbidden subprocess flags
# ---------------------------------------------------------------------------

#: Flags that must never appear in a CC argv.  If found, ``_validate_args``
#: raises ``DeadStopError("cc_bypass_permissions")`` before any process starts.
#: This is the subprocess-level structural check (defense in depth alongside
#: the tool-level dead stop in DEAD_STOP_ACTIONS).
_FORBIDDEN_FLAGS: frozenset[str] = frozenset(
    {
        "--dangerously-skip-permissions",
        "--no-permissions",
    }
)

#: Forbidden flag *values* — these appear as two-token sequences in argv.
#: E.g. ``["--permission-mode", "bypass"]``.
_FORBIDDEN_FLAG_VALUES: dict[str, frozenset[str]] = {
    "--permission-mode": frozenset({"bypass"}),
}

# ---------------------------------------------------------------------------
# CCResult
# ---------------------------------------------------------------------------


@dataclass
class CCResult:
    """Raw output from a single CC subprocess invocation.

    Attributes:
        stdout:     Captured stdout (CC's JSON output on success).
        returncode: Process exit code; 0 = clean exit.
        session_id: UUID assigned to this invocation by the manager.
        error:      Manager-level error (timeout, limit); None on clean exit.
    """

    stdout: str = ""
    returncode: int = 0
    session_id: str = field(default_factory=lambda: uuid4().hex)
    error: Optional[str] = None


# ---------------------------------------------------------------------------
# CCSubprocessManager
# ---------------------------------------------------------------------------


class CCSubprocessManager:
    """Spawn and manage Claude Code subprocesses within the session limit.

    Args:
        config: The ``CCConfig`` section of the loaded ``AppConfig``.

    Security notes:
    - Args are built as ``list[str]`` and passed to ``create_subprocess_exec``
      — never interpolated into a shell string.
    - ``_validate_args`` rejects forbidden permission-bypass flags before spawn.
    - Session UUIDs are generated per-invocation for audit correlation.
    - On Windows, ``Process.kill()`` calls ``TerminateProcess`` — equivalent
      to SIGKILL.  No platform-specific handling is needed.
    """

    def __init__(self, config: "CCConfig") -> None:
        self._config = config
        # Maps session_id → running asyncio.subprocess.Process.
        self._active_sessions: dict[str, asyncio.subprocess.Process] = {}

    # ------------------------------------------------------------------
    # Arg validation
    # ------------------------------------------------------------------

    def _validate_args(self, args: list[str]) -> None:
        """Scan *args* for forbidden flags and raise if found.

        Checks both standalone forbidden flags and forbidden ``--flag value``
        pairs.  Raises ``DeadStopError("cc_bypass_permissions")`` on any match
        so the dead-stop audit path fires before a process is ever created.

        Args:
            args: The full argv list that would be passed to the subprocess.

        Raises:
            DeadStopError: If any forbidden flag or flag/value pair is found.
        """
        for arg in args:
            if arg in _FORBIDDEN_FLAGS:
                logger.error(
                    "CCSubprocessManager: forbidden flag '%s' found in argv — dead stop", arg
                )
                raise DeadStopError("cc_bypass_permissions")

        # Check two-token flag/value pairs.
        for i, arg in enumerate(args[:-1]):
            forbidden_values = _FORBIDDEN_FLAG_VALUES.get(arg)
            if forbidden_values and args[i + 1] in forbidden_values:
                logger.error(
                    "CCSubprocessManager: forbidden flag pair '%s %s' found — dead stop",
                    arg,
                    args[i + 1],
                )
                raise DeadStopError("cc_bypass_permissions")

    # ------------------------------------------------------------------
    # Spawn
    # ------------------------------------------------------------------

    def _build_argv(
        self,
        task: str,
        project_path: Path,
        allowed_tools: list[str],
    ) -> list[str]:
        """Build the CC argv list for a subprocess invocation.

        Args:
            task:          Natural-language task description passed via ``-p``.
            project_path:  Absolute path to the workspace project directory.
            allowed_tools: CC tool names to pass via ``--allowedTools``.

        Returns:
            The full ``list[str]`` argv ready for ``create_subprocess_exec``.
        """
        return [
            self._config.claude_binary,
            "-p",
            task,
            "--output-format",
            "json",
            "--allowedTools",
            ",".join(allowed_tools),
            "--add-dir",
            str(project_path),
        ]

    async def spawn(
        self,
        task: str,
        project_path: Path,
        allowed_tools: list[str],
        env: dict[str, str],
    ) -> CCResult:
        """Spawn a CC subprocess and await its completion.

        Steps:
        1. Check the concurrent-session limit; return error immediately if at limit.
        2. Build argv and call ``_validate_args``.
        3. Merge *env* with the current process environment and spawn.
        4. Await stdout with ``session_timeout_seconds`` timeout.
        5. On timeout: kill the process, remove from ``_active_sessions``, return error.
        6. On success: return ``CCResult`` with captured stdout and returncode.

        Args:
            task:          Task description passed to CC via ``-p``.
            project_path:  Workspace project path; used as ``cwd`` and in ``--add-dir``.
            allowed_tools: CC tool names passed via ``--allowedTools``.
            env:           Environment variables to inject (merged with ``os.environ``).

        Returns:
            ``CCResult`` — never raises; errors are surfaced through ``CCResult.error``.
        """
        session_id = uuid4().hex

        # Enforce concurrent-session limit.
        if len(self._active_sessions) >= self._config.max_concurrent_sessions:
            logger.warning(
                "CCSubprocessManager: session limit reached (%d); rejecting new spawn",
                self._config.max_concurrent_sessions,
            )
            return CCResult(
                session_id=session_id,
                error=(
                    f"CC session limit reached "
                    f"({self._config.max_concurrent_sessions} concurrent session(s) max). "
                    "Wait for an active session to finish before starting a new one."
                ),
            )

        argv = self._build_argv(task, project_path, allowed_tools)

        try:
            self._validate_args(argv)
        except DeadStopError:
            # Re-raise so ToolExecutor's dead-stop path handles it.
            raise

        # Merge caller-supplied env on top of the current process environment.
        merged_env: dict[str, str] = {**os.environ, **env}

        logger.info(
            "CCSubprocessManager: spawning session %s — binary=%s project=%s tools=%s",
            session_id,
            self._config.claude_binary,
            project_path,
            allowed_tools,
        )

        try:
            process = await asyncio.create_subprocess_exec(
                *argv,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                cwd=str(project_path),
                env=merged_env,
            )
        except (FileNotFoundError, PermissionError) as exc:
            logger.error(
                "CCSubprocessManager: failed to start CC binary '%s': %s",
                self._config.claude_binary,
                exc,
            )
            return CCResult(
                session_id=session_id,
                error=f"Failed to start CC binary '{self._config.claude_binary}': {exc}",
            )

        self._active_sessions[session_id] = process

        try:
            stdout_bytes, _ = await asyncio.wait_for(
                process.communicate(),
                timeout=float(self._config.session_timeout_seconds),
            )
        except asyncio.TimeoutError:
            logger.warning(
                "CCSubprocessManager: session %s timed out after %ds — killing process",
                session_id,
                self._config.session_timeout_seconds,
            )
            process.kill()
            try:
                await process.communicate()
            except Exception:
                pass
            self._active_sessions.pop(session_id, None)
            return CCResult(
                session_id=session_id,
                error=(
                    f"CC session timed out after {self._config.session_timeout_seconds}s. "
                    "The process was killed."
                ),
            )

        self._active_sessions.pop(session_id, None)
        stdout = stdout_bytes.decode("utf-8", errors="replace")
        returncode = process.returncode if process.returncode is not None else -1

        logger.info(
            "CCSubprocessManager: session %s finished — returncode=%d stdout_len=%d",
            session_id,
            returncode,
            len(stdout),
        )

        return CCResult(
            stdout=stdout,
            returncode=returncode,
            session_id=session_id,
        )

    # ------------------------------------------------------------------
    # Shutdown
    # ------------------------------------------------------------------

    async def kill_all(self) -> None:
        """Kill all active CC subprocesses.

        Called during application shutdown to ensure no CC processes are
        orphaned.  Each process is killed and awaited sequentially; failures
        are logged but do not prevent the remaining processes from being killed.
        """
        session_ids = list(self._active_sessions.keys())
        if not session_ids:
            return

        logger.info(
            "CCSubprocessManager.kill_all: terminating %d active session(s)", len(session_ids)
        )

        for sid in session_ids:
            process = self._active_sessions.pop(sid, None)
            if process is None:
                continue
            try:
                process.kill()
                await process.communicate()
                logger.debug("CCSubprocessManager.kill_all: session %s terminated", sid)
            except Exception as exc:
                logger.error("CCSubprocessManager.kill_all: error killing session %s: %s", sid, exc)
