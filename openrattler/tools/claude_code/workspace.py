"""WorkspaceManager — filesystem isolation layer for Claude Code subprocesses.

Responsibility:
- Create and manage the assistant's workspace directory tree.
- Create per-task git repos with isolated author identity and a pre-push hook
  that blocks any push to main.
- Render the CLAUDE.md soft fence into every new project.
- Validate that a path stays within the workspace root (structural check to
  complement the --add-dir CC flag).
- Produce the environment dict injected into every CC subprocess
  (CLAUDE_CONFIG_DIR isolation).

This module has no dependency on the approval system, subprocess manager, or
tool executor — it is pure file I/O and is tested without any of those layers.
"""

from __future__ import annotations

import logging
import os
import subprocess
from importlib.resources import files as _pkg_files
from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from openrattler.config.loader import CCConfig

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Pre-push hook script
# ---------------------------------------------------------------------------

# Written to .git/hooks/pre-push in every workspace project.
# Git for Windows executes hooks via its bundled bash, so a POSIX shebang works.
_PRE_PUSH_HOOK = """\
#!/bin/sh
# Installed by OpenRattler WorkspaceManager — do not remove.
# Blocks any push to main or master.
while read local_ref local_sha remote_ref remote_sha; do
    case "$remote_ref" in
        refs/heads/main|refs/heads/master)
            echo "ERROR: Pushing to main/master is blocked in this workspace."
            exit 1
            ;;
    esac
done
exit 0
"""


class WorkspaceManager:
    """Manages the assistant's isolated workspace for Claude Code sessions.

    All public methods are synchronous — workspace setup happens at startup
    and at task creation time, which runs before the async approval/subprocess
    flow begins.
    """

    def __init__(self, config: CCConfig) -> None:
        self._config = config
        self._workspace_root = Path(config.workspace_root)
        self._prefix = config.project_prefix
        self._git_author_name = config.git_author_name
        self._git_author_email = config.git_author_email

    # ------------------------------------------------------------------
    # Public interface
    # ------------------------------------------------------------------

    def ensure_workspace(self) -> None:
        """Create workspace_root/projects/ and workspace_root/.claude/ if absent.

        Safe to call multiple times — uses exist_ok=True throughout.
        """
        (self._workspace_root / "projects").mkdir(parents=True, exist_ok=True)
        (self._workspace_root / ".claude").mkdir(parents=True, exist_ok=True)
        logger.info("WorkspaceManager: workspace ready at %s", self._workspace_root)

    def create_project(self, name: str) -> Path:
        """Create a new isolated project directory for a CC task.

        Creates {workspace_root}/projects/{prefix}-{name}/, initialises a git
        repo with workspace-local author identity, and installs the pre-push
        hook that blocks pushes to main.

        Args:
            name: Short task name.  Combined with the project prefix.

        Returns:
            Absolute Path to the newly created project directory.
        """
        project_path = self._workspace_root / "projects" / f"{self._prefix}-{name}"
        project_path.mkdir(parents=True, exist_ok=True)

        self._init_git_repo(project_path)
        self._install_pre_push_hook(project_path)
        self.write_project_claude_md(project_path)

        logger.info("WorkspaceManager: project created at %s", project_path)
        return project_path

    def write_project_claude_md(self, project_path: Path) -> None:
        """Render the CLAUDE.md soft fence template into project_path/CLAUDE.md.

        Uses the package template at openrattler/templates/cc_workspace_claude_md.txt.
        """
        template = self._load_template()
        content = template.format(
            assistant_name=self._config.assistant_name,
            project_path=str(project_path),
            prefix=self._prefix,
            git_author_name=self._git_author_name,
            git_author_email=self._git_author_email,
        )
        (project_path / "CLAUDE.md").write_text(content, encoding="utf-8")

    def validate_path(self, path: Path) -> bool:
        """Return True only if *path* is within workspace_root.

        Resolves symlinks so that a symlink pointing outside the workspace
        is caught.  Does not require the path to exist.

        Args:
            path: The path to validate (may or may not exist).

        Returns:
            True if path is within workspace_root, False otherwise.
        """
        try:
            # resolve() follows symlinks for existing paths; for non-existent
            # paths we use the strict=False form which resolves as far as possible.
            resolved_path = path.resolve(strict=False)
            resolved_root = self._workspace_root.resolve(strict=False)
        except (OSError, ValueError):
            return False

        try:
            resolved_path.relative_to(resolved_root)
            return True
        except ValueError:
            return False

    def get_env(self, project_path: Path) -> dict[str, str]:
        """Return environment variables to inject into a CC subprocess.

        Includes:
        - CLAUDE_CONFIG_DIR: points to workspace .claude/ so CC sessions use
          the assistant's isolated config, not the human user's personal config.
        - GIT_AUTHOR_NAME / GIT_AUTHOR_EMAIL: belt-and-suspenders alongside
          the per-repo git config set in create_project().

        Args:
            project_path: The project directory (used for context; the config
                          dir is workspace-level, not project-level).

        Returns:
            Dict of env vars to merge with the subprocess environment.
        """
        return {
            "CLAUDE_CONFIG_DIR": str(self._workspace_root / ".claude"),
            "GIT_AUTHOR_NAME": self._git_author_name,
            "GIT_AUTHOR_EMAIL": self._git_author_email,
        }

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    def _init_git_repo(self, project_path: Path) -> None:
        """Initialise a git repo with workspace author identity.

        If a .git directory already exists, skips `git init` but still
        applies the local config so identity stays correct after a resume.
        """
        git_dir = project_path / ".git"
        if not git_dir.exists():
            result = subprocess.run(
                ["git", "init", str(project_path)],
                capture_output=True,
                text=True,
            )
            if result.returncode != 0:
                logger.warning(
                    "WorkspaceManager: git init failed at %s: %s",
                    project_path,
                    result.stderr,
                )

        # Set local git identity regardless of whether we just ran git init.
        for key, value in [
            ("user.name", self._git_author_name),
            ("user.email", self._git_author_email),
        ]:
            subprocess.run(
                ["git", "-C", str(project_path), "config", "--local", key, value],
                capture_output=True,
                text=True,
            )

    def _install_pre_push_hook(self, project_path: Path) -> None:
        """Write the pre-push hook script to .git/hooks/pre-push.

        On Windows, Git for Windows runs hooks via its bundled bash so a
        POSIX shebang is correct.  We also set the executable bit so that
        Unix-like environments pick it up without extra chmod.
        """
        hooks_dir = project_path / ".git" / "hooks"
        hooks_dir.mkdir(parents=True, exist_ok=True)

        hook_path = hooks_dir / "pre-push"
        hook_path.write_text(_PRE_PUSH_HOOK, encoding="utf-8")

        # Set executable bit (no-op on Windows NTFS, meaningful on WSL/Linux).
        try:
            hook_path.chmod(0o755)
        except OSError:
            pass

    def _load_template(self) -> str:
        """Load cc_workspace_claude_md.txt from the package templates directory."""
        # __file__ is openrattler/tools/claude_code/workspace.py
        # .parent.parent = openrattler/
        template_path = Path(__file__).parent.parent / "templates" / "cc_workspace_claude_md.txt"
        if template_path.exists():
            return template_path.read_text(encoding="utf-8")

        # Fallback: try importlib.resources for installed package layout.
        try:
            resource = _pkg_files("openrattler.templates").joinpath("cc_workspace_claude_md.txt")
            return resource.read_text(encoding="utf-8")
        except Exception:
            pass

        # Last resort: inline minimal template so workspace is still functional.
        logger.warning(
            "WorkspaceManager: cc_workspace_claude_md.txt not found; using minimal fallback"
        )
        return (
            "# Workspace Rules for {assistant_name}\n\n"
            "Branch prefix: {prefix}/\n"
            "Never push to main.\n"
        )
