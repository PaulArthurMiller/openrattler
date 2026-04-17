"""Tests for WorkspaceManager (piece 40.1).

All tests use tmp_path so no real workspace directories are created on disk
outside of pytest's temporary directory.
"""

from __future__ import annotations

import stat
import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from openrattler.config.loader import CCConfig
from openrattler.tools.claude_code.workspace import WorkspaceManager

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_config(tmp_path: Path, **overrides) -> CCConfig:
    """Return a CCConfig pointed at tmp_path with sensible test defaults."""
    defaults = dict(
        enabled=True,
        workspace_root=str(tmp_path),
        assistant_name="TestBot",
        project_prefix="tb",
        git_author_name="TestBot (CC)",
        git_author_email="testbot@local",
    )
    defaults.update(overrides)
    return CCConfig(**defaults)


# ---------------------------------------------------------------------------
# ensure_workspace
# ---------------------------------------------------------------------------


def test_ensure_workspace_creates_projects_and_claude_dirs(tmp_path: Path) -> None:
    cfg = _make_config(tmp_path)
    mgr = WorkspaceManager(cfg)
    mgr.ensure_workspace()

    assert (tmp_path / "projects").is_dir()
    assert (tmp_path / ".claude").is_dir()


def test_ensure_workspace_is_idempotent(tmp_path: Path) -> None:
    cfg = _make_config(tmp_path)
    mgr = WorkspaceManager(cfg)
    mgr.ensure_workspace()
    mgr.ensure_workspace()  # second call must not raise

    assert (tmp_path / "projects").is_dir()
    assert (tmp_path / ".claude").is_dir()


# ---------------------------------------------------------------------------
# create_project
# ---------------------------------------------------------------------------


def test_create_project_produces_correct_path(tmp_path: Path) -> None:
    cfg = _make_config(tmp_path)
    mgr = WorkspaceManager(cfg)

    project_path = mgr.create_project("auth-fix")

    expected = tmp_path / "projects" / "tb-auth-fix"
    assert project_path == expected
    assert project_path.is_dir()


def test_create_project_writes_claude_md(tmp_path: Path) -> None:
    cfg = _make_config(tmp_path)
    mgr = WorkspaceManager(cfg)

    project_path = mgr.create_project("auth-fix")

    claude_md = project_path / "CLAUDE.md"
    assert claude_md.exists()
    content = claude_md.read_text(encoding="utf-8")
    # Prefix should appear in branch convention section.
    assert "tb/" in content


def test_create_project_installs_pre_push_hook(tmp_path: Path) -> None:
    cfg = _make_config(tmp_path)
    mgr = WorkspaceManager(cfg)

    project_path = mgr.create_project("hook-test")

    hook = project_path / ".git" / "hooks" / "pre-push"
    assert hook.exists(), "pre-push hook file must be written"
    hook_text = hook.read_text(encoding="utf-8")
    # Hook must block pushes to main.
    assert "main" in hook_text


@pytest.mark.skipif(sys.platform == "win32", reason="chmod not meaningful on NTFS")
def test_pre_push_hook_is_executable(tmp_path: Path) -> None:
    cfg = _make_config(tmp_path)
    mgr = WorkspaceManager(cfg)

    project_path = mgr.create_project("exec-test")

    hook = project_path / ".git" / "hooks" / "pre-push"
    mode = hook.stat().st_mode
    assert mode & stat.S_IXUSR, "pre-push hook must have owner execute bit set"


def test_create_project_is_idempotent(tmp_path: Path) -> None:
    """Second create_project call for the same name must not raise."""
    cfg = _make_config(tmp_path)
    mgr = WorkspaceManager(cfg)

    p1 = mgr.create_project("same-name")
    p2 = mgr.create_project("same-name")

    assert p1 == p2
    assert p1.is_dir()


# ---------------------------------------------------------------------------
# validate_path
# ---------------------------------------------------------------------------


def test_validate_path_accepts_path_inside_workspace(tmp_path: Path) -> None:
    cfg = _make_config(tmp_path)
    mgr = WorkspaceManager(cfg)

    inner = tmp_path / "projects" / "tb-task" / "src" / "main.py"
    assert mgr.validate_path(inner) is True


def test_validate_path_accepts_workspace_root_itself(tmp_path: Path) -> None:
    cfg = _make_config(tmp_path)
    mgr = WorkspaceManager(cfg)

    assert mgr.validate_path(tmp_path) is True


def test_validate_path_rejects_path_above_workspace(tmp_path: Path) -> None:
    cfg = _make_config(tmp_path)
    mgr = WorkspaceManager(cfg)

    outside = tmp_path.parent / "other-user" / "secret.txt"
    assert mgr.validate_path(outside) is False


def test_validate_path_rejects_traversal_attempt(tmp_path: Path) -> None:
    cfg = _make_config(tmp_path)
    mgr = WorkspaceManager(cfg)

    # Construct a path that starts inside but traverses out.
    traversal = tmp_path / "projects" / ".." / ".." / "etc" / "passwd"
    assert mgr.validate_path(traversal) is False


def test_validate_path_rejects_sibling_workspace(tmp_path: Path) -> None:
    """A path that starts with the same prefix but is a sibling must be rejected."""
    cfg = _make_config(tmp_path)
    mgr = WorkspaceManager(cfg)

    # e.g. /tmp/pytest-xxx/test_0 and /tmp/pytest-xxx/test_0extra
    sibling = tmp_path.parent / (tmp_path.name + "extra") / "file.py"
    assert mgr.validate_path(sibling) is False


# ---------------------------------------------------------------------------
# get_env
# ---------------------------------------------------------------------------


def test_get_env_returns_claude_config_dir(tmp_path: Path) -> None:
    cfg = _make_config(tmp_path)
    mgr = WorkspaceManager(cfg)

    project_path = tmp_path / "projects" / "tb-task"
    env = mgr.get_env(project_path)

    expected_config_dir = str(tmp_path / ".claude")
    assert "CLAUDE_CONFIG_DIR" in env
    assert env["CLAUDE_CONFIG_DIR"] == expected_config_dir


def test_get_env_returns_git_identity(tmp_path: Path) -> None:
    cfg = _make_config(tmp_path)
    mgr = WorkspaceManager(cfg)

    env = mgr.get_env(tmp_path / "projects" / "tb-task")

    assert env["GIT_AUTHOR_NAME"] == "TestBot (CC)"
    assert env["GIT_AUTHOR_EMAIL"] == "testbot@local"


def test_get_env_config_dir_points_to_workspace_not_project(tmp_path: Path) -> None:
    """CLAUDE_CONFIG_DIR must be workspace-level, not project-level."""
    cfg = _make_config(tmp_path)
    mgr = WorkspaceManager(cfg)

    project_path = tmp_path / "projects" / "tb-task"
    env = mgr.get_env(project_path)

    # Must be workspace .claude, not the project .claude.
    assert env["CLAUDE_CONFIG_DIR"] == str(tmp_path / ".claude")
    assert "projects" not in env["CLAUDE_CONFIG_DIR"]


# ---------------------------------------------------------------------------
# CCConfig validation
# ---------------------------------------------------------------------------


def test_ccconfig_rejects_relative_workspace_root() -> None:
    with pytest.raises(Exception, match="absolute"):
        CCConfig(
            enabled=True,
            workspace_root="relative/path",
        )


def test_ccconfig_allows_empty_workspace_root_when_disabled() -> None:
    cfg = CCConfig(enabled=False, workspace_root="")
    assert cfg.workspace_root == ""


def test_ccconfig_accepts_absolute_workspace_root(tmp_path: Path) -> None:
    cfg = CCConfig(enabled=True, workspace_root=str(tmp_path))
    assert cfg.workspace_root == str(tmp_path)


# ---------------------------------------------------------------------------
# write_project_claude_md
# ---------------------------------------------------------------------------


def test_write_project_claude_md_substitutes_prefix(tmp_path: Path) -> None:
    cfg = _make_config(tmp_path, project_prefix="cv")
    mgr = WorkspaceManager(cfg)

    project_path = tmp_path / "projects" / "cv-task"
    project_path.mkdir(parents=True)
    mgr.write_project_claude_md(project_path)

    content = (project_path / "CLAUDE.md").read_text(encoding="utf-8")
    assert "cv/" in content


def test_write_project_claude_md_substitutes_assistant_name(tmp_path: Path) -> None:
    cfg = _make_config(tmp_path, assistant_name="Corvus")
    mgr = WorkspaceManager(cfg)

    project_path = tmp_path / "projects" / "cv-task"
    project_path.mkdir(parents=True)
    mgr.write_project_claude_md(project_path)

    content = (project_path / "CLAUDE.md").read_text(encoding="utf-8")
    assert "Corvus" in content
