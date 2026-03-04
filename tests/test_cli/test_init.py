"""Tests for workspace initialisation and session listing (cli/main.py)."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from openrattler.cli.main import init_workspace, list_sessions

# ---------------------------------------------------------------------------
# init_workspace
# ---------------------------------------------------------------------------


def test_init_creates_workspace_root(tmp_path: Path) -> None:
    ws = tmp_path / "ws"
    init_workspace(ws)
    assert ws.is_dir()


def test_init_creates_subdirectories(tmp_path: Path) -> None:
    ws = tmp_path / "ws"
    init_workspace(ws)
    for subdir in ("sessions", "memory", "audit"):
        assert (ws / subdir).is_dir(), f"missing subdir: {subdir}"


def test_init_creates_default_config(tmp_path: Path) -> None:
    ws = tmp_path / "ws"
    init_workspace(ws)
    config_path = ws / "config.json"
    assert config_path.is_file()
    # Must be valid JSON
    data = json.loads(config_path.read_text())
    assert isinstance(data, dict)


def test_init_idempotent(tmp_path: Path) -> None:
    ws = tmp_path / "ws"
    init_workspace(ws)
    # Second call must not raise or overwrite config
    config_path = ws / "config.json"
    first_mtime = config_path.stat().st_mtime
    init_workspace(ws)
    assert config_path.stat().st_mtime == first_mtime


def test_init_prints_workspace_ready(tmp_path: Path, capsys: pytest.CaptureFixture) -> None:  # type: ignore[type-arg]
    ws = tmp_path / "ws"
    init_workspace(ws)
    out = capsys.readouterr().out
    assert "Workspace ready" in out


def test_init_prints_config_created_first_time(
    tmp_path: Path, capsys: pytest.CaptureFixture  # type: ignore[type-arg]
) -> None:
    ws = tmp_path / "ws"
    init_workspace(ws)
    out = capsys.readouterr().out
    assert "Created default config" in out


def test_init_prints_config_exists_second_time(
    tmp_path: Path, capsys: pytest.CaptureFixture  # type: ignore[type-arg]
) -> None:
    ws = tmp_path / "ws"
    init_workspace(ws)
    capsys.readouterr()  # discard first-run output
    init_workspace(ws)
    out = capsys.readouterr().out
    assert "Config already exists" in out


def test_init_nested_workspace(tmp_path: Path) -> None:
    ws = tmp_path / "a" / "b" / "ws"
    init_workspace(ws)
    assert ws.is_dir()


# ---------------------------------------------------------------------------
# list_sessions
# ---------------------------------------------------------------------------


def test_list_sessions_empty_when_no_dir(tmp_path: Path) -> None:
    ws = tmp_path / "ws"
    # workspace exists but has no sessions/ subdir
    ws.mkdir()
    assert list_sessions(ws) == []


def test_list_sessions_empty_when_no_files(tmp_path: Path) -> None:
    ws = tmp_path / "ws"
    (ws / "sessions").mkdir(parents=True)
    assert list_sessions(ws) == []


def test_list_sessions_single_file(tmp_path: Path) -> None:
    ws = tmp_path / "ws"
    session_dir = ws / "sessions" / "agent" / "main"
    session_dir.mkdir(parents=True)
    (session_dir / "main.jsonl").write_text("")
    keys = list_sessions(ws)
    assert keys == ["agent:main:main"]


def test_list_sessions_multiple_files_sorted(tmp_path: Path) -> None:
    ws = tmp_path / "ws"
    for parts in [
        ("agent", "main", "main"),
        ("agent", "telegram", "u123"),
        ("agent", "cli", "alice"),
    ]:
        d = ws / "sessions" / Path(*parts[:-1])
        d.mkdir(parents=True, exist_ok=True)
        (d / f"{parts[-1]}.jsonl").write_text("")

    keys = list_sessions(ws)
    assert keys == sorted(keys)
    assert len(keys) == 3
    assert "agent:main:main" in keys
    assert "agent:telegram:u123" in keys
    assert "agent:cli:alice" in keys


def test_list_sessions_ignores_non_jsonl(tmp_path: Path) -> None:
    ws = tmp_path / "ws"
    d = ws / "sessions" / "agent" / "main"
    d.mkdir(parents=True)
    (d / "main.jsonl").write_text("")
    (d / "notes.txt").write_text("")
    keys = list_sessions(ws)
    assert keys == ["agent:main:main"]
