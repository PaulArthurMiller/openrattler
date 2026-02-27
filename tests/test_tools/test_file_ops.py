"""Tests for the built-in file operation tools."""

from __future__ import annotations

from pathlib import Path

import pytest

import openrattler.tools.builtin.file_ops as file_ops_module
from openrattler.tools.builtin.file_ops import (
    configure_allowed_directories,
    file_list,
    file_read,
    file_write,
)

# ---------------------------------------------------------------------------
# Fixture: reset module state after every test
# ---------------------------------------------------------------------------


@pytest.fixture(autouse=True)
def reset_file_ops_config():
    """Restore module-level state after each test so tests don't bleed."""
    yield
    configure_allowed_directories([])


# ---------------------------------------------------------------------------
# file_read
# ---------------------------------------------------------------------------


class TestFileRead:
    async def test_reads_file_correctly(self, tmp_path: Path) -> None:
        (tmp_path / "hello.txt").write_text("hello world", encoding="utf-8")
        configure_allowed_directories([tmp_path])
        result = await file_read(str(tmp_path / "hello.txt"))
        assert result == "hello world"

    async def test_reads_empty_file(self, tmp_path: Path) -> None:
        (tmp_path / "empty.txt").write_text("", encoding="utf-8")
        configure_allowed_directories([tmp_path])
        result = await file_read(str(tmp_path / "empty.txt"))
        assert result == ""

    async def test_rejects_dotdot_traversal(self, tmp_path: Path) -> None:
        configure_allowed_directories([tmp_path])
        bad_path = str(tmp_path / ".." / "secret.txt")
        with pytest.raises(ValueError, match="traversal"):
            await file_read(bad_path)

    async def test_rejects_explicit_dotdot_string(self, tmp_path: Path) -> None:
        configure_allowed_directories([tmp_path])
        with pytest.raises(ValueError, match="traversal"):
            await file_read("../../etc/passwd")

    async def test_rejects_path_outside_allowed_directory(self, tmp_path: Path) -> None:
        sub = tmp_path / "allowed"
        sub.mkdir()
        configure_allowed_directories([sub])
        # A file in tmp_path itself is outside the narrower allowed dir.
        (tmp_path / "outside.txt").write_text("x", encoding="utf-8")
        with pytest.raises(ValueError, match="outside all allowed"):
            await file_read(str(tmp_path / "outside.txt"))

    async def test_rejects_file_over_size_limit(self, tmp_path: Path) -> None:
        big = tmp_path / "big.txt"
        big.write_text("x" * 20, encoding="utf-8")
        configure_allowed_directories([tmp_path], max_file_size=10)
        with pytest.raises(ValueError, match="too large"):
            await file_read(str(big))

    async def test_raises_when_no_dirs_configured(self, tmp_path: Path) -> None:
        # No configure_allowed_directories call — default is empty.
        with pytest.raises(ValueError, match="No allowed directories"):
            await file_read(str(tmp_path / "any.txt"))

    async def test_multiple_allowed_dirs(self, tmp_path: Path) -> None:
        dir_a = tmp_path / "a"
        dir_b = tmp_path / "b"
        dir_a.mkdir()
        dir_b.mkdir()
        (dir_a / "fa.txt").write_text("from-a", encoding="utf-8")
        (dir_b / "fb.txt").write_text("from-b", encoding="utf-8")
        configure_allowed_directories([dir_a, dir_b])
        assert await file_read(str(dir_a / "fa.txt")) == "from-a"
        assert await file_read(str(dir_b / "fb.txt")) == "from-b"

    async def test_file_not_found_raises(self, tmp_path: Path) -> None:
        configure_allowed_directories([tmp_path])
        with pytest.raises((FileNotFoundError, OSError)):
            await file_read(str(tmp_path / "nonexistent.txt"))

    def test_tool_definition_attached(self) -> None:
        assert hasattr(file_read, "_tool_definition")
        assert file_read._tool_definition.name == "file_read"  # type: ignore[attr-defined]

    def test_tool_requires_no_approval(self) -> None:
        assert file_read._tool_definition.requires_approval is False  # type: ignore[attr-defined]


# ---------------------------------------------------------------------------
# file_write
# ---------------------------------------------------------------------------


class TestFileWrite:
    async def test_writes_file_correctly(self, tmp_path: Path) -> None:
        configure_allowed_directories([tmp_path])
        target = tmp_path / "out.txt"
        await file_write(str(target), "hello write")
        assert target.read_text(encoding="utf-8") == "hello write"

    async def test_result_contains_character_count(self, tmp_path: Path) -> None:
        configure_allowed_directories([tmp_path])
        result = await file_write(str(tmp_path / "f.txt"), "abc")
        assert "3" in result

    async def test_creates_parent_directories(self, tmp_path: Path) -> None:
        configure_allowed_directories([tmp_path])
        deep = tmp_path / "sub" / "dir" / "file.txt"
        await file_write(str(deep), "nested")
        assert deep.read_text(encoding="utf-8") == "nested"

    async def test_overwrites_existing_file(self, tmp_path: Path) -> None:
        configure_allowed_directories([tmp_path])
        target = tmp_path / "over.txt"
        target.write_text("old", encoding="utf-8")
        await file_write(str(target), "new")
        assert target.read_text(encoding="utf-8") == "new"

    async def test_rejects_dotdot_traversal(self, tmp_path: Path) -> None:
        configure_allowed_directories([tmp_path])
        with pytest.raises(ValueError, match="traversal"):
            await file_write(str(tmp_path / ".." / "evil.txt"), "bad")

    async def test_rejects_path_outside_allowed(self, tmp_path: Path) -> None:
        sub = tmp_path / "allowed"
        sub.mkdir()
        configure_allowed_directories([sub])
        with pytest.raises(ValueError, match="outside all allowed"):
            await file_write(str(tmp_path / "escape.txt"), "bad")

    async def test_no_tmp_file_left_after_write(self, tmp_path: Path) -> None:
        configure_allowed_directories([tmp_path])
        target = tmp_path / "clean.txt"
        await file_write(str(target), "data")
        tmp_files = list(tmp_path.glob("*.tmp"))
        assert tmp_files == []

    def test_tool_requires_approval(self) -> None:
        assert file_write._tool_definition.requires_approval is True  # type: ignore[attr-defined]


# ---------------------------------------------------------------------------
# file_list
# ---------------------------------------------------------------------------


class TestFileList:
    async def test_lists_directory_contents(self, tmp_path: Path) -> None:
        (tmp_path / "a.txt").write_text("", encoding="utf-8")
        (tmp_path / "b.txt").write_text("", encoding="utf-8")
        configure_allowed_directories([tmp_path])
        entries = await file_list(str(tmp_path))
        assert "a.txt" in entries
        assert "b.txt" in entries

    async def test_returns_sorted_entries(self, tmp_path: Path) -> None:
        for name in ["c.txt", "a.txt", "b.txt"]:
            (tmp_path / name).touch()
        configure_allowed_directories([tmp_path])
        entries = await file_list(str(tmp_path))
        assert entries == sorted(entries)

    async def test_includes_subdirectories(self, tmp_path: Path) -> None:
        (tmp_path / "sub").mkdir()
        configure_allowed_directories([tmp_path])
        entries = await file_list(str(tmp_path))
        assert "sub" in entries

    async def test_rejects_dotdot_traversal(self, tmp_path: Path) -> None:
        configure_allowed_directories([tmp_path])
        with pytest.raises(ValueError, match="traversal"):
            await file_list(str(tmp_path / ".." / "parent"))

    async def test_raises_on_non_directory(self, tmp_path: Path) -> None:
        f = tmp_path / "file.txt"
        f.write_text("x", encoding="utf-8")
        configure_allowed_directories([tmp_path])
        with pytest.raises(ValueError, match="Not a directory"):
            await file_list(str(f))

    async def test_empty_directory_returns_empty_list(self, tmp_path: Path) -> None:
        empty_dir = tmp_path / "empty"
        empty_dir.mkdir()
        configure_allowed_directories([tmp_path])
        entries = await file_list(str(empty_dir))
        assert entries == []

    def test_tool_definition_attached(self) -> None:
        assert hasattr(file_list, "_tool_definition")
        assert file_list._tool_definition.name == "file_list"  # type: ignore[attr-defined]
