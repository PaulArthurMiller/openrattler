"""Tests for MemoryStore — structured JSON agent memory storage."""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path

import pytest

from openrattler.storage.memory import (
    MemoryStore,
    _agent_path,
    _compute_diff,
    _validate_agent_id,
)

# ---------------------------------------------------------------------------
# Helper — strip store-managed internal keys before comparing user data
# ---------------------------------------------------------------------------


def _user_data(d: dict) -> dict:
    """Return *d* without internal keys stamped by MemoryStore (e.g. memory_last_updated)."""
    return {k: v for k, v in d.items() if k not in ("memory_last_updated",)}


# ---------------------------------------------------------------------------
# Load
# ---------------------------------------------------------------------------


class TestLoad:
    async def test_load_returns_empty_dict_for_new_agent(self, tmp_path: Path) -> None:
        store = MemoryStore(tmp_path)
        result = await store.load("main")
        assert result == {}

    async def test_load_returns_saved_data(self, tmp_path: Path) -> None:
        store = MemoryStore(tmp_path)
        data: dict = {"facts": {"name": "Alice"}, "preferences": {}}
        await store.save("main", data)
        # save() stamps memory_last_updated; check user-supplied keys only.
        assert _user_data(await store.load("main")) == data

    async def test_load_nonexistent_base_returns_empty(self, tmp_path: Path) -> None:
        store = MemoryStore(tmp_path / "nonexistent")
        assert await store.load("main") == {}


# ---------------------------------------------------------------------------
# Save
# ---------------------------------------------------------------------------


class TestSave:
    async def test_save_creates_file(self, tmp_path: Path) -> None:
        store = MemoryStore(tmp_path)
        await store.save("main", {"facts": {}})
        assert _agent_path(tmp_path, "main").exists()

    async def test_save_creates_parent_dirs(self, tmp_path: Path) -> None:
        store = MemoryStore(tmp_path)
        await store.save("subagent-abc", {"facts": {}})
        assert _agent_path(tmp_path, "subagent-abc").exists()

    async def test_save_load_round_trip(self, tmp_path: Path) -> None:
        store = MemoryStore(tmp_path)
        data: dict = {
            "facts": {"user": "Bob", "tz": "UTC"},
            "preferences": {"style": "verbose"},
            "instructions": ["Be helpful"],
        }
        await store.save("main", data)
        assert _user_data(await store.load("main")) == data

    async def test_save_overwrites_existing(self, tmp_path: Path) -> None:
        store = MemoryStore(tmp_path)
        await store.save("main", {"facts": {"x": 1}})
        await store.save("main", {"facts": {"x": 99}})
        assert _user_data(await store.load("main")) == {"facts": {"x": 99}}

    async def test_save_preserves_unicode(self, tmp_path: Path) -> None:
        store = MemoryStore(tmp_path)
        data: dict = {"facts": {"greeting": "こんにちは", "emoji": "🎉"}}
        await store.save("main", data)
        assert _user_data(await store.load("main")) == data


# ---------------------------------------------------------------------------
# Atomic write
# ---------------------------------------------------------------------------


class TestAtomicWrite:
    async def test_no_tmp_file_after_successful_save(self, tmp_path: Path) -> None:
        store = MemoryStore(tmp_path)
        await store.save("main", {"facts": {}})
        tmp_file = _agent_path(tmp_path, "main").with_suffix(".tmp")
        assert not tmp_file.exists()

    async def test_leftover_tmp_file_does_not_prevent_save(self, tmp_path: Path) -> None:
        """A stale .tmp file from an interrupted previous write must not block new saves."""
        store = MemoryStore(tmp_path)
        agent_dir = tmp_path / "main"
        agent_dir.mkdir(parents=True)
        stale_tmp = agent_dir / "memory.tmp"
        stale_tmp.write_text("STALE DATA")

        await store.save("main", {"facts": {"fresh": True}})

        assert _user_data(await store.load("main")) == {"facts": {"fresh": True}}
        assert not stale_tmp.exists()

    async def test_sequential_saves_produce_correct_final_data(self, tmp_path: Path) -> None:
        """Multiple saves produce the exact data from the last write."""
        store = MemoryStore(tmp_path)
        await store.save("main", {"facts": {"version": 1}})
        await store.save("main", {"facts": {"version": 2}})
        assert _user_data(await store.load("main")) == {"facts": {"version": 2}}


# ---------------------------------------------------------------------------
# Compute diff
# ---------------------------------------------------------------------------


class TestComputeDiff:
    async def test_diff_empty_when_identical(self, tmp_path: Path) -> None:
        store = MemoryStore(tmp_path)
        data: dict = {"facts": {"x": 1}}
        await store.save("main", data)
        diff = await store.compute_diff("main", data)
        assert diff == {"added": {}, "removed": {}, "modified": {}}

    async def test_diff_detects_added_keys(self, tmp_path: Path) -> None:
        store = MemoryStore(tmp_path)
        await store.save("main", {"facts": {}})
        diff = await store.compute_diff("main", {"facts": {}, "preferences": {"style": "concise"}})
        assert "preferences" in diff["added"]
        assert diff["removed"] == {}
        assert diff["modified"] == {}

    async def test_diff_detects_removed_keys(self, tmp_path: Path) -> None:
        store = MemoryStore(tmp_path)
        await store.save("main", {"facts": {}, "preferences": {}})
        diff = await store.compute_diff("main", {"facts": {}})
        assert "preferences" in diff["removed"]
        assert diff["added"] == {}
        assert diff["modified"] == {}

    async def test_diff_detects_modified_keys(self, tmp_path: Path) -> None:
        store = MemoryStore(tmp_path)
        await store.save("main", {"facts": {"name": "Alice"}})
        diff = await store.compute_diff("main", {"facts": {"name": "Bob"}})
        assert "facts" in diff["modified"]
        assert diff["modified"]["facts"]["old"] == {"name": "Alice"}
        assert diff["modified"]["facts"]["new"] == {"name": "Bob"}

    async def test_diff_ignores_history_key(self, tmp_path: Path) -> None:
        store = MemoryStore(tmp_path)
        data: dict = {
            "facts": {},
            "history": [{"timestamp": "t", "change": "init", "approved_by": "user"}],
        }
        await store.save("main", data)
        # Different history and absent memory_last_updated in proposed — neither
        # should appear in the diff (both are internal store-managed keys).
        diff = await store.compute_diff("main", {"facts": {}, "history": []})
        assert diff == {"added": {}, "removed": {}, "modified": {}}

    async def test_diff_ignores_memory_last_updated_key(self, tmp_path: Path) -> None:
        store = MemoryStore(tmp_path)
        await store.save("main", {"facts": {}})
        # proposed has no memory_last_updated — must not appear in diff["removed"]
        diff = await store.compute_diff("main", {"facts": {}})
        assert diff == {"added": {}, "removed": {}, "modified": {}}

    async def test_diff_all_added_for_new_agent(self, tmp_path: Path) -> None:
        store = MemoryStore(tmp_path)
        proposed: dict = {"facts": {"x": 1}, "preferences": {}}
        diff = await store.compute_diff("main", proposed)
        assert "facts" in diff["added"]
        assert "preferences" in diff["added"]
        assert diff["removed"] == {}
        assert diff["modified"] == {}

    def test_compute_diff_pure(self) -> None:
        """_compute_diff is a pure function usable without any disk I/O."""
        diff = _compute_diff(
            {"a": 1, "b": 2, "history": []},
            {"b": 99, "c": 3, "history": [{"x": "y"}]},
        )
        assert diff["added"] == {"c": 3}
        assert diff["removed"] == {"a": 1}
        assert diff["modified"] == {"b": {"old": 2, "new": 99}}


# ---------------------------------------------------------------------------
# Apply changes
# ---------------------------------------------------------------------------


class TestApplyChanges:
    async def test_apply_merges_new_keys(self, tmp_path: Path) -> None:
        store = MemoryStore(tmp_path)
        await store.save("main", {"facts": {"x": 1}})
        await store.apply_changes("main", {"preferences": {"style": "verbose"}}, "user")
        result = await store.load("main")
        assert result["facts"] == {"x": 1}
        assert result["preferences"] == {"style": "verbose"}

    async def test_apply_updates_existing_keys(self, tmp_path: Path) -> None:
        store = MemoryStore(tmp_path)
        await store.save("main", {"facts": {"name": "Alice"}})
        await store.apply_changes("main", {"facts": {"name": "Bob"}}, "user")
        result = await store.load("main")
        assert result["facts"]["name"] == "Bob"

    async def test_apply_appends_history_entry(self, tmp_path: Path) -> None:
        store = MemoryStore(tmp_path)
        await store.save("main", {"facts": {}})
        await store.apply_changes("main", {"facts": {"key": "val"}}, "user")
        result = await store.load("main")
        assert "history" in result
        assert len(result["history"]) == 1
        entry = result["history"][0]
        assert entry["approved_by"] == "user"
        assert "timestamp" in entry
        assert "change" in entry

    async def test_apply_history_grows_across_calls(self, tmp_path: Path) -> None:
        store = MemoryStore(tmp_path)
        await store.save("main", {})
        await store.apply_changes("main", {"facts": {"a": 1}}, "user")
        await store.apply_changes("main", {"facts": {"a": 2}}, "security_agent")
        result = await store.load("main")
        assert len(result["history"]) == 2
        assert result["history"][0]["approved_by"] == "user"
        assert result["history"][1]["approved_by"] == "security_agent"

    async def test_apply_history_key_in_changes_ignored(self, tmp_path: Path) -> None:
        """Callers cannot overwrite the history key via apply_changes."""
        store = MemoryStore(tmp_path)
        await store.save("main", {})
        await store.apply_changes(
            "main",
            {"facts": {}, "history": [{"INJECTED": True}]},
            "user",
        )
        result = await store.load("main")
        # Exactly one history entry (from apply_changes itself), not the injected one.
        assert len(result["history"]) == 1
        assert "INJECTED" not in result["history"][0]

    async def test_apply_returns_true(self, tmp_path: Path) -> None:
        store = MemoryStore(tmp_path)
        assert await store.apply_changes("main", {"facts": {}}, "user") is True

    async def test_apply_to_new_agent_creates_file(self, tmp_path: Path) -> None:
        """apply_changes works even when no memory file exists yet."""
        store = MemoryStore(tmp_path)
        await store.apply_changes("main", {"facts": {"first": True}}, "user")
        result = await store.load("main")
        assert result["facts"] == {"first": True}
        assert len(result["history"]) == 1

    async def test_apply_preserves_prior_history(self, tmp_path: Path) -> None:
        """Existing history entries survive a subsequent apply_changes call."""
        store = MemoryStore(tmp_path)
        initial: dict = {
            "facts": {},
            "history": [{"timestamp": "t0", "change": "init", "approved_by": "bootstrap"}],
        }
        await store.save("main", initial)
        await store.apply_changes("main", {"facts": {"added": True}}, "user")
        result = await store.load("main")
        assert len(result["history"]) == 2
        assert result["history"][0]["approved_by"] == "bootstrap"


# ---------------------------------------------------------------------------
# Path sanitization
# ---------------------------------------------------------------------------


class TestPathSanitization:
    def _assert_rejected(self, agent_id: str) -> None:
        with pytest.raises(ValueError):
            _validate_agent_id(agent_id)

    def test_empty_rejected(self) -> None:
        self._assert_rejected("")

    def test_double_dot_rejected(self) -> None:
        self._assert_rejected("..")

    def test_path_traversal_rejected(self) -> None:
        self._assert_rejected("../../etc")

    def test_absolute_slash_rejected(self) -> None:
        self._assert_rejected("/main")

    def test_absolute_backslash_rejected(self) -> None:
        self._assert_rejected("\\main")

    def test_colon_rejected(self) -> None:
        self._assert_rejected("agent:main")

    def test_space_rejected(self) -> None:
        self._assert_rejected("my agent")

    def test_special_chars_rejected(self) -> None:
        self._assert_rejected("agent@main!")

    def test_valid_simple_name_accepted(self) -> None:
        _validate_agent_id("main")  # must not raise

    def test_valid_hyphens_accepted(self) -> None:
        _validate_agent_id("subagent-abc-123")  # must not raise

    def test_valid_underscores_accepted(self) -> None:
        _validate_agent_id("work_agent")  # must not raise

    async def test_sanitization_applies_to_load(self, tmp_path: Path) -> None:
        store = MemoryStore(tmp_path)
        with pytest.raises(ValueError):
            await store.load("../../etc")

    async def test_sanitization_applies_to_save(self, tmp_path: Path) -> None:
        store = MemoryStore(tmp_path)
        with pytest.raises(ValueError):
            await store.save("../evil", {})

    async def test_sanitization_applies_to_compute_diff(self, tmp_path: Path) -> None:
        store = MemoryStore(tmp_path)
        with pytest.raises(ValueError):
            await store.compute_diff("../evil", {})

    async def test_sanitization_applies_to_apply_changes(self, tmp_path: Path) -> None:
        store = MemoryStore(tmp_path)
        with pytest.raises(ValueError):
            await store.apply_changes("../evil", {}, "user")


# ---------------------------------------------------------------------------
# GetLastUpdated
# ---------------------------------------------------------------------------


class TestGetLastUpdated:
    async def test_returns_none_on_fresh_memory(self, tmp_path: Path) -> None:
        store = MemoryStore(tmp_path)
        result = await store.get_last_updated("main")
        assert result is None
        print("[get_last_updated] fresh store → None ✓")

    async def test_returns_datetime_after_save(self, tmp_path: Path) -> None:
        store = MemoryStore(tmp_path)
        before = datetime.now(timezone.utc)
        await store.save("main", {"facts": {}})
        after = datetime.now(timezone.utc)
        result = await store.get_last_updated("main")
        assert result is not None
        assert before <= result <= after
        print(f"[get_last_updated] after save → {result} ✓")

    async def test_result_is_timezone_aware(self, tmp_path: Path) -> None:
        store = MemoryStore(tmp_path)
        await store.save("main", {"facts": {}})
        result = await store.get_last_updated("main")
        assert result is not None
        assert result.tzinfo is not None
        print(f"[get_last_updated] timezone-aware: {result.tzinfo} ✓")

    async def test_updates_on_each_save(self, tmp_path: Path) -> None:
        store = MemoryStore(tmp_path)
        await store.save("main", {"facts": {"v": 1}})
        first = await store.get_last_updated("main")
        assert first is not None
        # Second save must produce a timestamp >= the first.
        await store.save("main", {"facts": {"v": 2}})
        second = await store.get_last_updated("main")
        assert second is not None
        assert second >= first
        print(f"[get_last_updated] second={second} >= first={first} ✓")

    async def test_returns_datetime_after_apply_changes(self, tmp_path: Path) -> None:
        store = MemoryStore(tmp_path)
        # apply_changes calls save() internally → timestamp should be stamped.
        await store.apply_changes("main", {"facts": {"x": 1}}, "user")
        result = await store.get_last_updated("main")
        assert result is not None
        print(f"[get_last_updated] after apply_changes → {result} ✓")

    async def test_save_does_not_mutate_input_dict(self, tmp_path: Path) -> None:
        store = MemoryStore(tmp_path)
        data: dict = {"facts": {"name": "Alice"}}
        await store.save("main", data)
        # The caller's original dict must not have memory_last_updated injected.
        assert "memory_last_updated" not in data
        print("[get_last_updated] input dict not mutated ✓")

    async def test_returns_none_when_key_absent_in_legacy_file(self, tmp_path: Path) -> None:
        # Simulate a legacy memory.json written before memory_last_updated existed.
        store = MemoryStore(tmp_path)
        path = tmp_path / "main" / "memory.json"
        path.parent.mkdir(parents=True, exist_ok=True)
        import json as _json

        path.write_text(_json.dumps({"facts": {"name": "legacy"}}), encoding="utf-8")
        result = await store.get_last_updated("main")
        assert result is None
        print("[get_last_updated] legacy file (no key) → None ✓")

    async def test_returns_none_when_value_is_invalid(self, tmp_path: Path) -> None:
        store = MemoryStore(tmp_path)
        path = tmp_path / "main" / "memory.json"
        path.parent.mkdir(parents=True, exist_ok=True)
        import json as _json

        path.write_text(_json.dumps({"memory_last_updated": "not-a-date"}), encoding="utf-8")
        result = await store.get_last_updated("main")
        assert result is None
        print("[get_last_updated] invalid timestamp value → None ✓")
