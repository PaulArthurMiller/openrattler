"""Tests for HeartbeatLogEntry and HeartbeatLog (Build Piece 20.1)."""

from __future__ import annotations

import json
from dataclasses import asdict
from pathlib import Path

import pytest

from openrattler.processors.heartbeat_log import HeartbeatLog, HeartbeatLogEntry

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _entry(
    cycle_id: str = "hb_2025-03-27T14:00:00Z",
    run_at: str = "2025-03-27T14:00:00Z",
    urgency: str = "low",
    flagged_topics: list[str] | None = None,
    delivered_to_user: bool = False,
    summary: str = "No significant activity detected.",
    predictions: list[dict] | None = None,
    outcomes: list[dict] | None = None,
    calibration_applied: bool = False,
) -> HeartbeatLogEntry:
    return HeartbeatLogEntry(
        cycle_id=cycle_id,
        run_at=run_at,
        urgency=urgency,
        flagged_topics=flagged_topics if flagged_topics is not None else [],
        delivered_to_user=delivered_to_user,
        summary=summary,
        predictions=predictions if predictions is not None else [],
        outcomes=outcomes if outcomes is not None else [],
        calibration_applied=calibration_applied,
    )


def _make_log(tmp_path: Path, max_context: int = 7) -> HeartbeatLog:
    return HeartbeatLog(log_path=tmp_path / "heartbeat_log.jsonl", max_context_entries=max_context)


# ---------------------------------------------------------------------------
# TestHeartbeatLogEntry
# ---------------------------------------------------------------------------


class TestHeartbeatLogEntry:
    def test_constructs_with_valid_fields(self) -> None:
        e = _entry()
        assert e.cycle_id == "hb_2025-03-27T14:00:00Z"
        assert e.urgency == "low"

    def test_all_defaults_apply(self) -> None:
        e = _entry()
        assert e.predictions == []
        assert e.outcomes == []
        assert e.calibration_applied is False

    def test_summary_truncated_to_120_chars_no_exception(self) -> None:
        long_summary = "A" * 200
        e = _entry(summary=long_summary)
        assert len(e.summary) == 120
        assert e.summary.endswith("...")

    def test_summary_at_exactly_120_chars_not_truncated(self) -> None:
        exact = "B" * 120
        e = _entry(summary=exact)
        assert e.summary == exact

    def test_serialises_to_json_line(self) -> None:
        e = _entry()
        line = json.dumps(asdict(e))
        assert isinstance(line, str)
        assert '"cycle_id"' in line

    def test_round_trips_json(self) -> None:
        e = _entry(
            urgency="high",
            delivered_to_user=True,
            summary="Alert: budget review due.",
            flagged_topics=["budget_review"],
        )
        data = json.loads(json.dumps(asdict(e)))
        e2 = HeartbeatLogEntry(**data)
        assert e2 == e

    def test_predictions_defaults_to_empty_list(self) -> None:
        e = _entry()
        assert e.predictions == []

    def test_outcomes_defaults_to_empty_list(self) -> None:
        e = _entry()
        assert e.outcomes == []

    def test_calibration_applied_defaults_to_false(self) -> None:
        e = _entry()
        assert e.calibration_applied is False


# ---------------------------------------------------------------------------
# TestHeartbeatLogReadWrite
# ---------------------------------------------------------------------------


class TestHeartbeatLogReadWrite:
    async def test_append_creates_file_and_parent_dirs(self, tmp_path: Path) -> None:
        log = HeartbeatLog(
            log_path=tmp_path / "sub" / "dir" / "heartbeat_log.jsonl",
            max_context_entries=7,
        )
        await log.append(_entry(cycle_id="hb_001"))
        assert log._log_path.exists()

    async def test_append_adds_exactly_one_line_per_call(self, tmp_path: Path) -> None:
        log = _make_log(tmp_path)
        await log.append(_entry(cycle_id="hb_001"))
        await log.append(_entry(cycle_id="hb_002"))
        lines = [ln for ln in log._log_path.read_text().splitlines() if ln.strip()]
        assert len(lines) == 2

    async def test_read_recent_returns_last_n_in_chronological_order(self, tmp_path: Path) -> None:
        log = _make_log(tmp_path)
        for i in range(5):
            await log.append(_entry(cycle_id=f"hb_{i:03d}"))
        entries = await log.read_recent(3)
        assert len(entries) == 3
        assert entries[0].cycle_id == "hb_002"
        assert entries[1].cycle_id == "hb_003"
        assert entries[2].cycle_id == "hb_004"

    async def test_read_recent_on_absent_file_returns_empty_list(self, tmp_path: Path) -> None:
        log = _make_log(tmp_path)
        entries = await log.read_recent(5)
        assert entries == []

    async def test_read_recent_n_exceeds_length_returns_all(self, tmp_path: Path) -> None:
        log = _make_log(tmp_path)
        for i in range(3):
            await log.append(_entry(cycle_id=f"hb_{i:03d}"))
        entries = await log.read_recent(100)
        assert len(entries) == 3

    async def test_stale_tmp_file_does_not_corrupt_log(self, tmp_path: Path) -> None:
        log = _make_log(tmp_path)
        await log.append(_entry(cycle_id="hb_good"))
        # Simulate a stale .tmp file left from a prior crash.
        tmp_file = log._log_path.with_suffix(log._log_path.suffix + ".tmp")
        tmp_file.write_text('{"corrupted": true}\n', encoding="utf-8")
        # A new append should still work correctly.
        await log.append(_entry(cycle_id="hb_after_crash"))
        entries = await log.read_recent(10)
        ids = [e.cycle_id for e in entries]
        assert "hb_good" in ids
        assert "hb_after_crash" in ids

    async def test_update_outcomes_replaces_outcomes_field(self, tmp_path: Path) -> None:
        log = _make_log(tmp_path)
        await log.append(_entry(cycle_id="hb_target"))
        outcomes = [
            {
                "topic": "budget",
                "observed": "discussed",
                "prediction_correct": True,
                "turns_to_resolution": 3,
            }
        ]
        await log.update_outcomes("hb_target", outcomes)
        entries = await log.read_recent(10)
        assert entries[0].outcomes == outcomes

    async def test_update_outcomes_unknown_cycle_id_logs_warning_no_raise(
        self, tmp_path: Path, caplog: pytest.LogCaptureFixture
    ) -> None:
        log = _make_log(tmp_path)
        await log.append(_entry(cycle_id="hb_exists"))
        import logging

        with caplog.at_level(logging.WARNING):
            await log.update_outcomes("hb_does_not_exist", [])
        assert any("not found" in r.message for r in caplog.records)

    async def test_update_outcomes_atomic_write(self, tmp_path: Path) -> None:
        log = _make_log(tmp_path)
        await log.append(_entry(cycle_id="hb_a"))
        await log.update_outcomes(
            "hb_a",
            [
                {
                    "topic": "t",
                    "observed": "o",
                    "prediction_correct": None,
                    "turns_to_resolution": None,
                }
            ],
        )
        # File should exist and be readable after the write.
        entries = await log.read_recent(10)
        assert len(entries) == 1

    async def test_read_recent_returns_updated_entry_after_update_outcomes(
        self, tmp_path: Path
    ) -> None:
        log = _make_log(tmp_path)
        await log.append(_entry(cycle_id="hb_z", urgency="high"))
        await log.update_outcomes(
            "hb_z",
            [{"topic": "x", "observed": "y", "prediction_correct": True, "turns_to_resolution": 1}],
        )
        entries = await log.read_recent(10)
        assert entries[0].outcomes[0]["topic"] == "x"


# ---------------------------------------------------------------------------
# TestHeartbeatLogPrune
# ---------------------------------------------------------------------------


class TestHeartbeatLogPrune:
    async def test_prune_leaves_correct_number_of_entries(self, tmp_path: Path) -> None:
        log = _make_log(tmp_path)
        for i in range(25):
            await log.append(_entry(cycle_id=f"hb_{i:03d}"))
        await log.prune(keep=10)
        entries = await log.read_recent(100)
        assert len(entries) == 10

    async def test_prune_is_noop_when_entries_lte_keep(self, tmp_path: Path) -> None:
        log = _make_log(tmp_path)
        for i in range(10):
            await log.append(_entry(cycle_id=f"hb_{i:03d}"))
        original_content = log._log_path.read_text()
        await log.prune(keep=100)
        assert log._log_path.read_text() == original_content

    async def test_prune_retains_most_recent_entries(self, tmp_path: Path) -> None:
        log = _make_log(tmp_path)
        for i in range(15):
            await log.append(_entry(cycle_id=f"hb_{i:03d}"))
        await log.prune(keep=5)
        entries = await log.read_recent(100)
        ids = [e.cycle_id for e in entries]
        # Should keep hb_010 through hb_014 (the last 5).
        assert "hb_014" in ids
        assert "hb_000" not in ids

    async def test_prune_is_idempotent(self, tmp_path: Path) -> None:
        log = _make_log(tmp_path)
        for i in range(20):
            await log.append(_entry(cycle_id=f"hb_{i:03d}"))
        await log.prune(keep=5)
        after_first = log._log_path.read_text()
        await log.prune(keep=5)
        after_second = log._log_path.read_text()
        assert after_first == after_second

    async def test_prune_uses_atomic_write(self, tmp_path: Path) -> None:
        log = _make_log(tmp_path)
        for i in range(15):
            await log.append(_entry(cycle_id=f"hb_{i:03d}"))
        await log.prune(keep=5)
        # File should exist and entries be readable after prune.
        entries = await log.read_recent(100)
        assert len(entries) == 5


# ---------------------------------------------------------------------------
# TestHeartbeatLogContextBlock
# ---------------------------------------------------------------------------


class TestHeartbeatLogContextBlock:
    def test_empty_entries_returns_no_prior_cycles_string(self) -> None:
        log = _make_log(Path("/tmp"))  # path doesn't matter for this test
        result = log.build_context_block([])
        assert "no prior cycles" in result.lower()
        assert len(result) > 0

    def test_block_contains_required_fields(self) -> None:
        log = _make_log(Path("/tmp"))
        e = _entry(
            cycle_id="hb_2025-03-27T14:00:00Z",
            urgency="high",
            delivered_to_user=True,
            summary="Flagged budget review.",
        )
        result = log.build_context_block([e])
        assert "hb_2025-03-27T14:00:00Z" in result
        assert "high" in result
        assert "yes" in result
        assert "Flagged budget review." in result

    def test_summary_truncated_to_80_chars_in_table(self) -> None:
        log = _make_log(Path("/tmp"))
        long_summary = "X" * 100
        e = _entry(summary=long_summary[:120])  # valid 120 char summary
        result = log.build_context_block([e])
        # The table row summary should be at most 80 chars (plus the "..." suffix).
        # Find the last column in the row.
        for line in result.splitlines():
            if "X" in line and "|" in line:
                # Extract last cell.
                parts = [p.strip() for p in line.split("|")]
                last_cell = [p for p in parts if p][-1]
                assert len(last_cell) <= 83  # 80 + "..." = 83

    def test_pending_predictions_appear_in_column(self) -> None:
        log = _make_log(Path("/tmp"))
        e = _entry(
            predictions=[
                {"topic": "budget_review", "predicted_urgency": "high", "predicted_action": "alert"}
            ],
            outcomes=[],  # not yet resolved
        )
        result = log.build_context_block([e])
        assert "budget_review" in result

    def test_resolved_predictions_show_dash(self) -> None:
        log = _make_log(Path("/tmp"))
        e = _entry(
            predictions=[
                {"topic": "budget_review", "predicted_urgency": "high", "predicted_action": "alert"}
            ],
            outcomes=[
                {
                    "topic": "budget_review",
                    "observed": "discussed",
                    "prediction_correct": True,
                    "turns_to_resolution": 2,
                }
            ],
        )
        result = log.build_context_block([e])
        # The pending column should show "—" since the prediction was resolved.
        # Check that budget_review does NOT appear in the pending column.
        # The row format: | cycle | urgency | delivered | pending | topics | summary |
        for line in result.splitlines():
            if "hb_" in line and "|" in line:
                parts = [p.strip() for p in line.split("|")]
                # Index 4 is the "Predictions Pending Review" column (0-indexed after leading |).
                non_empty = [p for p in parts if p]
                if len(non_empty) >= 4:
                    pending_cell = non_empty[3]
                    assert pending_cell == "\u2014"

    def test_block_is_valid_markdown(self) -> None:
        log = _make_log(Path("/tmp"))
        entries = [_entry(cycle_id=f"hb_{i:03d}", urgency="low") for i in range(3)]
        result = log.build_context_block(entries)
        # Must contain a header line and separator row.
        assert "| Cycle |" in result
        assert "|----" in result
