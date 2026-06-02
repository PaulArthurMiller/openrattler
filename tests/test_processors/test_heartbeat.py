"""Tests for HeartbeatProcessor and HeartbeatOutput (Build 35.2 / 20.1)."""

from __future__ import annotations

from pathlib import Path
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import asyncio

import pytest

from openrattler.models.messages import UniversalMessage, create_message
from openrattler.processors.heartbeat import (
    HEARTBEAT_OPERATION,
    HEARTBEAT_SESSION_KEY,
    HeartbeatOutput,
    HeartbeatProcessor,
)
from openrattler.processors.heartbeat_log import HeartbeatLogEntry

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_SESSION_KEY = HEARTBEAT_SESSION_KEY


def _stub_response(content: str, session_key: str = _SESSION_KEY) -> UniversalMessage:
    return create_message(
        from_agent="agent:main:main",
        to_agent="scheduler:heartbeat",
        session_key=session_key,
        type="response",
        operation="chat_response",
        trust_level="main",
        params={"content": content},
    )


def _make_processor(
    heartbeat_content: str = "## Heartbeat\nCheck your alerts.",
    response_content: str = "",
    tmp_path: Path | None = None,
) -> HeartbeatProcessor:
    """Build a HeartbeatProcessor with mocked runtime, identity loader, and heartbeat log."""
    runtime = MagicMock()
    session_mock = MagicMock(
        key=_SESSION_KEY,
        system_prompt="## Soul\n\nBase prompt.",
        history=[],
    )
    runtime.initialize_session = AsyncMock(return_value=session_mock)
    # process_message returns based on current response_content; allow it to vary in tests.
    # Accept **kwargs so the mock handles the new tool_allowlist parameter.
    runtime.process_message = AsyncMock(
        side_effect=lambda sess, msg, **kwargs: _stub_response(response_content, msg.session_key)
    )

    identity_loader = MagicMock()
    identity_loader.load_heartbeat_section = AsyncMock(return_value=heartbeat_content)

    proc = HeartbeatProcessor(
        runtime=runtime,
        identity_loader=identity_loader,
        identity_dir=tmp_path if tmp_path is not None else Path("/tmp/heartbeat_test"),
        session_key=_SESSION_KEY,
    )
    # Replace heartbeat_log with an async mock so tests don't touch disk unless they
    # explicitly need a real log (see TestEchoChamberRegression).
    log_mock = MagicMock()
    log_mock.read_recent = AsyncMock(return_value=[])
    log_mock.append = AsyncMock()
    log_mock.prune = AsyncMock()
    log_mock.build_context_block = MagicMock(
        return_value="## Recent Heartbeat History\n\n_No prior cycles recorded._\n"
    )
    proc._heartbeat_log = log_mock

    return proc


# ---------------------------------------------------------------------------
# HeartbeatOutput
# ---------------------------------------------------------------------------


class TestHeartbeatOutput:
    def test_urgency_is_immediate(self) -> None:
        out = HeartbeatOutput(summary="something")
        assert out.urgency == "immediate"

    def test_operation_is_heartbeat_response(self) -> None:
        out = HeartbeatOutput(summary="something")
        assert out.operation == HEARTBEAT_OPERATION

    def test_params_contains_summary_and_content(self) -> None:
        out = HeartbeatOutput(summary="check this")
        assert out.params["summary"] == "check this"
        assert out.params["content"] == "check this"

    def test_id_is_unique_per_instance(self) -> None:
        a = HeartbeatOutput(summary="x")
        b = HeartbeatOutput(summary="x")
        assert a.id != b.id

    def test_id_has_heartbeat_prefix(self) -> None:
        out = HeartbeatOutput(summary="x")
        assert out.id.startswith("heartbeat_")


# ---------------------------------------------------------------------------
# HeartbeatProcessor — lifecycle
# ---------------------------------------------------------------------------


class TestHeartbeatProcessorLifecycle:
    def test_processor_name(self) -> None:
        proc = _make_processor()
        assert proc.processor_name == "heartbeat"

    async def test_connect_is_noop(self) -> None:
        proc = _make_processor()
        await proc.connect()  # must not raise

    async def test_disconnect_is_noop(self) -> None:
        proc = _make_processor()
        await proc.disconnect()  # must not raise

    async def test_get_pending_output_initially_empty(self) -> None:
        proc = _make_processor()
        assert await proc.get_pending_output() == []


# ---------------------------------------------------------------------------
# HeartbeatProcessor — run_cycle
# ---------------------------------------------------------------------------


class TestHeartbeatProcessorCycle:
    async def test_cycle_returns_one_when_content_produced(self) -> None:
        proc = _make_processor(response_content="Nothing urgent, but memory looks good.")
        count = await proc.run_cycle()
        assert count == 1

    async def test_cycle_returns_zero_when_no_content(self) -> None:
        proc = _make_processor(response_content="")
        count = await proc.run_cycle()
        assert count == 0

    async def test_cycle_returns_zero_when_whitespace_only(self) -> None:
        proc = _make_processor(response_content="   \n  ")
        count = await proc.run_cycle()
        assert count == 0

    async def test_heartbeat_section_injected_into_system_prompt(self) -> None:
        proc = _make_processor(
            heartbeat_content="## Heartbeat\nCheck alerts.",
            response_content="ok",
        )
        await proc.run_cycle()
        # The session object's system_prompt should have been mutated to include heartbeat.
        session = proc._runtime.initialize_session.return_value
        assert "## Heartbeat" in session.system_prompt

    async def test_empty_heartbeat_section_still_injects_context_block(self) -> None:
        # When heartbeat_section is empty, the context block is still injected.
        proc = _make_processor(heartbeat_content="", response_content="ok")
        original_prompt = proc._runtime.initialize_session.return_value.system_prompt
        await proc.run_cycle()
        session = proc._runtime.initialize_session.return_value
        # The context block (heartbeat log history) is always appended even when HEARTBEAT.md
        # section is empty, so system_prompt is modified.
        assert session.system_prompt != original_prompt
        assert "Heartbeat History" in session.system_prompt

    async def test_runtime_process_message_called(self) -> None:
        proc = _make_processor(response_content="something")
        await proc.run_cycle()
        proc._runtime.process_message.assert_awaited_once()

    async def test_trigger_message_has_correct_operation(self) -> None:
        proc = _make_processor(response_content="something")
        await proc.run_cycle()
        call_args = proc._runtime.process_message.await_args
        trigger: UniversalMessage = call_args[0][1]
        assert trigger.operation == "heartbeat_trigger"
        assert trigger.trust_level == "main"

    async def test_pending_output_has_response_content(self) -> None:
        proc = _make_processor(response_content="Alert: check social")
        await proc.run_cycle()
        pending = await proc.get_pending_output()
        assert len(pending) == 1
        assert pending[0].summary == "Alert: check social"

    async def test_pending_cleared_between_cycles(self) -> None:
        proc = _make_processor(response_content="first response")
        await proc.run_cycle()
        assert len(await proc.get_pending_output()) == 1

        # Second cycle with no content clears pending
        proc._runtime.process_message = AsyncMock(return_value=_stub_response(""))
        await proc.run_cycle()
        assert await proc.get_pending_output() == []

    async def test_runtime_error_does_not_raise(self) -> None:
        proc = _make_processor()
        proc._runtime.process_message = AsyncMock(side_effect=RuntimeError("boom"))
        count = await proc.run_cycle()
        assert count == 0

    async def test_identity_loader_error_does_not_raise(self) -> None:
        proc = _make_processor()
        proc._identity_loader.load_heartbeat_section = AsyncMock(
            side_effect=OSError("file not found")
        )
        count = await proc.run_cycle()
        assert count == 0


# ---------------------------------------------------------------------------
# HeartbeatProcessor — scheduler dispatch integration
# ---------------------------------------------------------------------------


class TestHeartbeatDispatchIntegration:
    async def test_heartbeat_output_dispatched_by_scheduler(self) -> None:
        """HeartbeatOutput with urgency='immediate' is dispatched via on_urgent_alert."""
        from openrattler.gateway.scheduler import ProcessorScheduler

        received: list[Any] = []

        async def callback(msg: Any) -> None:
            received.append(msg)

        proc = _make_processor(response_content="You have a pending social alert.")
        scheduler = ProcessorScheduler(on_urgent_alert=callback)
        await scheduler._run_processor_cycle(proc)

        assert len(received) == 1
        msg = received[0]
        assert isinstance(msg, UniversalMessage)
        assert msg.operation == HEARTBEAT_OPERATION

    async def test_heartbeat_dispatch_params_contain_content(self) -> None:
        from openrattler.gateway.scheduler import ProcessorScheduler

        received: list[Any] = []

        async def callback(msg: Any) -> None:
            received.append(msg)

        proc = _make_processor(response_content="Memory note: bootstrap complete.")
        scheduler = ProcessorScheduler(on_urgent_alert=callback)
        await scheduler._run_processor_cycle(proc)

        msg = received[0]
        assert "Memory note" in msg.params.get("content", "")

    async def test_no_dispatch_when_cycle_returns_zero(self) -> None:
        from openrattler.gateway.scheduler import ProcessorScheduler

        received: list[Any] = []

        async def callback(msg: Any) -> None:
            received.append(msg)

        proc = _make_processor(response_content="")
        scheduler = ProcessorScheduler(on_urgent_alert=callback)
        await scheduler._run_processor_cycle(proc)

        assert received == []


# ---------------------------------------------------------------------------
# TestEchoChamberRegression (Build Piece 20.1)
# ---------------------------------------------------------------------------


class TestEchoChamberRegression:
    """Verifies per-cycle session isolation — the echo-chamber fix."""

    async def test_two_cycles_produce_different_session_keys(self, tmp_path: Path) -> None:
        proc = _make_processor(response_content="something", tmp_path=tmp_path)
        await proc.run_cycle()
        key1 = proc._runtime.initialize_session.await_args_list[0][0][0]
        # Sleep 1 ms so _utcnow_iso() produces a different microsecond timestamp.
        await asyncio.sleep(0.001)
        await proc.run_cycle()
        key2 = proc._runtime.initialize_session.await_args_list[1][0][0]
        assert key1 != key2

    async def test_session_key_follows_prefix_pattern(self, tmp_path: Path) -> None:
        proc = _make_processor(response_content="something", tmp_path=tmp_path)
        await proc.run_cycle()
        key = proc._runtime.initialize_session.await_args_list[0][0][0]
        assert key.startswith("agent:main:heartbeat:hb_")

    async def test_session_initialised_with_empty_history(self, tmp_path: Path) -> None:
        proc = _make_processor(response_content="something", tmp_path=tmp_path)
        await proc.run_cycle()
        session = proc._runtime.initialize_session.return_value
        # run_cycle() must set session.history = [] for per-cycle isolation.
        assert session.history == []

    async def test_heartbeat_log_append_called_once_per_cycle(self, tmp_path: Path) -> None:
        proc = _make_processor(response_content="something", tmp_path=tmp_path)
        await proc.run_cycle()
        proc._heartbeat_log.append.assert_awaited_once()

    async def test_quiet_cycle_produces_correct_log_entry(self, tmp_path: Path) -> None:
        proc = _make_processor(response_content="", tmp_path=tmp_path)
        await proc.run_cycle()
        call_args = proc._heartbeat_log.append.await_args
        entry: HeartbeatLogEntry = call_args[0][0]
        assert entry.urgency == "low"
        assert entry.delivered_to_user is False
        assert entry.summary == "No significant activity detected."

    async def test_heartbeat_log_prune_called_after_append(self, tmp_path: Path) -> None:
        proc = _make_processor(response_content="something", tmp_path=tmp_path)
        await proc.run_cycle()
        proc._heartbeat_log.prune.assert_awaited_once()


# ---------------------------------------------------------------------------
# HeartbeatProcessor — lifecycle events (46.1)
# ---------------------------------------------------------------------------


def _make_lifecycle_store() -> MagicMock:
    """Return a mock SessionLifecycleStore."""
    store = MagicMock()
    store.emit_open = AsyncMock()
    store.emit_close = AsyncMock()
    return store


class TestHeartbeatLifecycleEvents:
    async def test_open_event_emitted_at_cycle_start(self, tmp_path: Path) -> None:
        lc_store = _make_lifecycle_store()
        proc = _make_processor(response_content="ok", tmp_path=tmp_path)
        proc._lifecycle_store = lc_store
        await proc.run_cycle()
        lc_store.emit_open.assert_awaited_once()
        call_args = lc_store.emit_open.await_args
        session_key = call_args[0][0]
        assert session_key.startswith("agent:main:heartbeat:")
        assert call_args[0][1] == "heartbeat"

    async def test_close_event_emitted_on_success(self, tmp_path: Path) -> None:
        lc_store = _make_lifecycle_store()
        proc = _make_processor(response_content="ok", tmp_path=tmp_path)
        proc._lifecycle_store = lc_store
        await proc.run_cycle()
        lc_store.emit_close.assert_awaited_once()
        call_args = lc_store.emit_close.await_args
        close_reason = call_args[0][1]
        assert close_reason == "completed"

    async def test_close_event_emitted_on_error_with_error_reason(self, tmp_path: Path) -> None:
        lc_store = _make_lifecycle_store()
        proc = _make_processor(tmp_path=tmp_path)
        proc._lifecycle_store = lc_store
        proc._runtime.process_message = AsyncMock(side_effect=RuntimeError("boom"))
        await proc.run_cycle()
        lc_store.emit_close.assert_awaited_once()
        call_args = lc_store.emit_close.await_args
        close_reason = call_args[0][1]
        assert close_reason == "error"

    async def test_lifecycle_store_failure_does_not_break_cycle(self, tmp_path: Path) -> None:
        lc_store = _make_lifecycle_store()
        lc_store.emit_open = AsyncMock(side_effect=Exception("store unavailable"))
        proc = _make_processor(response_content="ok", tmp_path=tmp_path)
        proc._lifecycle_store = lc_store
        # Should not raise
        count = await proc.run_cycle()
        assert count == 1

    async def test_no_lifecycle_events_when_store_is_none(self, tmp_path: Path) -> None:
        proc = _make_processor(response_content="ok", tmp_path=tmp_path)
        assert proc._lifecycle_store is None
        # Should not raise
        count = await proc.run_cycle()
        assert count == 1


# ---------------------------------------------------------------------------
# ProcessorScheduler — first-tick fix (46.1)
# ---------------------------------------------------------------------------


class TestSchedulerFirstTick:
    def test_register_processor_sets_last_run_to_now_not_none(self) -> None:
        from datetime import datetime, timezone

        from openrattler.gateway.scheduler import ProcessorScheduler

        processor = MagicMock()
        processor.processor_name = "test_proc"
        scheduler = ProcessorScheduler()
        scheduler.register_processor(processor, interval_minutes=30)
        last_run = scheduler._last_run.get("test_proc")
        # Must be a real datetime, not None.
        assert last_run is not None
        assert isinstance(last_run, datetime)

    def test_processor_does_not_fire_immediately_after_registration(self) -> None:
        """Elapsed time at first tick should be ~0, well below any reasonable interval."""
        from datetime import datetime, timezone

        from openrattler.gateway.scheduler import ProcessorScheduler

        processor = MagicMock()
        processor.processor_name = "test_proc"
        scheduler = ProcessorScheduler()
        scheduler.register_processor(processor, interval_minutes=30)
        # Simulate a scheduler tick right after registration.
        now = datetime.now(timezone.utc)
        last = scheduler._last_run["test_proc"]
        elapsed = (now - last).total_seconds()  # type: ignore[operator]
        # Elapsed should be tiny (milliseconds) — far less than 30 minutes.
        assert elapsed < 60  # generous 60-second window for slow test runners


# ---------------------------------------------------------------------------
# HeartbeatProcessor — tool allowlist (46.2)
# ---------------------------------------------------------------------------


def _make_processor_with_config(
    tool_allowlist: list[str],
    response_content: str = "ok",
    tmp_path: Path | None = None,
) -> HeartbeatProcessor:
    """Build a HeartbeatProcessor with a specific tool_allowlist from config."""
    from openrattler.config.loader import AppConfig, HeartbeatConfig

    config = AppConfig(heartbeat=HeartbeatConfig(tool_allowlist=tool_allowlist))

    runtime = MagicMock()
    session_mock = MagicMock(
        key=_SESSION_KEY,
        system_prompt="## Soul\n\nBase prompt.",
        history=[],
    )
    runtime.initialize_session = AsyncMock(return_value=session_mock)
    runtime.process_message = AsyncMock(
        side_effect=lambda sess, msg, **kwargs: _stub_response(response_content, msg.session_key)
    )
    runtime._usage_store = None

    identity_loader = MagicMock()
    identity_loader.load_heartbeat_section = AsyncMock(return_value="## Heartbeat")

    proc = HeartbeatProcessor(
        runtime=runtime,
        identity_loader=identity_loader,
        identity_dir=tmp_path if tmp_path is not None else Path("/tmp/heartbeat_allowlist_test"),
        config=config,
    )
    log_mock = MagicMock()
    log_mock.read_recent = AsyncMock(return_value=[])
    log_mock.append = AsyncMock()
    log_mock.prune = AsyncMock()
    log_mock.build_context_block = MagicMock(return_value="## Recent Heartbeat History\n")
    proc._heartbeat_log = log_mock
    return proc


class TestHeartbeatToolAllowlist:
    """Verifies that HeartbeatConfig.tool_allowlist is passed through to process_message."""

    async def test_configured_allowlist_passed_to_process_message(self, tmp_path: Path) -> None:
        """When tool_allowlist is set in config, process_message receives it."""
        allowlist = ["research_query", "memory_read", "send_email"]
        proc = _make_processor_with_config(tool_allowlist=allowlist, tmp_path=tmp_path)
        await proc.run_cycle()

        call_kwargs = proc._runtime.process_message.await_args.kwargs
        print(f"[test] call_kwargs={call_kwargs}")
        assert call_kwargs.get("tool_allowlist") == allowlist

    async def test_empty_allowlist_passes_none_to_process_message(self, tmp_path: Path) -> None:
        """When tool_allowlist is empty (default), process_message receives tool_allowlist=None."""
        proc = _make_processor_with_config(tool_allowlist=[], tmp_path=tmp_path)
        await proc.run_cycle()

        call_kwargs = proc._runtime.process_message.await_args.kwargs
        print(f"[test] call_kwargs={call_kwargs}")
        assert call_kwargs.get("tool_allowlist") is None

    async def test_tool_allowlist_stored_from_config(self) -> None:
        """HeartbeatProcessor._tool_allowlist reflects HeartbeatConfig.tool_allowlist."""
        from openrattler.config.loader import AppConfig, HeartbeatConfig

        runtime = MagicMock()
        identity_loader = MagicMock()
        config = AppConfig(heartbeat=HeartbeatConfig(tool_allowlist=["research_query", "send_sms"]))
        proc = HeartbeatProcessor(
            runtime=runtime,
            identity_loader=identity_loader,
            config=config,
        )
        assert proc._tool_allowlist == ["research_query", "send_sms"]

    async def test_no_config_gives_empty_tool_allowlist(self) -> None:
        """When no config is provided, _tool_allowlist defaults to empty list."""
        runtime = MagicMock()
        identity_loader = MagicMock()
        proc = HeartbeatProcessor(runtime=runtime, identity_loader=identity_loader, config=None)
        assert proc._tool_allowlist == []
