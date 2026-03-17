"""Tests for HeartbeatProcessor and HeartbeatOutput (Build 35.2)."""

from __future__ import annotations

from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from openrattler.models.messages import UniversalMessage, create_message
from openrattler.processors.heartbeat import (
    HEARTBEAT_OPERATION,
    HEARTBEAT_SESSION_KEY,
    HeartbeatOutput,
    HeartbeatProcessor,
)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_SESSION_KEY = HEARTBEAT_SESSION_KEY


def _stub_response(content: str) -> UniversalMessage:
    return create_message(
        from_agent="agent:main:main",
        to_agent="scheduler:heartbeat",
        session_key=_SESSION_KEY,
        type="response",
        operation="chat_response",
        trust_level="main",
        params={"content": content},
    )


def _make_processor(
    heartbeat_content: str = "## Heartbeat\nCheck your alerts.",
    response_content: str = "",
) -> HeartbeatProcessor:
    """Build a HeartbeatProcessor with mocked runtime and identity loader."""
    runtime = MagicMock()
    runtime.initialize_session = AsyncMock(
        return_value=MagicMock(
            key=_SESSION_KEY,
            system_prompt="## Soul\n\nBase prompt.",
            history=[],
        )
    )
    runtime.process_message = AsyncMock(return_value=_stub_response(response_content))

    identity_loader = MagicMock()
    identity_loader.load_heartbeat_section = AsyncMock(return_value=heartbeat_content)

    return HeartbeatProcessor(
        runtime=runtime,
        identity_loader=identity_loader,
        session_key=_SESSION_KEY,
    )


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

    async def test_empty_heartbeat_section_not_appended(self) -> None:
        proc = _make_processor(heartbeat_content="", response_content="ok")
        original_prompt = proc._runtime.initialize_session.return_value.system_prompt
        await proc.run_cycle()
        session = proc._runtime.initialize_session.return_value
        # system_prompt should not be appended to if heartbeat_section is empty
        assert session.system_prompt == original_prompt

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
