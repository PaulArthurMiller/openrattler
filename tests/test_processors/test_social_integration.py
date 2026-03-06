"""Integration tests for Social Secretary SS-D — Scheduler, Runtime, and Tools.

Test classes:

1. TestSchedulerIntegration  — ProcessorScheduler lifecycle and cycle execution
2. TestMainAlertLoading      — AgentRuntime._load_social_alerts + system prompt
3. TestAcknowledgeTool       — SocialTools.acknowledge_social_alert
4. TestContactAttentionTool  — SocialTools.adjust_contact_attention
5. TestObservationTool       — SocialTools.add_learning_observation
6. TestUrgentNotification    — Urgent alert dispatches UniversalMessage via callback
"""

from __future__ import annotations

import asyncio
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from openrattler.agents.providers.base import LLMProvider, LLMResponse, TokenUsage
from openrattler.agents.runtime import AgentRuntime
from openrattler.config.loader import AppConfig, load_config
from openrattler.gateway.scheduler import ProcessorScheduler
from openrattler.models.agents import AgentConfig, TrustLevel
from openrattler.models.messages import UniversalMessage
from openrattler.models.social import (
    ContactEntry,
    SocialAlert,
    SocialSecretaryConfig,
)
from openrattler.processors.base import ProactiveProcessor
from openrattler.storage.audit import AuditLog
from openrattler.storage.memory import MemoryStore
from openrattler.storage.social import SocialStore
from openrattler.storage.transcripts import TranscriptStore
from openrattler.tools.executor import ToolExecutor
from openrattler.tools.registry import ToolRegistry
from openrattler.tools.social_tools import SocialTools

# ---------------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------------

_MAIN_SESSION = "agent:main:main"
_OTHER_SESSION = "agent:other:other"


def _usage() -> TokenUsage:
    return TokenUsage(
        prompt_tokens=10, completion_tokens=5, total_tokens=15, estimated_cost_usd=0.0
    )


def _text_response(content: str = "ok") -> LLMResponse:
    return LLMResponse(
        content=content,
        tool_calls=[],
        usage=_usage(),
        model="test-model",
        finish_reason="stop",
    )


def _mock_provider() -> LLMProvider:
    provider = MagicMock(spec=LLMProvider)
    provider.complete = AsyncMock(return_value=_text_response())
    return provider


def _make_runtime(
    tmp_path: Path,
    *,
    social_store: SocialStore | None = None,
    system_prompt: str = "You are a test agent.",
) -> AgentRuntime:
    reg = ToolRegistry()
    log = AuditLog(tmp_path / "audit.jsonl")
    executor = ToolExecutor(reg, log)
    config = AgentConfig(
        agent_id=_MAIN_SESSION,
        name="Test",
        description="Test agent",
        model="test-model",
        trust_level=TrustLevel.main,
        allowed_tools=[],
        system_prompt=system_prompt,
    )
    return AgentRuntime(
        config=config,
        provider=_mock_provider(),
        tool_executor=executor,
        transcript_store=TranscriptStore(tmp_path / "transcripts"),
        memory_store=MemoryStore(tmp_path / "memory"),
        audit_log=log,
        social_store=social_store,
    )


def _make_alert(urgency: str = "low", acknowledged: bool = False) -> SocialAlert:
    return SocialAlert(
        source="facebook",
        person="Alice",
        relationship_strength="unknown",
        relationship_context="friend",
        event_type="birthday",
        summary="Alice's birthday is tomorrow",
        urgency=urgency,
        recommended_action="inform_user",
        recommended_timing="next_heartbeat",
        confidence=0.9,
        raw_reference_id="fb_123",
        acknowledged=acknowledged,
    )


def _make_contact(name: str = "Alice", attention: str = "normal") -> ContactEntry:
    return ContactEntry(
        name=name,
        relationship="friend",
        context_learned="unit test",
        source="test",
        attention_level=attention,
    )


# ---------------------------------------------------------------------------
# Stub ProactiveProcessor implementations
# ---------------------------------------------------------------------------


class _OkProcessor(ProactiveProcessor):
    """Processor that succeeds and returns a fixed cycle count."""

    def __init__(self, cycle_count: int = 2, pending: list[Any] | None = None) -> None:
        self._cycle_count = cycle_count
        self._pending = pending or []
        self.cycles_run = 0

    @property
    def processor_name(self) -> str:
        return "ok_processor"

    async def connect(self) -> None:
        pass

    async def disconnect(self) -> None:
        pass

    async def run_cycle(self) -> int:
        self.cycles_run += 1
        return self._cycle_count

    async def get_pending_output(self) -> list[Any]:
        return list(self._pending)


class _ErrorProcessor(ProactiveProcessor):
    """Processor whose run_cycle always raises."""

    @property
    def processor_name(self) -> str:
        return "error_processor"

    async def connect(self) -> None:
        pass

    async def disconnect(self) -> None:
        pass

    async def run_cycle(self) -> int:
        raise RuntimeError("deliberate failure")

    async def get_pending_output(self) -> list[Any]:
        return []


# ---------------------------------------------------------------------------
# 1. TestSchedulerIntegration
# ---------------------------------------------------------------------------


class TestSchedulerIntegration:
    async def test_register_processor_adds_to_last_run(self) -> None:
        scheduler = ProcessorScheduler()
        proc = _OkProcessor()
        scheduler.register_processor(proc, 60)
        assert "ok_processor" in scheduler._last_run

    async def test_run_cycle_calls_processor(self) -> None:
        scheduler = ProcessorScheduler()
        proc = _OkProcessor()
        await scheduler._run_processor_cycle(proc)
        assert proc.cycles_run == 1

    async def test_run_cycle_audit_logged(self, tmp_path: Path) -> None:
        log = AuditLog(tmp_path / "audit.jsonl")
        scheduler = ProcessorScheduler(audit=log)
        proc = _OkProcessor(cycle_count=3)
        await scheduler._run_processor_cycle(proc)

        events = await log.query()
        assert any(e.event == "ok_processor_cycle_complete" for e in events)
        complete_event = next(e for e in events if e.event == "ok_processor_cycle_complete")
        assert complete_event.details["alerts_generated"] == 3

    async def test_error_does_not_raise(self) -> None:
        scheduler = ProcessorScheduler()
        proc = _ErrorProcessor()
        # Must not raise
        await scheduler._run_processor_cycle(proc)

    async def test_error_audit_logged(self, tmp_path: Path) -> None:
        log = AuditLog(tmp_path / "audit.jsonl")
        scheduler = ProcessorScheduler(audit=log)
        proc = _ErrorProcessor()
        await scheduler._run_processor_cycle(proc)

        events = await log.query()
        assert any(e.event == "error_processor_cycle_error" for e in events)
        err_event = next(e for e in events if e.event == "error_processor_cycle_error")
        assert err_event.details["error"] == "RuntimeError"

    async def test_start_creates_task_and_stop_cancels(self) -> None:
        scheduler = ProcessorScheduler()
        assert not scheduler._running
        await scheduler.start()
        assert scheduler._running
        assert scheduler._task is not None
        await scheduler.stop()
        assert not scheduler._running
        assert scheduler._task is None

    async def test_start_is_idempotent(self) -> None:
        scheduler = ProcessorScheduler()
        await scheduler.start()
        task_ref = scheduler._task
        await scheduler.start()  # second call is no-op
        assert scheduler._task is task_ref
        await scheduler.stop()

    async def test_interval_not_elapsed_skips_run(self) -> None:
        """Processor with a 60-min interval is not run if just ran."""
        scheduler = ProcessorScheduler()
        proc = _OkProcessor()
        scheduler.register_processor(proc, 60)
        # Simulate "just ran" by setting last_run to now
        scheduler._last_run["ok_processor"] = datetime.now(timezone.utc)

        # Manually tick once — elapsed ≈ 0 s, interval = 3600 s → skip
        now = datetime.now(timezone.utc)
        for p, interval_minutes in scheduler._processors:
            last = scheduler._last_run.get(p.processor_name)
            elapsed = (now - last).total_seconds() if last is not None else float("inf")
            if elapsed >= interval_minutes * 60:
                await scheduler._run_processor_cycle(p)

        assert proc.cycles_run == 0


# ---------------------------------------------------------------------------
# 2. TestMainAlertLoading
# ---------------------------------------------------------------------------


class TestMainAlertLoading:
    async def test_no_store_returns_empty(self, tmp_path: Path) -> None:
        runtime = _make_runtime(tmp_path)
        result = await runtime._load_social_alerts(_MAIN_SESSION)
        assert result == ""

    async def test_non_main_session_returns_empty(self, tmp_path: Path) -> None:
        store = SocialStore(tmp_path / "social")
        runtime = _make_runtime(tmp_path, social_store=store)
        result = await runtime._load_social_alerts(_OTHER_SESSION)
        assert result == ""

    async def test_no_pending_alerts_returns_empty(self, tmp_path: Path) -> None:
        store = SocialStore(tmp_path / "social")
        runtime = _make_runtime(tmp_path, social_store=store)
        result = await runtime._load_social_alerts(_MAIN_SESSION)
        assert result == ""

    async def test_pending_alerts_appear_in_section(self, tmp_path: Path) -> None:
        store = SocialStore(tmp_path / "social")
        alert = _make_alert(urgency="next_interaction")
        await store.add_alert(alert)

        runtime = _make_runtime(tmp_path, social_store=store)
        result = await runtime._load_social_alerts(_MAIN_SESSION)

        assert "## Pending Social Alerts" in result
        assert "Alice" in result
        assert "birthday" in result

    async def test_acknowledged_alerts_excluded(self, tmp_path: Path) -> None:
        store = SocialStore(tmp_path / "social")
        alert = _make_alert()
        await store.add_alert(alert)
        await store.acknowledge_alert(alert.id)

        runtime = _make_runtime(tmp_path, social_store=store)
        result = await runtime._load_social_alerts(_MAIN_SESSION)

        assert result == ""

    async def test_alerts_in_system_prompt_after_initialize(self, tmp_path: Path) -> None:
        store = SocialStore(tmp_path / "social")
        alert = _make_alert(urgency="immediate")
        await store.add_alert(alert)

        runtime = _make_runtime(tmp_path, social_store=store)
        session = await runtime.initialize_session(_MAIN_SESSION)

        assert "Pending Social Alerts" in session.system_prompt
        assert alert.id in session.system_prompt

    async def test_no_alerts_section_in_prompt_when_no_store(self, tmp_path: Path) -> None:
        runtime = _make_runtime(tmp_path)
        session = await runtime.initialize_session(_MAIN_SESSION)
        assert "Pending Social Alerts" not in session.system_prompt

    async def test_store_error_returns_empty_gracefully(self, tmp_path: Path) -> None:
        store = MagicMock(spec=SocialStore)
        store.get_pending_alerts = AsyncMock(side_effect=IOError("disk failure"))
        runtime = _make_runtime(tmp_path, social_store=store)
        result = await runtime._load_social_alerts(_MAIN_SESSION)
        assert result == ""


# ---------------------------------------------------------------------------
# 3. TestAcknowledgeTool
# ---------------------------------------------------------------------------


class TestAcknowledgeTool:
    async def test_acknowledge_existing_alert(self, tmp_path: Path) -> None:
        store = SocialStore(tmp_path / "social")
        alert = _make_alert()
        await store.add_alert(alert)

        tools = SocialTools(store)
        result = await tools.acknowledge_social_alert(alert.id)

        assert result["success"] is True
        assert result["alert_id"] == alert.id

    async def test_acknowledge_sets_flag_in_store(self, tmp_path: Path) -> None:
        store = SocialStore(tmp_path / "social")
        alert = _make_alert()
        await store.add_alert(alert)

        tools = SocialTools(store)
        await tools.acknowledge_social_alert(alert.id)

        pending = await store.get_pending_alerts()
        assert not any(a.id == alert.id for a in pending)

    async def test_acknowledge_nonexistent_returns_error(self, tmp_path: Path) -> None:
        store = SocialStore(tmp_path / "social")
        tools = SocialTools(store)
        result = await tools.acknowledge_social_alert("social_alert_doesnotexist")
        assert result["success"] is False
        assert "not found" in result["error"]

    async def test_double_acknowledge_is_idempotent(self, tmp_path: Path) -> None:
        store = SocialStore(tmp_path / "social")
        alert = _make_alert()
        await store.add_alert(alert)

        tools = SocialTools(store)
        first = await tools.acknowledge_social_alert(alert.id)
        second = await tools.acknowledge_social_alert(alert.id)

        # Store finds the (now-acknowledged) alert and sets acknowledged=True again — idempotent
        assert first["success"] is True
        assert second["success"] is True

    async def test_tools_registered_in_registry(self, tmp_path: Path) -> None:
        store = SocialStore(tmp_path / "social")
        tools = SocialTools(store)
        reg = ToolRegistry()
        tools.register_all(reg)
        assert reg.get("acknowledge_social_alert") is not None


# ---------------------------------------------------------------------------
# 4. TestContactAttentionTool
# ---------------------------------------------------------------------------


class TestContactAttentionTool:
    async def test_adjust_known_contact(self, tmp_path: Path) -> None:
        store = SocialStore(tmp_path / "social")
        contact = _make_contact("Bob", attention="normal")
        await store.upsert_contact(contact)

        tools = SocialTools(store)
        result = await tools.adjust_contact_attention("Bob", "watch_closely")

        assert result["success"] is True
        assert result["attention_level"] == "watch_closely"

    async def test_adjustment_persisted(self, tmp_path: Path) -> None:
        store = SocialStore(tmp_path / "social")
        contact = _make_contact("Bob")
        await store.upsert_contact(contact)

        tools = SocialTools(store)
        await tools.adjust_contact_attention("Bob", "low")

        updated = await store.find_contact("Bob")
        assert updated is not None
        assert updated.attention_level == "low"

    async def test_unknown_contact_returns_error(self, tmp_path: Path) -> None:
        store = SocialStore(tmp_path / "social")
        tools = SocialTools(store)
        result = await tools.adjust_contact_attention("NoSuchPerson", "normal")
        assert result["success"] is False
        assert "not found" in result["error"]

    async def test_invalid_attention_level_returns_error(self, tmp_path: Path) -> None:
        store = SocialStore(tmp_path / "social")
        tools = SocialTools(store)
        result = await tools.adjust_contact_attention("Alice", "obsessive")
        assert result["success"] is False
        assert "Invalid attention_level" in result["error"]

    async def test_all_valid_levels_accepted(self, tmp_path: Path) -> None:
        store = SocialStore(tmp_path / "social")
        for level in ("watch_closely", "normal", "low"):
            contact = _make_contact(f"Person_{level}")
            await store.upsert_contact(contact)
            tools = SocialTools(store)
            result = await tools.adjust_contact_attention(f"Person_{level}", level)
            assert result["success"] is True, f"Level '{level}' should be accepted"


# ---------------------------------------------------------------------------
# 5. TestObservationTool
# ---------------------------------------------------------------------------


class TestObservationTool:
    async def test_add_valid_observation(self, tmp_path: Path) -> None:
        store = SocialStore(tmp_path / "social")
        tools = SocialTools(store)
        result = await tools.add_learning_observation(
            observed="User mentioned Alice prefers morning calls",
            priority="important",
            relates_to="other_person",
            purpose="scheduling",
        )
        assert result["success"] is True
        assert "observation_id" in result

    async def test_observation_persisted(self, tmp_path: Path) -> None:
        store = SocialStore(tmp_path / "social")
        tools = SocialTools(store)
        await tools.add_learning_observation(
            observed="Test observation",
            priority="curious",
            relates_to="user",
            purpose="enrichment",
        )
        open_obs = await store.get_open_observations()
        assert len(open_obs) == 1
        assert open_obs[0].observed == "Test observation"

    async def test_invalid_priority_returns_error(self, tmp_path: Path) -> None:
        store = SocialStore(tmp_path / "social")
        tools = SocialTools(store)
        result = await tools.add_learning_observation(
            observed="something",
            priority="critical",  # invalid
            relates_to="user",
            purpose="scheduling",
        )
        assert result["success"] is False
        assert "Invalid priority" in result["error"]

    async def test_invalid_purpose_returns_error(self, tmp_path: Path) -> None:
        store = SocialStore(tmp_path / "social")
        tools = SocialTools(store)
        result = await tools.add_learning_observation(
            observed="something",
            priority="important",
            relates_to="user",
            purpose="gossip",  # invalid
        )
        assert result["success"] is False
        assert "Invalid purpose" in result["error"]

    async def test_all_valid_priorities_accepted(self, tmp_path: Path) -> None:
        store = SocialStore(tmp_path / "social")
        tools = SocialTools(store)
        for priority in ("blocking", "important", "curious"):
            result = await tools.add_learning_observation(
                observed=f"obs_{priority}",
                priority=priority,
                relates_to="user",
                purpose="enrichment",
            )
            assert result["success"] is True, f"Priority '{priority}' should be accepted"

    async def test_all_valid_purposes_accepted(self, tmp_path: Path) -> None:
        store = SocialStore(tmp_path / "social")
        tools = SocialTools(store)
        for purpose in ("scheduling", "social_obligation", "collaboration", "enrichment"):
            result = await tools.add_learning_observation(
                observed=f"obs_{purpose}",
                priority="curious",
                relates_to="user",
                purpose=purpose,
            )
            assert result["success"] is True, f"Purpose '{purpose}' should be accepted"

    async def test_observation_has_correct_source_session(self, tmp_path: Path) -> None:
        store = SocialStore(tmp_path / "social")
        tools = SocialTools(store)
        await tools.add_learning_observation(
            observed="something",
            priority="curious",
            relates_to="user",
            purpose="enrichment",
        )
        obs_list = await store.get_open_observations()
        assert obs_list[0].source_session == "agent:main:main"


# ---------------------------------------------------------------------------
# 6. TestUrgentNotification
# ---------------------------------------------------------------------------


class TestUrgentNotification:
    async def test_immediate_alert_fires_callback(self, tmp_path: Path) -> None:
        """A cycle that produces an immediate-urgency alert calls on_urgent_alert."""
        received: list[Any] = []

        async def callback(msg: Any) -> None:
            received.append(msg)

        store = SocialStore(tmp_path / "social")
        immediate_alert = _make_alert(urgency="immediate")
        await store.add_alert(immediate_alert)

        # Processor returns count=1 and has one immediate-urgency pending item
        proc = _OkProcessor(cycle_count=1, pending=[immediate_alert])
        scheduler = ProcessorScheduler(on_urgent_alert=callback)

        await scheduler._run_processor_cycle(proc)

        assert len(received) == 1

    async def test_callback_receives_universal_message(self, tmp_path: Path) -> None:
        """The callback argument is a valid UniversalMessage."""
        received: list[Any] = []

        async def callback(msg: Any) -> None:
            received.append(msg)

        immediate_alert = _make_alert(urgency="immediate")
        proc = _OkProcessor(cycle_count=1, pending=[immediate_alert])
        scheduler = ProcessorScheduler(on_urgent_alert=callback)

        await scheduler._run_processor_cycle(proc)

        assert len(received) == 1
        msg = received[0]
        assert isinstance(msg, UniversalMessage)
        assert msg.operation == "social_alert_urgent"
        assert msg.type == "event"
        assert msg.params["person"] == "Alice"

    async def test_low_urgency_alert_does_not_fire_callback(self) -> None:
        """A cycle with only low-urgency alerts does not invoke the callback."""
        received: list[Any] = []

        async def callback(msg: Any) -> None:
            received.append(msg)

        low_alert = _make_alert(urgency="low")
        proc = _OkProcessor(cycle_count=1, pending=[low_alert])
        scheduler = ProcessorScheduler(on_urgent_alert=callback)

        await scheduler._run_processor_cycle(proc)

        assert len(received) == 0

    async def test_no_callback_registered_does_not_raise(self) -> None:
        """Scheduler with no urgent callback runs cleanly even with immediate alerts."""
        immediate_alert = _make_alert(urgency="immediate")
        proc = _OkProcessor(cycle_count=1, pending=[immediate_alert])
        scheduler = ProcessorScheduler(on_urgent_alert=None)
        # Must not raise
        await scheduler._run_processor_cycle(proc)

    async def test_zero_count_skips_urgent_check(self) -> None:
        """If run_cycle returns 0, the urgent-alert check is skipped."""
        received: list[Any] = []

        async def callback(msg: Any) -> None:
            received.append(msg)

        immediate_alert = _make_alert(urgency="immediate")
        proc = _OkProcessor(cycle_count=0, pending=[immediate_alert])
        scheduler = ProcessorScheduler(on_urgent_alert=callback)

        await scheduler._run_processor_cycle(proc)

        # Even though pending has immediate alert, count=0 so check is skipped
        assert len(received) == 0


# ---------------------------------------------------------------------------
# 7. TestConfigIntegration
# ---------------------------------------------------------------------------


class TestConfigIntegration:
    def test_app_config_has_social_secretary_field(self) -> None:
        config = AppConfig()
        assert hasattr(config, "social_secretary")
        assert isinstance(config.social_secretary, SocialSecretaryConfig)

    def test_social_secretary_defaults(self) -> None:
        config = AppConfig()
        ss = config.social_secretary
        assert ss.enabled is False
        assert ss.cycle_interval_minutes == 120
        assert ss.max_alerts_per_cycle == 10

    def test_social_secretary_loaded_from_json(self, tmp_path: Path) -> None:
        config_file = tmp_path / "config.json"
        config_file.write_text(
            '{"social_secretary": {"enabled": true, "cycle_interval_minutes": 60}}',
            encoding="utf-8",
        )
        config = load_config(config_file)
        assert config.social_secretary.enabled is True
        assert config.social_secretary.cycle_interval_minutes == 60

    def test_missing_social_secretary_uses_defaults(self, tmp_path: Path) -> None:
        config_file = tmp_path / "config.json"
        config_file.write_text("{}", encoding="utf-8")
        config = load_config(config_file)
        assert config.social_secretary.enabled is False
