"""Tests for TrustLevel, AgentConfig, TaskTemplate, AgentCreationRequest, AgentSpawnLimits."""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from openrattler.models.agents import (
    AgentConfig,
    AgentCreationRequest,
    AgentSpawnLimits,
    TaskTemplate,
    TrustLevel,
)

# ---------------------------------------------------------------------------
# TrustLevel
# ---------------------------------------------------------------------------


class TestTrustLevel:
    def test_all_values_present(self) -> None:
        names = {m.value for m in TrustLevel}
        assert names == {"public", "main", "local", "security", "mcp"}

    def test_is_string_enum(self) -> None:
        assert TrustLevel.main == "main"
        assert TrustLevel.public == "public"

    def test_comparison_with_string(self) -> None:
        # str enum — can compare directly to string literals
        assert TrustLevel.main == "main"
        assert TrustLevel.local != "main"


# ---------------------------------------------------------------------------
# AgentConfig
# ---------------------------------------------------------------------------


_MINIMAL_CONFIG = dict(
    agent_id="agent:main:main",
    name="Main Agent",
    description="Personal assistant",
    model="anthropic/claude-sonnet-4.5",
    trust_level=TrustLevel.main,
)


class TestAgentConfig:
    def test_minimal_config(self) -> None:
        cfg = AgentConfig(**_MINIMAL_CONFIG)
        assert cfg.agent_id == "agent:main:main"
        assert cfg.trust_level == TrustLevel.main

    def test_defaults(self) -> None:
        cfg = AgentConfig(**_MINIMAL_CONFIG)
        assert cfg.model_selection == "fixed"
        assert cfg.fallback_models == []
        assert cfg.allowed_tools == []
        assert cfg.denied_tools == []
        assert cfg.can_spawn_subagents is False
        assert cfg.max_cost_per_turn is None
        assert cfg.session_key is None
        assert cfg.workspace is None
        assert cfg.system_prompt == ""
        assert cfg.memory_files == []

    def test_full_config(self) -> None:
        cfg = AgentConfig(
            agent_id="agent:main:main",
            name="Main Agent",
            description="Handles personal DMs",
            model="anthropic/claude-sonnet-4.5",
            model_selection="adaptive",
            fallback_models=["anthropic/claude-haiku-4.5", "openai/gpt-4o-mini"],
            allowed_tools=["web_search", "file_read"],
            denied_tools=["exec"],
            trust_level=TrustLevel.main,
            can_spawn_subagents=True,
            max_cost_per_turn=0.50,
            session_key="agent:main:main",
            workspace="/home/user/.openrattler/workspace",
            system_prompt="You are a helpful assistant.",
            memory_files=["AGENTS.md", "USER.md"],
        )
        assert cfg.can_spawn_subagents is True
        assert cfg.max_cost_per_turn == 0.50
        assert "web_search" in cfg.allowed_tools
        assert "exec" in cfg.denied_tools

    def test_invalid_trust_level_rejected(self) -> None:
        with pytest.raises(ValidationError):
            AgentConfig(**{**_MINIMAL_CONFIG, "trust_level": "admin"})  # type: ignore[arg-type]

    def test_invalid_model_selection_rejected(self) -> None:
        with pytest.raises(ValidationError):
            AgentConfig(**{**_MINIMAL_CONFIG, "model_selection": "random"})  # type: ignore[arg-type]

    def test_all_model_selections_valid(self) -> None:
        for sel in ("fixed", "cost_optimized", "quality_optimized", "adaptive"):
            cfg = AgentConfig(**{**_MINIMAL_CONFIG, "model_selection": sel})  # type: ignore[arg-type]
            assert cfg.model_selection == sel

    def test_all_trust_levels_valid(self) -> None:
        for level in TrustLevel:
            cfg = AgentConfig(**{**_MINIMAL_CONFIG, "trust_level": level})
            assert cfg.trust_level == level

    def test_missing_required_field_raises(self) -> None:
        with pytest.raises(ValidationError):
            AgentConfig(
                agent_id="agent:main:main",
                name="Main",
                description="desc",
                # model missing
                trust_level=TrustLevel.main,
            )

    def test_round_trip(self) -> None:
        cfg = AgentConfig(**_MINIMAL_CONFIG)
        data = cfg.model_dump()
        restored = AgentConfig.model_validate(data)
        assert restored == cfg


# ---------------------------------------------------------------------------
# TaskTemplate
# ---------------------------------------------------------------------------


_MINIMAL_TEMPLATE = dict(
    name="research",
    description="Search and synthesise information",
    system_prompt="You are a research specialist.",
    required_tools=["web_search", "web_fetch"],
    suggested_model="openai/gpt-4o-mini",
    typical_complexity_range=(3, 7),
)


class TestTaskTemplate:
    def test_minimal_template(self) -> None:
        t = TaskTemplate(**_MINIMAL_TEMPLATE)
        assert t.name == "research"
        assert t.typical_complexity_range == (3, 7)

    def test_defaults(self) -> None:
        t = TaskTemplate(**_MINIMAL_TEMPLATE)
        assert t.suggested_cost_limit == 0.10
        assert t.workflow is None

    def test_with_workflow(self) -> None:
        t = TaskTemplate(**{**_MINIMAL_TEMPLATE, "workflow": ["Search", "Fetch", "Summarize"]})
        assert t.workflow is not None
        assert len(t.workflow) == 3

    def test_complexity_range_min_greater_than_max_raises(self) -> None:
        with pytest.raises(ValidationError):
            TaskTemplate(**{**_MINIMAL_TEMPLATE, "typical_complexity_range": (8, 3)})

    def test_complexity_range_out_of_bounds_raises(self) -> None:
        with pytest.raises(ValidationError):
            TaskTemplate(**{**_MINIMAL_TEMPLATE, "typical_complexity_range": (-1, 5)})

    def test_complexity_range_equal_min_max_valid(self) -> None:
        t = TaskTemplate(**{**_MINIMAL_TEMPLATE, "typical_complexity_range": (5, 5)})
        assert t.typical_complexity_range == (5, 5)

    def test_complexity_boundary_values_valid(self) -> None:
        t = TaskTemplate(**{**_MINIMAL_TEMPLATE, "typical_complexity_range": (0, 10)})
        assert t.typical_complexity_range == (0, 10)

    def test_round_trip(self) -> None:
        t = TaskTemplate(**_MINIMAL_TEMPLATE)
        data = t.model_dump()
        restored = TaskTemplate.model_validate(data)
        assert restored == t


# ---------------------------------------------------------------------------
# AgentCreationRequest
# ---------------------------------------------------------------------------


_MINIMAL_REQUEST = dict(
    from_agent="agent:main:main",
    session_key="agent:main:main",
    task="Research NWS API docs",
    task_complexity=4,
    template="research",
    depth=1,
    parent_agent="agent:main:main",
    reason="User asked about weather",
    original_user_message="What is the weather in Asheville next week?",
)


class TestAgentCreationRequest:
    def test_minimal_request(self) -> None:
        req = AgentCreationRequest(**_MINIMAL_REQUEST)
        assert req.template == "research"
        assert req.depth == 1
        assert req.is_retry is False

    def test_defaults(self) -> None:
        req = AgentCreationRequest(**_MINIMAL_REQUEST)
        assert req.custom_tools == []
        assert req.custom_model is None
        assert req.max_cost_per_turn is None
        assert req.max_runtime_seconds == 300
        assert req.is_retry is False
        assert req.previous_agent_id is None
        assert req.task_id is None

    def test_complexity_out_of_range_raises(self) -> None:
        with pytest.raises(ValidationError):
            AgentCreationRequest(**{**_MINIMAL_REQUEST, "task_complexity": 11})

    def test_complexity_negative_raises(self) -> None:
        with pytest.raises(ValidationError):
            AgentCreationRequest(**{**_MINIMAL_REQUEST, "task_complexity": -1})

    def test_complexity_boundary_values_valid(self) -> None:
        for v in (0, 10):
            req = AgentCreationRequest(**{**_MINIMAL_REQUEST, "task_complexity": v})
            assert req.task_complexity == v

    def test_retry_fields(self) -> None:
        req = AgentCreationRequest(
            **{
                **_MINIMAL_REQUEST,
                "is_retry": True,
                "previous_agent_id": "agent:research:subagent:old-uuid",
                "task_id": "task-abc",
            }
        )
        assert req.is_retry is True
        assert req.previous_agent_id == "agent:research:subagent:old-uuid"

    def test_custom_tools_set(self) -> None:
        req = AgentCreationRequest(**{**_MINIMAL_REQUEST, "custom_tools": ["exec"]})
        assert "exec" in req.custom_tools

    def test_round_trip(self) -> None:
        req = AgentCreationRequest(**_MINIMAL_REQUEST)
        data = req.model_dump()
        restored = AgentCreationRequest.model_validate(data)
        assert restored == req


# ---------------------------------------------------------------------------
# AgentSpawnLimits
# ---------------------------------------------------------------------------


class TestAgentSpawnLimits:
    def test_default_values(self) -> None:
        limits = AgentSpawnLimits()
        assert limits.max_depth == 3
        assert limits.max_children_per_agent == 5
        assert limits.max_total_subagents_per_session == 20
        assert limits.max_spawns_per_minute == 10
        assert limits.max_spawns_per_hour == 50
        assert limits.max_concurrent_agents == 10
        assert limits.max_total_cost_per_spawn_chain == 1.00
        assert limits.subagent_max_runtime_seconds == 300
        assert limits.subagent_idle_timeout_seconds == 60
        assert limits.max_retries_on_failure == 2
        assert limits.retry_backoff_seconds == 5

    def test_custom_limits(self) -> None:
        limits = AgentSpawnLimits(max_depth=5, max_children_per_agent=10)
        assert limits.max_depth == 5
        assert limits.max_children_per_agent == 10
        # unchanged defaults
        assert limits.max_spawns_per_minute == 10

    def test_round_trip(self) -> None:
        limits = AgentSpawnLimits()
        data = limits.model_dump()
        restored = AgentSpawnLimits.model_validate(data)
        assert restored == limits
