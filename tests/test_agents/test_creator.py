"""Tests for AgentCreator — spawn limits, trust, isolation, retry, audit."""

from __future__ import annotations

from pathlib import Path

import pytest

from openrattler.agents.creator import AgentCreator
from openrattler.agents.creator_validator import (
    AUTHORIZED_SPAWNERS,
    SecurityError,
    SpawnLimitError,
)
from openrattler.models.agents import (
    AgentConfig,
    AgentCreationRequest,
    AgentSpawnLimits,
    TrustLevel,
)
from openrattler.storage.audit import AuditLog
from openrattler.tools.registry import ToolRegistry

# ---------------------------------------------------------------------------
# Shared helpers / fixtures
# ---------------------------------------------------------------------------

_SPAWNER = "agent:main:main"
_SESSION = "agent:main:main"


def _limits(**overrides: int) -> AgentSpawnLimits:
    defaults: dict = {
        "max_depth": 3,
        "max_children_per_agent": 5,
        "max_total_subagents_per_session": 20,
        "max_spawns_per_minute": 10,
        "max_spawns_per_hour": 50,
        "max_concurrent_agents": 10,
        "max_total_cost_per_spawn_chain": 1.00,
        "subagent_max_runtime_seconds": 300,
        "subagent_idle_timeout_seconds": 60,
        "max_retries_on_failure": 2,
        "retry_backoff_seconds": 5,
    }
    defaults.update(overrides)
    return AgentSpawnLimits(**defaults)


def _creator_config() -> AgentConfig:
    return AgentConfig(
        agent_id="agent:creator:system",
        name="Agent Creator",
        description="Creates subagents",
        model="anthropic/claude-haiku-4-5-20251001",
        trust_level=TrustLevel.security,
        can_spawn_subagents=False,
    )


def _make_creator(
    tmp_path: Path,
    registry: dict | None = None,
    limits: AgentSpawnLimits | None = None,
) -> tuple[AgentCreator, AuditLog]:
    audit_path = tmp_path / "audit.jsonl"
    audit_log = AuditLog(audit_path)
    reg: dict = registry if registry is not None else {}
    creator = AgentCreator(
        config=_creator_config(),
        spawn_limits=limits or _limits(),
        agent_registry=reg,
        audit_log=audit_log,
        tool_registry=ToolRegistry(),
    )
    return creator, audit_log


def _request(
    *,
    template: str = "research",
    depth: int = 0,
    custom_tools: list[str] | None = None,
    is_retry: bool = False,
    previous_agent_id: str | None = None,
    task_id: str | None = None,
    from_agent: str = _SPAWNER,
) -> AgentCreationRequest:
    return AgentCreationRequest(
        from_agent=from_agent,
        session_key=_SESSION,
        task="Research the NWS API",
        task_complexity=4,
        template=template,
        custom_tools=custom_tools or [],
        depth=depth,
        parent_agent=_SPAWNER,
        reason="User asked for weather info",
        original_user_message="What is the weather in Asheville?",
        is_retry=is_retry,
        previous_agent_id=previous_agent_id,
        task_id=task_id,
    )


# ---------------------------------------------------------------------------
# Basic creation
# ---------------------------------------------------------------------------


async def test_create_agent_returns_agent_config(tmp_path: Path) -> None:
    creator, _ = _make_creator(tmp_path)
    config = await creator.create_agent(_request())
    assert isinstance(config, AgentConfig)


async def test_created_agent_registered(tmp_path: Path) -> None:
    registry: dict = {}
    creator, _ = _make_creator(tmp_path, registry=registry)
    config = await creator.create_agent(_request())
    assert config.agent_id in registry


async def test_created_agent_uses_template_tools(tmp_path: Path) -> None:
    creator, _ = _make_creator(tmp_path)
    config = await creator.create_agent(_request(template="research"))
    assert "web_search" in config.allowed_tools
    assert "web_fetch" in config.allowed_tools


async def test_custom_tools_included(tmp_path: Path) -> None:
    creator, _ = _make_creator(tmp_path)
    config = await creator.create_agent(_request(custom_tools=["my_tool"]))
    assert "my_tool" in config.allowed_tools


async def test_custom_model_override(tmp_path: Path) -> None:
    creator, _ = _make_creator(tmp_path)
    req = _request()
    req = req.model_copy(update={"custom_model": "openai/gpt-4o"})
    config = await creator.create_agent(req)
    assert config.model == "openai/gpt-4o"


# ---------------------------------------------------------------------------
# Isolated session key
# ---------------------------------------------------------------------------


async def test_created_agent_has_isolated_session_key(tmp_path: Path) -> None:
    creator, _ = _make_creator(tmp_path)
    config = await creator.create_agent(_request())
    assert config.session_key is not None
    # Must be different from the parent session
    assert config.session_key != _SESSION
    # Must still be traceable to the parent (starts with parent session key)
    assert config.session_key.startswith(_SESSION)


async def test_two_agents_get_different_session_keys(tmp_path: Path) -> None:
    creator, _ = _make_creator(tmp_path)
    c1 = await creator.create_agent(_request())
    c2 = await creator.create_agent(_request())
    assert c1.session_key != c2.session_key


# ---------------------------------------------------------------------------
# Trust level never exceeds parent
# ---------------------------------------------------------------------------


async def test_created_agent_trust_capped_at_main(tmp_path: Path) -> None:
    """Main agent (trust=main) spawns subagent; subagent trust must be <= main."""
    registry: dict = {
        _SPAWNER: AgentConfig(
            agent_id=_SPAWNER,
            name="Main",
            description="main agent",
            model="anthropic/claude-sonnet-4-6",
            trust_level=TrustLevel.main,
        )
    }
    creator, _ = _make_creator(tmp_path, registry=registry)
    config = await creator.create_agent(_request())
    assert config.trust_level in (TrustLevel.public, TrustLevel.main)


async def test_public_spawner_trust_capped_at_public(tmp_path: Path) -> None:
    """A public-trust agent spawning from a registered public config gets public trust."""
    # Register the spawner with public trust
    registry: dict = {
        _SPAWNER: AgentConfig(
            agent_id=_SPAWNER,
            name="Public",
            description="public agent",
            model="openai/gpt-4o-mini",
            trust_level=TrustLevel.public,
        )
    }
    creator, _ = _make_creator(tmp_path, registry=registry)
    config = await creator.create_agent(_request())
    assert config.trust_level == TrustLevel.public


# ---------------------------------------------------------------------------
# Spawn depth limit
# ---------------------------------------------------------------------------


async def test_depth_limit_enforced(tmp_path: Path) -> None:
    creator, _ = _make_creator(tmp_path, limits=_limits(max_depth=2))
    with pytest.raises(SecurityError, match="depth"):
        await creator.create_agent(_request(depth=2))


async def test_depth_below_limit_allowed(tmp_path: Path) -> None:
    creator, _ = _make_creator(tmp_path, limits=_limits(max_depth=3))
    config = await creator.create_agent(_request(depth=2))
    assert config is not None


# ---------------------------------------------------------------------------
# Spawn width limit (max children per parent)
# ---------------------------------------------------------------------------


async def test_width_limit_enforced(tmp_path: Path) -> None:
    registry: dict = {}
    creator, _ = _make_creator(
        tmp_path, registry=registry, limits=_limits(max_children_per_agent=2)
    )
    # Create 2 children (fills the limit)
    c1 = await creator.create_agent(_request())
    c2 = await creator.create_agent(_request())
    # Third spawn should fail
    with pytest.raises(SecurityError, match="children"):
        await creator.create_agent(_request())


# ---------------------------------------------------------------------------
# Session-wide subagent limit
# ---------------------------------------------------------------------------


async def test_session_total_limit_enforced(tmp_path: Path) -> None:
    registry: dict = {}
    creator, _ = _make_creator(
        tmp_path,
        registry=registry,
        limits=_limits(max_total_subagents_per_session=2, max_children_per_agent=10),
    )
    await creator.create_agent(_request())
    await creator.create_agent(_request())
    with pytest.raises(SecurityError, match="subagents"):
        await creator.create_agent(_request())


# ---------------------------------------------------------------------------
# Rate limit
# ---------------------------------------------------------------------------


async def test_rate_limit_enforced(tmp_path: Path) -> None:
    registry: dict = {}
    creator, _ = _make_creator(
        tmp_path,
        registry=registry,
        limits=_limits(
            max_spawns_per_minute=2, max_children_per_agent=10, max_total_subagents_per_session=20
        ),
    )
    await creator.create_agent(_request())
    await creator.create_agent(_request())
    with pytest.raises(SecurityError, match="rate"):
        await creator.create_agent(_request())


# ---------------------------------------------------------------------------
# Unauthorised spawner
# ---------------------------------------------------------------------------


async def test_unauthorised_spawner_rejected(tmp_path: Path) -> None:
    creator, _ = _make_creator(tmp_path)
    with pytest.raises(SecurityError, match="authorised spawner"):
        await creator.create_agent(_request(from_agent="agent:evil:agent"))


# ---------------------------------------------------------------------------
# Unknown template
# ---------------------------------------------------------------------------


async def test_unknown_template_raises(tmp_path: Path) -> None:
    creator, _ = _make_creator(tmp_path)
    with pytest.raises(ValueError, match="template"):
        await creator.create_agent(_request(template="nonexistent"))


# ---------------------------------------------------------------------------
# Kill agent
# ---------------------------------------------------------------------------


async def test_kill_removes_from_registry(tmp_path: Path) -> None:
    registry: dict = {}
    creator, _ = _make_creator(tmp_path, registry=registry)
    config = await creator.create_agent(_request())
    assert config.agent_id in registry
    await creator.kill_agent(config.agent_id, reason="test")
    assert config.agent_id not in registry


async def test_kill_unknown_agent_raises(tmp_path: Path) -> None:
    creator, _ = _make_creator(tmp_path)
    with pytest.raises(ValueError, match="not found"):
        await creator.kill_agent("agent:nonexistent:xyz", reason="test")


async def test_kill_logs_audit_event(tmp_path: Path) -> None:
    creator, audit_log = _make_creator(tmp_path)
    config = await creator.create_agent(_request())
    await creator.kill_agent(config.agent_id, reason="done")
    events = await audit_log.query(event_type="subagent_killed")
    assert len(events) == 1
    assert events[0].agent_id == config.agent_id


# ---------------------------------------------------------------------------
# Retry logic
# ---------------------------------------------------------------------------


async def test_retry_kills_previous_agent(tmp_path: Path) -> None:
    registry: dict = {}
    creator, _ = _make_creator(tmp_path, registry=registry)
    first = await creator.create_agent(_request())
    assert first.agent_id in registry

    retry_req = _request(is_retry=True, previous_agent_id=first.agent_id)
    second = await creator.handle_retry(retry_req)

    assert first.agent_id not in registry, "Previous agent should be killed"
    assert second.agent_id in registry, "New agent should be registered"


async def test_retry_without_previous_id_creates_new(tmp_path: Path) -> None:
    registry: dict = {}
    creator, _ = _make_creator(tmp_path, registry=registry)
    first = await creator.create_agent(_request())
    initial_count = len(registry)

    retry_req = _request(is_retry=True)  # no previous_agent_id or task_id
    second = await creator.create_agent(retry_req)

    assert second.agent_id in registry
    assert second.agent_id != first.agent_id


# ---------------------------------------------------------------------------
# Audit log
# ---------------------------------------------------------------------------


async def test_creation_logged(tmp_path: Path) -> None:
    creator, audit_log = _make_creator(tmp_path)
    config = await creator.create_agent(_request())
    events = await audit_log.query(event_type="subagent_created")
    assert len(events) == 1
    assert events[0].agent_id == config.agent_id


async def test_denied_creation_logged(tmp_path: Path) -> None:
    creator, audit_log = _make_creator(tmp_path)
    with pytest.raises(SecurityError):
        await creator.create_agent(_request(from_agent="agent:bad:actor"))
    events = await audit_log.query(event_type="subagent_creation_denied")
    assert len(events) == 1


# ---------------------------------------------------------------------------
# list_agents
# ---------------------------------------------------------------------------


async def test_list_agents_returns_all(tmp_path: Path) -> None:
    creator, _ = _make_creator(tmp_path)
    await creator.create_agent(_request())
    await creator.create_agent(_request())
    agents = await creator.list_agents()
    assert len(agents) == 2


async def test_list_agents_filtered_by_session(tmp_path: Path) -> None:
    creator, _ = _make_creator(tmp_path)
    config = await creator.create_agent(_request())
    # Filter by parent session prefix — should find the subagent
    agents = await creator.list_agents(session_key=_SESSION)
    assert any(a.agent_id == config.agent_id for a in agents)


async def test_list_agents_empty_when_all_killed(tmp_path: Path) -> None:
    creator, _ = _make_creator(tmp_path)
    config = await creator.create_agent(_request())
    await creator.kill_agent(config.agent_id, reason="cleanup")
    agents = await creator.list_agents()
    assert agents == []
