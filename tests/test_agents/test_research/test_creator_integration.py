"""Tests for AgentCreator.create_research_agent integration.

Security guarantees verified here:
- AgentCreator recognizes "research_query" as a valid operation.
- AgentCreator rejects spawn with invalid ResearchRequest params.
- AgentCreator rejects spawn from trust level below main ("public").
- AgentCreator rejects model override not in APPROVED_RESEARCH_MODELS.
- AgentCreator accepts a valid spawn request and returns a ResearchAgent instance.
"""

from __future__ import annotations

import uuid
from pathlib import Path
from typing import Any

import pytest

from openrattler.agents.creator import AgentCreator
from openrattler.agents.creator_validator import SecurityError
from openrattler.agents.research.agent import ResearchAgent
from openrattler.agents.research.config import APPROVED_RESEARCH_MODELS
from openrattler.models.agents import AgentConfig, AgentSpawnLimits, TrustLevel
from openrattler.models.messages import create_message
from openrattler.storage.audit import AuditLog
from openrattler.tools.registry import ToolRegistry

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_creator(tmp_path: Path) -> tuple[AgentCreator, AuditLog]:
    audit = AuditLog(tmp_path / "creator_audit.jsonl")
    creator_config = AgentConfig(
        agent_id="agent:creator:system",
        name="Agent Creator",
        description="Creates subagents",
        model="anthropic/claude-haiku-4-5-20251001",
        trust_level=TrustLevel.security,
        can_spawn_subagents=False,
    )
    limits = AgentSpawnLimits(
        max_depth=3,
        max_children_per_agent=5,
        max_total_subagents_per_session=20,
        max_spawns_per_minute=10,
        max_spawns_per_hour=50,
        max_concurrent_agents=10,
        max_total_cost_per_spawn_chain=1.00,
        subagent_max_runtime_seconds=300,
        subagent_idle_timeout_seconds=60,
        max_retries_on_failure=2,
        retry_backoff_seconds=5,
    )
    creator = AgentCreator(
        config=creator_config,
        spawn_limits=limits,
        agent_registry={},
        audit_log=audit,
        tool_registry=ToolRegistry(),
    )
    return creator, audit


def _make_research_um(
    trust_level: str = "main",
    params: dict[str, Any] | None = None,
    metadata: dict[str, Any] | None = None,
) -> Any:
    """Build a research_query UniversalMessage."""
    return create_message(
        from_agent="agent:main:main",
        to_agent="agent:creator:system",
        session_key="agent:main:main",
        type="request",
        operation="research_query",
        trust_level=trust_level,  # type: ignore[arg-type]
        params=(
            params
            if params is not None
            else {
                "query": "Python async best practices",
                "max_results": 3,
            }
        ),
        metadata=metadata or {},
        trace_id=str(uuid.uuid4()),
    )


def _make_research_audit(tmp_path: Path) -> AuditLog:
    """Separate audit log for the ResearchAgent session."""
    return AuditLog(tmp_path / "research_audit.jsonl")


# ---------------------------------------------------------------------------
# Operation recognition
# ---------------------------------------------------------------------------


class TestOperationRecognition:
    """AgentCreator recognizes research_query as a valid spawnable operation."""

    async def test_recognizes_research_query_operation(self, tmp_path: Path) -> None:
        """create_research_agent accepts operation='research_query'."""
        creator, _ = _make_creator(tmp_path)
        research_audit = _make_research_audit(tmp_path)
        message = _make_research_um()
        print(f"[TestOperationRecognition] operation={message.operation!r}")
        # Should not raise ValueError about unknown operation
        agent = await creator.create_research_agent(message, research_audit)
        assert isinstance(agent, ResearchAgent)

    async def test_rejects_wrong_operation(self, tmp_path: Path) -> None:
        """create_research_agent raises ValueError for non-research_query operations."""
        creator, _ = _make_creator(tmp_path)
        research_audit = _make_research_audit(tmp_path)
        message = _make_research_um()
        # Manually override operation
        object.__setattr__(message, "operation", "send_email")
        print(f"[TestOperationRecognition] wrong operation={message.operation!r}")
        with pytest.raises(ValueError) as exc_info:
            await creator.create_research_agent(message, research_audit)
        assert "research_query" in str(exc_info.value)


# ---------------------------------------------------------------------------
# Trust level enforcement
# ---------------------------------------------------------------------------


class TestTrustLevelEnforcement:
    """Spawn requests from trust level below main are rejected."""

    async def test_rejects_spawn_from_public_trust_level(self, tmp_path: Path) -> None:
        creator, _ = _make_creator(tmp_path)
        research_audit = _make_research_audit(tmp_path)
        message = _make_research_um(trust_level="public")
        print(f"[TestTrustLevel] trust_level={message.trust_level!r}")
        with pytest.raises(SecurityError) as exc_info:
            await creator.create_research_agent(message, research_audit)
        assert "main" in str(exc_info.value).lower() or "trust" in str(exc_info.value).lower()

    async def test_accepts_main_trust_level(self, tmp_path: Path) -> None:
        creator, _ = _make_creator(tmp_path)
        research_audit = _make_research_audit(tmp_path)
        message = _make_research_um(trust_level="main")
        print(f"[TestTrustLevel] main trust accepted")
        agent = await creator.create_research_agent(message, research_audit)
        assert isinstance(agent, ResearchAgent)

    async def test_accepts_local_trust_level(self, tmp_path: Path) -> None:
        creator, _ = _make_creator(tmp_path)
        research_audit = _make_research_audit(tmp_path)
        message = _make_research_um(trust_level="local")
        print(f"[TestTrustLevel] local trust accepted")
        agent = await creator.create_research_agent(message, research_audit)
        assert isinstance(agent, ResearchAgent)


# ---------------------------------------------------------------------------
# Params validation
# ---------------------------------------------------------------------------


class TestParamsValidation:
    """AgentCreator rejects invalid ResearchRequest params."""

    async def test_rejects_missing_query(self, tmp_path: Path) -> None:
        creator, _ = _make_creator(tmp_path)
        research_audit = _make_research_audit(tmp_path)
        message = _make_research_um(params={"max_results": 3})  # missing required 'query'
        print(f"[TestParamsValidation] missing query field")
        with pytest.raises(ValueError) as exc_info:
            await creator.create_research_agent(message, research_audit)
        assert "ResearchRequest" in str(exc_info.value) or "query" in str(exc_info.value).lower()

    async def test_rejects_query_over_300_chars(self, tmp_path: Path) -> None:
        creator, _ = _make_creator(tmp_path)
        research_audit = _make_research_audit(tmp_path)
        message = _make_research_um(params={"query": "q" * 301, "max_results": 3})
        print(f"[TestParamsValidation] query > 300 chars")
        with pytest.raises(ValueError):
            await creator.create_research_agent(message, research_audit)

    async def test_rejects_max_results_out_of_range(self, tmp_path: Path) -> None:
        creator, _ = _make_creator(tmp_path)
        research_audit = _make_research_audit(tmp_path)
        message = _make_research_um(params={"query": "test", "max_results": 99})
        print(f"[TestParamsValidation] max_results=99 out of range")
        with pytest.raises(ValueError):
            await creator.create_research_agent(message, research_audit)


# ---------------------------------------------------------------------------
# Model override validation
# ---------------------------------------------------------------------------


class TestModelOverrideValidation:
    """Model overrides must be in APPROVED_RESEARCH_MODELS."""

    async def test_rejects_model_not_in_allowlist(self, tmp_path: Path) -> None:
        creator, _ = _make_creator(tmp_path)
        research_audit = _make_research_audit(tmp_path)
        message = _make_research_um(metadata={"model": "openai/gpt-4o"})
        print(f"[TestModelOverride] rejected model: openai/gpt-4o")
        with pytest.raises(SecurityError) as exc_info:
            await creator.create_research_agent(message, research_audit)
        assert (
            "allowlist" in str(exc_info.value).lower() or "approved" in str(exc_info.value).lower()
        )

    async def test_accepts_approved_model_override(self, tmp_path: Path) -> None:
        creator, _ = _make_creator(tmp_path)
        research_audit = _make_research_audit(tmp_path)
        # Pick the first approved model (not the default)
        approved = sorted(APPROVED_RESEARCH_MODELS)[0]
        message = _make_research_um(metadata={"model": approved})
        print(f"[TestModelOverride] approved model override: {approved!r}")
        agent = await creator.create_research_agent(message, research_audit)
        assert isinstance(agent, ResearchAgent)
        assert agent._config.model == approved

    async def test_no_model_override_uses_default(self, tmp_path: Path) -> None:
        creator, _ = _make_creator(tmp_path)
        research_audit = _make_research_audit(tmp_path)
        message = _make_research_um()  # no metadata.model
        agent = await creator.create_research_agent(message, research_audit)
        print(f"[TestModelOverride] default model: {agent._config.model!r}")
        assert agent._config.model == "anthropic/claude-haiku-4-5-20251001"


# ---------------------------------------------------------------------------
# Successful spawn
# ---------------------------------------------------------------------------


class TestSuccessfulSpawn:
    """Valid spawn request returns a ResearchAgent instance."""

    async def test_returns_research_agent_instance(self, tmp_path: Path) -> None:
        creator, _ = _make_creator(tmp_path)
        research_audit = _make_research_audit(tmp_path)
        message = _make_research_um()
        print(f"[TestSuccessfulSpawn] spawning research agent")
        agent = await creator.create_research_agent(message, research_audit)
        print(f"[TestSuccessfulSpawn] got: {type(agent).__name__}")
        assert isinstance(agent, ResearchAgent)

    async def test_spawned_agent_has_correct_tool_allowlist(self, tmp_path: Path) -> None:
        creator, _ = _make_creator(tmp_path)
        research_audit = _make_research_audit(tmp_path)
        message = _make_research_um()
        agent = await creator.create_research_agent(message, research_audit)
        print(f"[TestSuccessfulSpawn] allowed_tools: {agent.allowed_tools}")
        assert agent.allowed_tools == frozenset({"web_search", "web_fetch"})

    async def test_audit_log_receives_spawn_entry(self, tmp_path: Path) -> None:
        import json

        creator, creator_audit = _make_creator(tmp_path)
        research_audit = _make_research_audit(tmp_path)
        message = _make_research_um()
        await creator.create_research_agent(message, research_audit)

        audit_path = tmp_path / "creator_audit.jsonl"
        entries = [json.loads(line) for line in audit_path.read_text().splitlines() if line.strip()]
        print(f"[TestSuccessfulSpawn] audit entries: {[e['event'] for e in entries]}")
        spawn_entries = [e for e in entries if e["event"] == "research_agent_spawned"]
        assert len(spawn_entries) == 1
        assert spawn_entries[0]["details"]["query"] == "Python async best practices"
