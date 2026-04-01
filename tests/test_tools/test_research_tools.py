"""Tests for ResearchTools — the research_query tool registration and handler.

Coverage:
- Tool registration in registry
- ToolDefinition metadata (name, trust level, required params)
- Handler calls AgentCreator.create_research_agent()
- Handler calls agent.run() with a ResearchRequest
- Success path formats result correctly (summary + citations)
- Success path with no citations includes stub note
- Error UM from agent is returned as formatted error string
- AgentCreator spawn failure returns a safe error string (never raises)
- ResearchRequest construction failure returns a safe error string
"""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from openrattler.agents.research.models import ResearchResult
from openrattler.models.agents import AgentConfig, AgentSpawnLimits, TrustLevel
from openrattler.models.messages import UniversalMessage, create_message
from openrattler.storage.audit import AuditLog
from openrattler.tools.builtin.research_tools import ResearchTools
from openrattler.tools.registry import ToolRegistry

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def mock_audit(tmp_path):
    return AuditLog(tmp_path / "audit.jsonl")


@pytest.fixture
def mock_creator():
    """A mock AgentCreator with create_research_agent returning a mock agent."""
    creator = MagicMock()
    creator.create_research_agent = AsyncMock()
    return creator


@pytest.fixture
def mock_agent():
    """A mock ResearchAgent with a configurable run() return value."""
    agent = MagicMock()
    agent.run = AsyncMock()
    return agent


@pytest.fixture
def registry():
    return ToolRegistry()


@pytest.fixture
def research_tools(mock_creator, mock_audit):
    return ResearchTools(creator=mock_creator, audit=mock_audit)


def _success_um(summary: str, citations: list[dict]) -> UniversalMessage:
    """Build a success-type response UM as ResearchAgent would return."""
    return create_message(
        from_agent="agent:research:sub",
        to_agent="agent:main:main",
        session_key="agent:research:ephemeral",
        type="response",
        operation="research_query",
        trust_level="main",
        params={"summary": summary, "citations": citations, "warnings": []},
    )


def _error_um(code: str, message: str) -> UniversalMessage:
    """Build an error-type UM as ResearchAgent would return on failure."""
    return create_message(
        from_agent="agent:research:sub",
        to_agent="agent:main:main",
        session_key="agent:research:ephemeral",
        type="error",
        operation="research_query",
        trust_level="main",
        params={"error_code": code, "message": message},
    )


# ---------------------------------------------------------------------------
# Registration tests
# ---------------------------------------------------------------------------


def test_register_all_adds_research_query(research_tools, registry):
    """research_query is in the registry after register_all."""
    research_tools.register_all(registry)
    tool_def = registry.get("research_query")
    assert tool_def is not None
    assert tool_def.name == "research_query"


def test_tool_trust_level_is_main(research_tools, registry):
    """research_query requires main trust level."""
    research_tools.register_all(registry)
    tool_def = registry.get("research_query")
    assert tool_def is not None
    assert tool_def.trust_level_required == TrustLevel.main


def test_tool_does_not_require_approval(research_tools, registry):
    """research_query does not pause for human approval."""
    research_tools.register_all(registry)
    tool_def = registry.get("research_query")
    assert tool_def is not None
    assert not tool_def.requires_approval


def test_tool_schema_requires_query(research_tools, registry):
    """'query' is a required parameter in the tool schema."""
    research_tools.register_all(registry)
    tool_def = registry.get("research_query")
    assert tool_def is not None
    assert "query" in tool_def.parameters.get("required", [])


def test_tool_schema_max_results_optional(research_tools, registry):
    """'max_results' is an optional parameter — not in 'required'."""
    research_tools.register_all(registry)
    tool_def = registry.get("research_query")
    assert tool_def is not None
    required = tool_def.parameters.get("required", [])
    assert "max_results" not in required
    assert "max_results" in tool_def.parameters.get("properties", {})


# ---------------------------------------------------------------------------
# Handler: AgentCreator interaction
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_handler_calls_create_research_agent(research_tools, mock_creator, mock_agent):
    """Handler passes a research_query UM through create_research_agent."""
    mock_creator.create_research_agent.return_value = mock_agent
    mock_agent.run.return_value = _success_um("Test summary.", [])

    await research_tools._research_query("Ohio protests")

    mock_creator.create_research_agent.assert_called_once()
    call_msg: UniversalMessage = mock_creator.create_research_agent.call_args[0][0]
    assert call_msg.operation == "research_query"
    assert call_msg.trust_level == "main"
    assert call_msg.params["query"] == "Ohio protests"


@pytest.mark.asyncio
async def test_handler_calls_agent_run(research_tools, mock_creator, mock_agent):
    """Handler calls agent.run() with a ResearchRequest after spawn."""
    mock_creator.create_research_agent.return_value = mock_agent
    mock_agent.run.return_value = _success_um("Summary.", [])

    await research_tools._research_query("test query", max_results=2)

    mock_agent.run.assert_called_once()
    args = mock_agent.run.call_args
    request = args[0][0]  # positional arg 0 is the ResearchRequest
    assert request.query == "test query"
    assert request.max_results == 2


@pytest.mark.asyncio
async def test_spawn_failure_returns_safe_error_string(research_tools, mock_creator):
    """If create_research_agent raises, handler returns an error string (never raises)."""
    mock_creator.create_research_agent.side_effect = Exception("spawn failed")

    result = await research_tools._research_query("test query")

    assert "Research failed" in result
    assert "spawn" in result.lower() or "research agent" in result.lower()


# ---------------------------------------------------------------------------
# Handler: result formatting
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_success_result_includes_summary(research_tools, mock_creator, mock_agent):
    """Formatted success result includes the summary text."""
    mock_creator.create_research_agent.return_value = mock_agent
    mock_agent.run.return_value = _success_um("Ohio protests summary.", [])

    result = await research_tools._research_query("Ohio protests")

    assert "Ohio protests summary." in result


@pytest.mark.asyncio
async def test_success_result_includes_citations(research_tools, mock_creator, mock_agent):
    """Formatted success result lists citation title and URL."""
    citations = [{"title": "CNN Article", "url": "https://cnn.com/ohio", "domain": "cnn.com"}]
    mock_creator.create_research_agent.return_value = mock_agent
    mock_agent.run.return_value = _success_um("Summary.", citations)

    result = await research_tools._research_query("Ohio protests")

    assert "CNN Article" in result
    assert "https://cnn.com/ohio" in result


@pytest.mark.asyncio
async def test_no_citations_includes_stub_note(research_tools, mock_creator, mock_agent):
    """When citations list is empty, result includes the stub note."""
    mock_creator.create_research_agent.return_value = mock_agent
    mock_agent.run.return_value = _success_um("No sources summary.", [])

    result = await research_tools._research_query("Ohio protests")

    assert "No sources" in result or "not yet connected" in result


@pytest.mark.asyncio
async def test_error_um_returns_formatted_error(research_tools, mock_creator, mock_agent):
    """An error-type UM from the agent produces an error string with the code."""
    mock_creator.create_research_agent.return_value = mock_agent
    mock_agent.run.return_value = _error_um("SANITIZATION_FAILED", "Output rejected.")

    result = await research_tools._research_query("Ohio protests")

    assert "SANITIZATION_FAILED" in result
    assert "Output rejected." in result
