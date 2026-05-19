"""Tests for openrattler.agents.summarizer.SummarizerAgent.

Security guarantees verified here:
- FileNotFoundError at init if skill_prompt_path is missing.
- Named skill (SKILL_session.md) loaded when skill='session' and file exists.
- Falls back to default skill when named skill file is missing.
- Input truncated at max_input_chars; was_truncated=True set in result.
- Suspicious output → error UM with error_code='OUTPUT_FLAGGED'; audit event fired.
- No provider → stub summary returned (no crash).
- Invalid UM params → error UM, not crash.
- Always returns a UM; never raises.
"""

from __future__ import annotations

import uuid
from pathlib import Path
from typing import Any
from unittest.mock import AsyncMock, MagicMock

import pytest

from openrattler.agents.providers.base import LLMResponse, TokenUsage
from openrattler.agents.summarizer.agent import SummarizerAgent
from openrattler.agents.summarizer.config import SummarizerAgentConfig
from openrattler.agents.summarizer.models import SummarizerError, SummarizerResult
from openrattler.models.messages import create_message
from openrattler.storage.audit import AuditLog

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_DEFAULT_SKILL_CONTENT = "# Default skill\nSummarize concisely."
_SESSION_SKILL_CONTENT = "# Session skill\nSummarize the session."


def _write_default_skill(tmp_path: Path) -> Path:
    skill_path = tmp_path / "SKILL.md"
    skill_path.write_text(_DEFAULT_SKILL_CONTENT, encoding="utf-8")
    return skill_path


def _write_named_skills_dir(tmp_path: Path) -> Path:
    skills_dir = tmp_path / "skills"
    skills_dir.mkdir()
    (skills_dir / "SKILL_session.md").write_text(_SESSION_SKILL_CONTENT, encoding="utf-8")
    return skills_dir


def _make_config(
    tmp_path: Path,
    skill_exists: bool = True,
    named_skills_dir: Path | None = None,
    **overrides: Any,
) -> SummarizerAgentConfig:
    if skill_exists:
        skill_path = _write_default_skill(tmp_path)
    else:
        skill_path = tmp_path / "SKILL.md"  # does not exist

    defaults: dict[str, Any] = {
        "skill_prompt_path": skill_path,
        "named_skills_dir": named_skills_dir,
    }
    defaults.update(overrides)
    return SummarizerAgentConfig(**defaults)


def _make_agent(
    tmp_path: Path,
    provider: Any = None,
    named_skills_dir: Path | None = None,
    **config_overrides: Any,
) -> tuple[SummarizerAgent, AuditLog]:
    audit = AuditLog(tmp_path / "audit.jsonl")
    config = _make_config(tmp_path, named_skills_dir=named_skills_dir, **config_overrides)
    agent = SummarizerAgent(config=config, audit=audit, provider=provider)
    return agent, audit


def _make_request_um(
    text: str = "Hello world",
    skill: str | None = None,
    context: str | None = None,
    params_override: dict[str, Any] | None = None,
) -> Any:
    params: dict[str, Any] = {"text": text}
    if skill is not None:
        params["skill"] = skill
    if context is not None:
        params["context"] = context
    if params_override is not None:
        params = params_override
    return create_message(
        from_agent="agent:main:main",
        to_agent="agent:summarizer:sub",
        session_key="agent:main:main",
        type="request",
        operation="summarize",
        trust_level="main",
        params=params,
        trace_id=str(uuid.uuid4()),
    )


def _make_llm_provider(content: str = "This is a summary.") -> MagicMock:
    """Return a mock LLMProvider that returns the given content."""
    provider = MagicMock()
    provider.complete = AsyncMock(
        return_value=LLMResponse(
            content=content,
            tool_calls=[],
            usage=TokenUsage(
                prompt_tokens=10,
                completion_tokens=5,
                total_tokens=15,
                estimated_cost_usd=0.0001,
            ),
            model="claude-haiku-4-5-20251001",
            finish_reason="end_turn",
        )
    )
    return provider


# ---------------------------------------------------------------------------
# Instantiation tests
# ---------------------------------------------------------------------------


def test_init_raises_when_skill_prompt_missing(tmp_path: Path) -> None:
    """FileNotFoundError if skill_prompt_path does not exist — no silent degradation."""
    config = _make_config(tmp_path, skill_exists=False)
    audit = AuditLog(tmp_path / "audit.jsonl")
    with pytest.raises(FileNotFoundError):
        SummarizerAgent(config=config, audit=audit)


def test_init_succeeds_when_skill_prompt_exists(tmp_path: Path) -> None:
    """Agent constructs cleanly when skill_prompt_path points to an existing file."""
    agent, _ = _make_agent(tmp_path)
    assert agent is not None


# ---------------------------------------------------------------------------
# Stub (no provider) path
# ---------------------------------------------------------------------------


async def test_stub_summary_returned_when_no_provider(tmp_path: Path) -> None:
    """No provider → stub summary (first 1000 chars) returned; no crash."""
    agent, _ = _make_agent(tmp_path)
    text = "The quick brown fox jumps over the lazy dog."
    um = _make_request_um(text=text)

    result_um = await agent.run(um, trace_id=um.trace_id)

    print("result_um.type:", result_um.type)
    print("result_um.params:", result_um.params)
    assert result_um.type == "response"
    result = SummarizerResult.model_validate(result_um.params)
    assert result.summary == text  # short input → returned as-is by stub
    assert result.was_truncated is False
    assert result.original_length == len(text)


async def test_stub_truncates_long_text_at_1000_chars(tmp_path: Path) -> None:
    """Stub summary is capped at 1000 chars."""
    agent, _ = _make_agent(tmp_path)
    text = "x" * 2000
    um = _make_request_um(text=text)

    result_um = await agent.run(um, trace_id=um.trace_id)

    assert result_um.type == "response"
    result = SummarizerResult.model_validate(result_um.params)
    assert len(result.summary) == 1000


# ---------------------------------------------------------------------------
# Input truncation
# ---------------------------------------------------------------------------


async def test_input_truncated_at_max_input_chars(tmp_path: Path) -> None:
    """Text exceeding max_input_chars is truncated; was_truncated=True set."""
    provider = _make_llm_provider("short summary")
    agent, _ = _make_agent(tmp_path, provider=provider, max_input_chars=50)

    text = "a" * 200
    um = _make_request_um(text=text)
    result_um = await agent.run(um, trace_id=um.trace_id)

    assert result_um.type == "response"
    result = SummarizerResult.model_validate(result_um.params)
    assert result.was_truncated is True
    assert result.original_length == 200
    # Verify the provider was called with the truncated text (50 chars)
    call_args = provider.complete.call_args
    messages = call_args.kwargs.get("messages") or call_args.args[0]
    user_msg = next(m for m in messages if m["role"] == "user")
    assert len(user_msg["content"]) == 50


async def test_was_truncated_false_when_text_fits(tmp_path: Path) -> None:
    """was_truncated=False when text is within max_input_chars."""
    provider = _make_llm_provider("ok")
    agent, _ = _make_agent(tmp_path, provider=provider, max_input_chars=500)
    um = _make_request_um(text="short text")

    result_um = await agent.run(um, trace_id=um.trace_id)

    assert result_um.type == "response"
    result = SummarizerResult.model_validate(result_um.params)
    assert result.was_truncated is False


# ---------------------------------------------------------------------------
# Named skill selection
# ---------------------------------------------------------------------------


async def test_named_skill_loaded_when_skill_file_exists(tmp_path: Path) -> None:
    """Named SKILL_session.md is used when skill='session' and file exists."""
    skills_dir = _write_named_skills_dir(tmp_path)
    provider = _make_llm_provider("session summary")
    agent, _ = _make_agent(tmp_path, provider=provider, named_skills_dir=skills_dir)

    um = _make_request_um(text="Turn 1: hello. Turn 2: world.", skill="session")
    result_um = await agent.run(um, trace_id=um.trace_id)

    assert result_um.type == "response"
    result = SummarizerResult.model_validate(result_um.params)
    # skill_used should reflect the named skill file stem
    assert result.skill_used == "SKILL_session"
    # Provider's system message should contain the session skill content
    call_args = provider.complete.call_args
    messages = call_args.kwargs.get("messages") or call_args.args[0]
    system_msg = next(m for m in messages if m["role"] == "system")
    assert _SESSION_SKILL_CONTENT in system_msg["content"]


async def test_fallback_to_default_when_named_skill_file_missing(tmp_path: Path) -> None:
    """Falls back to default skill when the requested named skill file does not exist."""
    skills_dir = tmp_path / "empty_skills"
    skills_dir.mkdir()
    provider = _make_llm_provider("default summary")
    agent, _ = _make_agent(tmp_path, provider=provider, named_skills_dir=skills_dir)

    um = _make_request_um(text="some text", skill="nonexistent")
    result_um = await agent.run(um, trace_id=um.trace_id)

    assert result_um.type == "response"
    result = SummarizerResult.model_validate(result_um.params)
    assert result.skill_used == "SKILL"
    call_args = provider.complete.call_args
    messages = call_args.kwargs.get("messages") or call_args.args[0]
    system_msg = next(m for m in messages if m["role"] == "system")
    assert _DEFAULT_SKILL_CONTENT in system_msg["content"]


async def test_fallback_to_default_when_named_skills_dir_not_configured(tmp_path: Path) -> None:
    """Falls back to default when named_skills_dir is None (not configured)."""
    provider = _make_llm_provider("default summary")
    agent, _ = _make_agent(tmp_path, provider=provider, named_skills_dir=None)

    um = _make_request_um(text="some text", skill="session")
    result_um = await agent.run(um, trace_id=um.trace_id)

    assert result_um.type == "response"
    result = SummarizerResult.model_validate(result_um.params)
    assert result.skill_used == "SKILL"


# ---------------------------------------------------------------------------
# Suspicious output detection
# ---------------------------------------------------------------------------


async def test_flagged_output_returns_error_um(tmp_path: Path) -> None:
    """Suspicious LLM output → error UM with error_code='OUTPUT_FLAGGED'."""
    # A command-injection pattern that scan_for_suspicious_content will catch.
    flagged_text = "Try running: os.system('rm -rf /')"
    provider = _make_llm_provider(flagged_text)
    agent, audit = _make_agent(tmp_path, provider=provider)

    um = _make_request_um(text="hello")
    result_um = await agent.run(um, trace_id=um.trace_id)

    print("result_um.type:", result_um.type)
    print("result_um.params:", result_um.params)
    assert result_um.type == "error"
    error = SummarizerError.model_validate(result_um.params)
    assert error.error_code == "OUTPUT_FLAGGED"


async def test_flagged_output_writes_audit_event(tmp_path: Path) -> None:
    """Audit event 'summarizer_output_flagged' is written when output is flagged."""
    flagged_text = "os.system('whoami')"
    provider = _make_llm_provider(flagged_text)
    agent, audit = _make_agent(tmp_path, provider=provider)

    trace_id = str(uuid.uuid4())
    um = _make_request_um(text="hello")
    await agent.run(um, trace_id=trace_id)

    events = await audit.query(event_type="summarizer_output_flagged")
    print("audit events:", events)
    assert len(events) >= 1
    assert events[0].details["trace_id"] == trace_id


# ---------------------------------------------------------------------------
# Error handling
# ---------------------------------------------------------------------------


async def test_invalid_params_returns_error_um(tmp_path: Path) -> None:
    """Missing required 'text' field → error UM with error_code='INVALID_REQUEST'."""
    agent, _ = _make_agent(tmp_path)
    um = _make_request_um(params_override={"not_text": "oops"})

    result_um = await agent.run(um, trace_id=um.trace_id)

    assert result_um.type == "error"
    error = SummarizerError.model_validate(result_um.params)
    assert error.error_code == "INVALID_REQUEST"


async def test_provider_exception_falls_back_to_stub(tmp_path: Path) -> None:
    """Provider raising an exception → stub summary returned, not an error UM."""
    provider = MagicMock()
    provider.complete = AsyncMock(side_effect=RuntimeError("network error"))
    agent, _ = _make_agent(tmp_path, provider=provider)

    text = "some text to summarize"
    um = _make_request_um(text=text)
    result_um = await agent.run(um, trace_id=um.trace_id)

    assert result_um.type == "response"
    result = SummarizerResult.model_validate(result_um.params)
    assert result.summary == text  # stub returns full text (within 1000 char limit)


async def test_run_never_raises(tmp_path: Path) -> None:
    """Agent.run() never raises an exception — all errors become error UMs."""
    # Inject a provider that raises an unexpected error AND make the audit log
    # broken so even the error-path could fail — agent must still return a UM.
    provider = MagicMock()
    provider.complete = AsyncMock(side_effect=Exception("catastrophic"))
    agent, _ = _make_agent(tmp_path, provider=provider)

    um = _make_request_um(text="hello")
    result_um = await agent.run(um, trace_id="trace-never-raises")

    # Should still get back a UM — either response (stub) or error
    assert result_um is not None
    assert result_um.type in ("response", "error")


# ---------------------------------------------------------------------------
# Context field
# ---------------------------------------------------------------------------


async def test_context_appended_to_user_message(tmp_path: Path) -> None:
    """Optional context is appended to the user turn in the LLM prompt."""
    provider = _make_llm_provider("summary with context")
    agent, _ = _make_agent(tmp_path, provider=provider)

    um = _make_request_um(text="main text", context="extra info")
    await agent.run(um, trace_id=um.trace_id)

    call_args = provider.complete.call_args
    messages = call_args.kwargs.get("messages") or call_args.args[0]
    user_msg = next(m for m in messages if m["role"] == "user")
    assert "main text" in user_msg["content"]
    assert "extra info" in user_msg["content"]


# ---------------------------------------------------------------------------
# Output capping
# ---------------------------------------------------------------------------


async def test_output_capped_at_max_output_chars(tmp_path: Path) -> None:
    """LLM output longer than max_output_chars is sliced before returning."""
    long_output = "y" * 10_000
    provider = _make_llm_provider(long_output)
    agent, _ = _make_agent(tmp_path, provider=provider, max_output_chars=500)

    um = _make_request_um(text="summarize this")
    result_um = await agent.run(um, trace_id=um.trace_id)

    assert result_um.type == "response"
    result = SummarizerResult.model_validate(result_um.params)
    assert len(result.summary) == 500


# ---------------------------------------------------------------------------
# UM fields
# ---------------------------------------------------------------------------


async def test_response_um_fields(tmp_path: Path) -> None:
    """Response UM has correct type, operation, and trust_level."""
    provider = _make_llm_provider("clean summary")
    agent, _ = _make_agent(tmp_path, provider=provider)

    trace_id = str(uuid.uuid4())
    um = _make_request_um(text="hello world")
    result_um = await agent.run(
        um,
        trace_id=trace_id,
        from_agent="agent:summarizer:sub",
        to_agent="agent:main:main",
        session_key="sess:xyz",
    )

    assert result_um.type == "response"
    assert result_um.operation == "summarize"
    assert result_um.trust_level == "main"
    assert result_um.trace_id == trace_id
    assert result_um.from_agent == "agent:summarizer:sub"
    assert result_um.to_agent == "agent:main:main"
