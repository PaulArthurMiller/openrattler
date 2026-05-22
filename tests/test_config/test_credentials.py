"""Tests for openrattler.config.credentials — CredentialManager core (43.1).

Coverage:
- repr/str never expose credential values
- get() raises CredentialMissingError with actionable message
- load() reads env-var credentials correctly
- load() reads config-sourced credentials correctly
- load() skips disabled-channel credentials
- missing_for_config() reports required-but-absent credentials
- missing_for_config() applies the anthropic/openai OR logic
- load() is idempotent
"""

from __future__ import annotations

import pytest

from openrattler.config.credentials import (
    CredentialManager,
    CredentialMissingError,
    build_credential_manager,
)
from openrattler.config.loader import AppConfig, ChannelConfig
from openrattler.models.agents import AgentConfig, TrustLevel

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


def _minimal_config(**kwargs: object) -> AppConfig:
    """Build an AppConfig with all defaults, optionally overriding fields."""
    return AppConfig(**kwargs)  # type: ignore[arg-type]


def _slack_config(*, enabled: bool, bot_token: str = "") -> AppConfig:
    settings = {"bot_token": bot_token} if bot_token else {}
    return AppConfig(channels={"slack": ChannelConfig(enabled=enabled, settings=settings)})


def _sms_config(*, enabled: bool, account_sid: str = "", auth_token: str = "") -> AppConfig:
    settings: dict[str, str] = {}
    if account_sid:
        settings["account_sid"] = account_sid
    if auth_token:
        settings["auth_token"] = auth_token
    return AppConfig(channels={"sms": ChannelConfig(enabled=enabled, settings=settings)})


# ---------------------------------------------------------------------------
# Test: repr never contains credential values
# ---------------------------------------------------------------------------


def test_repr_never_contains_credential_value(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-secret-anthropic-value")
    monkeypatch.setenv("SERPER_API_KEY", "serper-secret-value")

    manager = build_credential_manager(_minimal_config())

    r = repr(manager)
    s = str(manager)

    assert "sk-secret-anthropic-value" not in r
    assert "sk-secret-anthropic-value" not in s
    assert "serper-secret-value" not in r
    assert "serper-secret-value" not in s
    assert "credentials loaded" in r
    assert "redacted" in r

    print(f"repr: {r}")


# ---------------------------------------------------------------------------
# Test: get() raises CredentialMissingError with actionable message
# ---------------------------------------------------------------------------


def test_get_raises_credential_missing_error_with_actionable_message(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)

    manager = CredentialManager()
    manager.load(_minimal_config())

    with pytest.raises(CredentialMissingError) as exc_info:
        manager.get("anthropic_api_key")

    message = str(exc_info.value)
    print(f"Error message: {message}")

    # Message must contain the canonical name and the env var (actionable)
    assert "anthropic_api_key" in message
    assert "ANTHROPIC_API_KEY" in message


def test_get_raises_for_config_sourced_credential_with_actionable_message() -> None:
    manager = CredentialManager()
    manager.load(_slack_config(enabled=False))

    with pytest.raises(CredentialMissingError) as exc_info:
        manager.get("slack_bot_token")

    message = str(exc_info.value)
    print(f"Error message: {message}")

    # Must contain the canonical name and point to config.json
    assert "slack_bot_token" in message
    assert "bot_token" in message


# ---------------------------------------------------------------------------
# Test: load() reads env-var credentials correctly
# ---------------------------------------------------------------------------


def test_load_reads_env_var_correctly(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-test-anthropic-123")

    manager = CredentialManager()
    manager.load(_minimal_config())

    result = manager.get("anthropic_api_key")

    assert result == "sk-test-anthropic-123"
    assert manager.is_present("anthropic_api_key")
    assert "anthropic_api_key" in manager.loaded_names()

    print(f"loaded_names: {manager.loaded_names()}")


# ---------------------------------------------------------------------------
# Test: load() reads config-sourced credentials correctly
# ---------------------------------------------------------------------------


def test_load_reads_config_credential_correctly() -> None:
    config = _slack_config(enabled=True, bot_token="xoxb-test-token-123")

    manager = CredentialManager()
    manager.load(config)

    result = manager.get("slack_bot_token")

    assert result == "xoxb-test-token-123"
    assert manager.is_present("slack_bot_token")

    print(f"Slack token loaded: is_present={manager.is_present('slack_bot_token')}")


# ---------------------------------------------------------------------------
# Test: load() skips disabled-channel credentials
# ---------------------------------------------------------------------------


def test_load_skips_disabled_channel_credentials() -> None:
    config = _slack_config(enabled=False, bot_token="xoxb-should-not-load")

    manager = CredentialManager()
    manager.load(config)

    assert not manager.is_present("slack_bot_token")
    assert "slack_bot_token" not in manager.loaded_names()

    print(f"Disabled channel loaded_names: {manager.loaded_names()}")


# ---------------------------------------------------------------------------
# Test: missing_for_config() reports required-but-absent credentials
# ---------------------------------------------------------------------------


def test_missing_for_config_reports_correctly(monkeypatch: pytest.MonkeyPatch) -> None:
    # Provide anthropic key so the LLM OR group is satisfied
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-test")
    # SMS enabled but no account_sid in settings
    config = _sms_config(enabled=True)

    manager = CredentialManager()
    manager.load(config)

    missing = manager.missing_for_config(config)
    missing_names = [spec.name for spec in missing]

    print(f"Missing credentials: {missing_names}")

    assert "twilio_account_sid" in missing_names
    # Anthropic is present so the LLM group should NOT appear
    assert "anthropic_api_key" not in missing_names


# ---------------------------------------------------------------------------
# Test: missing_for_config() applies anthropic/openai OR logic
# ---------------------------------------------------------------------------


def test_missing_for_config_or_logic(monkeypatch: pytest.MonkeyPatch) -> None:
    config = _minimal_config()

    # --- Case 1: both absent → one LLM entry ---
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)

    manager = CredentialManager()
    manager.load(config)
    missing = manager.missing_for_config(config)
    missing_names = [spec.name for spec in missing]

    print(f"Both absent — missing: {missing_names}")

    llm_entries = [n for n in missing_names if n in ("anthropic_api_key", "openai_api_key")]
    assert len(llm_entries) == 1, f"Expected 1 LLM entry, got {llm_entries}"

    # --- Case 2: anthropic present → no LLM entries ---
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-present")
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)

    manager2 = CredentialManager()
    manager2.load(config)
    missing2 = manager2.missing_for_config(config)
    missing_names2 = [spec.name for spec in missing2]

    print(f"Anthropic present — missing: {missing_names2}")

    assert "anthropic_api_key" not in missing_names2
    assert "openai_api_key" not in missing_names2

    # --- Case 3: openai present → no LLM entries ---
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    monkeypatch.setenv("OPENAI_API_KEY", "sk-openai-present")

    manager3 = CredentialManager()
    manager3.load(config)
    missing3 = manager3.missing_for_config(config)
    missing_names3 = [spec.name for spec in missing3]

    print(f"OpenAI present — missing: {missing_names3}")

    assert "anthropic_api_key" not in missing_names3
    assert "openai_api_key" not in missing_names3


# ---------------------------------------------------------------------------
# Test: load() is idempotent
# ---------------------------------------------------------------------------


def test_load_is_idempotent(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-idempotent-test")

    manager = CredentialManager()
    manager.load(_minimal_config())
    count_first = len(manager.loaded_names())
    names_first = manager.loaded_names()

    # Second load must not duplicate or error
    manager.load(_minimal_config())
    count_second = len(manager.loaded_names())
    names_second = manager.loaded_names()

    print(f"After first load: {names_first}")
    print(f"After second load: {names_second}")

    assert count_first == count_second
    assert names_first == names_second
    assert manager.get("anthropic_api_key") == "sk-idempotent-test"


# ---------------------------------------------------------------------------
# Test: build_credential_manager convenience function
# ---------------------------------------------------------------------------


def test_build_credential_manager_returns_loaded_manager(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-build-test")

    manager = build_credential_manager(_minimal_config())

    assert isinstance(manager, CredentialManager)
    assert manager.is_present("anthropic_api_key")
    assert manager.get("anthropic_api_key") == "sk-build-test"

    print(f"build_credential_manager result: {repr(manager)}")


# ---------------------------------------------------------------------------
# Test: is_present() returns False for unknown names
# ---------------------------------------------------------------------------


def test_is_present_returns_false_for_unknown_name() -> None:
    manager = CredentialManager()
    manager.load(_minimal_config())

    assert not manager.is_present("nonexistent_credential_xyz")


# ---------------------------------------------------------------------------
# Test: missing_for_config() respects serper required_check (agent tools)
# ---------------------------------------------------------------------------


def test_missing_for_config_serper_required_when_agent_uses_research_query(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-test")
    monkeypatch.delenv("SERPER_API_KEY", raising=False)

    agent_with_research = AgentConfig(
        agent_id="agent:main:main",
        name="Main",
        description="Main agent",
        model="anthropic/claude-sonnet-4-5",
        trust_level=TrustLevel.main,
        allowed_tools=["research_query", "send_message"],
    )
    config = AppConfig(agents={"main": agent_with_research})

    manager = CredentialManager()
    manager.load(config)

    missing = manager.missing_for_config(config)
    missing_names = [spec.name for spec in missing]

    print(f"Missing with research agent: {missing_names}")

    assert "serper_api_key" in missing_names


def test_missing_for_config_serper_not_required_without_research_agent(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-test")
    monkeypatch.delenv("SERPER_API_KEY", raising=False)

    config = _minimal_config()  # no agents with research_query

    manager = CredentialManager()
    manager.load(config)

    missing = manager.missing_for_config(config)
    missing_names = [spec.name for spec in missing]

    print(f"Missing without research agent: {missing_names}")

    assert "serper_api_key" not in missing_names
