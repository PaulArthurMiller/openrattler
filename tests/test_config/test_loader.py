"""Tests for openrattler.config.loader.

Testing focus:
- Config loads cleanly with sensible defaults from an empty or partial file
- Invalid configs are caught by Pydantic at load time
- Round-trip (save → load) produces an equal AppConfig
- Missing config file returns default AppConfig (not an error)
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from pydantic import ValidationError

from openrattler.config.loader import (
    AppConfig,
    BudgetConfig,
    ChannelConfig,
    HeartbeatConfig,
    MemoryConfig,
    SecurityConfig,
    ToolsConfig,
    UsageReportConfig,
    load_config,
    save_config,
)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_MINIMAL_AGENT = {
    "agent_id": "agent:main:main",
    "name": "Main",
    "description": "Primary assistant agent",
    "model": "anthropic/claude-sonnet-4-6",
    "trust_level": "main",
}


def _write_json(path: Path, data: object) -> None:
    path.write_text(json.dumps(data), encoding="utf-8")


# ---------------------------------------------------------------------------
# load_config
# ---------------------------------------------------------------------------


class TestLoadConfig:
    def test_missing_file_returns_default(self, tmp_path: Path) -> None:
        """A non-existent config file returns a default AppConfig."""
        result = load_config(tmp_path / "nonexistent.json")
        assert isinstance(result, AppConfig)
        # Defaults are applied
        assert result.security.profile == "standard"
        assert result.budget.daily_limit_usd == 5.00
        assert result.agents == {}
        assert result.channels == {}

    def test_empty_object_returns_defaults(self, tmp_path: Path) -> None:
        """An empty JSON object {} loads with all field defaults."""
        path = tmp_path / "config.json"
        _write_json(path, {})
        result = load_config(path)
        assert isinstance(result, AppConfig)
        assert result.security.profile == "standard"
        assert result.budget.prefer_tier == "balanced"

    def test_valid_full_config(self, tmp_path: Path) -> None:
        """A fully-specified config is loaded with all values preserved."""
        path = tmp_path / "config.json"
        data = {
            "agents": {"main": _MINIMAL_AGENT},
            "security": {"profile": "paranoid", "session_isolation": True},
            "budget": {
                "daily_limit_usd": 10.00,
                "monthly_limit_usd": 200.00,
                "prefer_tier": "quality",
            },
            "channels": {"telegram": {"enabled": True, "settings": {"token": "abc123"}}},
        }
        _write_json(path, data)
        result = load_config(path)
        assert result.security.profile == "paranoid"
        assert result.security.session_isolation is True
        assert result.budget.daily_limit_usd == 10.00
        assert result.budget.monthly_limit_usd == 200.00
        assert result.budget.prefer_tier == "quality"
        assert result.channels["telegram"].enabled is True
        assert result.channels["telegram"].settings["token"] == "abc123"
        assert result.agents["main"].agent_id == "agent:main:main"

    def test_partial_security_uses_defaults(self, tmp_path: Path) -> None:
        """A config with partial security settings fills in missing fields with None."""
        path = tmp_path / "config.json"
        _write_json(path, {"security": {"profile": "minimal"}})
        result = load_config(path)
        assert result.security.profile == "minimal"
        # Unset layers remain None (use profile default at apply_profile time)
        assert result.security.session_isolation is None
        assert result.security.approval_gates is None

    def test_partial_budget_uses_defaults(self, tmp_path: Path) -> None:
        """A config with only daily_limit_usd leaves other budget fields at defaults."""
        path = tmp_path / "config.json"
        _write_json(path, {"budget": {"daily_limit_usd": 3.00}})
        result = load_config(path)
        assert result.budget.daily_limit_usd == 3.00
        assert result.budget.monthly_limit_usd == 150.00  # default
        assert result.budget.prefer_tier == "balanced"  # default

    def test_invalid_config_raises_validation_error(self, tmp_path: Path) -> None:
        """A config with a structurally invalid agent raises ValidationError."""
        path = tmp_path / "config.json"
        # AgentConfig requires agent_id, name, description, model, trust_level
        _write_json(path, {"agents": {"broken": {"name": "Broken"}}})
        with pytest.raises(ValidationError):
            load_config(path)

    def test_invalid_profile_raises_validation_error(self, tmp_path: Path) -> None:
        """An unrecognised security profile raises ValidationError."""
        path = tmp_path / "config.json"
        _write_json(path, {"security": {"profile": "ultraparanoid"}})
        with pytest.raises(ValidationError):
            load_config(path)

    def test_invalid_budget_tier_raises_validation_error(self, tmp_path: Path) -> None:
        """An unrecognised budget tier raises ValidationError."""
        path = tmp_path / "config.json"
        _write_json(path, {"budget": {"prefer_tier": "extravagant"}})
        with pytest.raises(ValidationError):
            load_config(path)

    def test_negative_daily_limit_raises_validation_error(self, tmp_path: Path) -> None:
        """A negative daily limit fails Pydantic's ge=0 constraint."""
        path = tmp_path / "config.json"
        _write_json(path, {"budget": {"daily_limit_usd": -1.0}})
        with pytest.raises(ValidationError):
            load_config(path)

    def test_invalid_json_raises_json_decode_error(self, tmp_path: Path) -> None:
        """A file containing invalid JSON raises json.JSONDecodeError."""
        import json

        path = tmp_path / "config.json"
        path.write_text("not valid json {{{", encoding="utf-8")
        with pytest.raises(json.JSONDecodeError):
            load_config(path)


# ---------------------------------------------------------------------------
# save_config
# ---------------------------------------------------------------------------


class TestSaveConfig:
    def test_creates_parent_directory(self, tmp_path: Path) -> None:
        """save_config creates missing parent directories."""
        path = tmp_path / "nested" / "dir" / "config.json"
        save_config(AppConfig(), path)
        assert path.exists()

    def test_writes_valid_json(self, tmp_path: Path) -> None:
        """The saved file contains valid JSON."""
        path = tmp_path / "config.json"
        save_config(AppConfig(), path)
        data = json.loads(path.read_text(encoding="utf-8"))
        assert isinstance(data, dict)

    def test_round_trip(self, tmp_path: Path) -> None:
        """A config saved and loaded is equal to the original."""
        path = tmp_path / "config.json"
        original = AppConfig(
            security=SecurityConfig(profile="paranoid", approval_gates=False),
            budget=BudgetConfig(daily_limit_usd=7.50, prefer_tier="quality"),
            channels={"cli": ChannelConfig(enabled=True, settings={"color": True})},
        )
        save_config(original, path)
        loaded = load_config(path)
        assert loaded.security.profile == "paranoid"
        assert loaded.security.approval_gates is False
        assert loaded.budget.daily_limit_usd == 7.50
        assert loaded.budget.prefer_tier == "quality"
        assert loaded.channels["cli"].enabled is True
        assert loaded.channels["cli"].settings["color"] is True

    def test_round_trip_with_agent(self, tmp_path: Path) -> None:
        """An AppConfig with an agent survives a save/load round-trip."""
        from openrattler.models.agents import AgentConfig, TrustLevel

        path = tmp_path / "config.json"
        agent = AgentConfig(
            agent_id="agent:main:main",
            name="Main",
            description="Primary agent",
            model="anthropic/claude-sonnet-4-6",
            trust_level=TrustLevel.main,
        )
        original = AppConfig(agents={"main": agent})
        save_config(original, path)
        loaded = load_config(path)
        assert loaded.agents["main"].agent_id == "agent:main:main"
        assert loaded.agents["main"].trust_level == TrustLevel.main


# ---------------------------------------------------------------------------
# MemoryConfig
# ---------------------------------------------------------------------------


class TestMemoryConfig:
    def test_default_identity_max_tokens(self) -> None:
        cfg = MemoryConfig()
        assert cfg.identity_max_tokens == 500

    def test_custom_identity_max_tokens(self) -> None:
        cfg = MemoryConfig(identity_max_tokens=800)
        assert cfg.identity_max_tokens == 800

    def test_identity_max_tokens_minimum_one(self) -> None:
        from pydantic import ValidationError

        with pytest.raises(ValidationError):
            MemoryConfig(identity_max_tokens=0)


# ---------------------------------------------------------------------------
# ToolsConfig
# ---------------------------------------------------------------------------


class TestToolsConfig:
    def test_default_main_tools_present(self) -> None:
        cfg = ToolsConfig()
        main_tools = cfg.trust_defaults["main"]
        assert "update_memory_narrative" in main_tools
        assert "update_user_profile" in main_tools
        assert "update_identity" in main_tools
        assert "memory_read" in main_tools
        assert "memory_write" in main_tools

    def test_default_public_tools_empty(self) -> None:
        cfg = ToolsConfig()
        assert cfg.trust_defaults["public"] == []

    def test_custom_trust_defaults_accepted(self) -> None:
        cfg = ToolsConfig(trust_defaults={"main": ["some_tool"], "local": ["other_tool"]})
        assert cfg.trust_defaults["main"] == ["some_tool"]
        assert cfg.trust_defaults["local"] == ["other_tool"]

    def test_appconfig_includes_tools_field(self) -> None:
        app = AppConfig()
        assert isinstance(app.tools, ToolsConfig)
        assert "main" in app.tools.trust_defaults

    def test_tools_config_round_trips_via_json(self, tmp_path: Path) -> None:
        path = tmp_path / "config.json"
        original = AppConfig(
            tools=ToolsConfig(trust_defaults={"main": ["tool_a", "tool_b"], "local": []})
        )
        save_config(original, path)
        loaded = load_config(path)
        assert loaded.tools.trust_defaults["main"] == ["tool_a", "tool_b"]


# ---------------------------------------------------------------------------
# HeartbeatConfig
# ---------------------------------------------------------------------------


class TestHeartbeatConfig:
    def test_default_enabled(self) -> None:
        cfg = HeartbeatConfig()
        assert cfg.enabled is True

    def test_default_interval_minutes(self) -> None:
        cfg = HeartbeatConfig()
        assert cfg.interval_minutes == 60

    def test_can_disable(self) -> None:
        cfg = HeartbeatConfig(enabled=False)
        assert cfg.enabled is False

    def test_custom_interval(self) -> None:
        cfg = HeartbeatConfig(interval_minutes=30)
        assert cfg.interval_minutes == 30

    def test_interval_minimum_one(self) -> None:
        with pytest.raises(Exception):
            HeartbeatConfig(interval_minutes=0)

    def test_appconfig_has_heartbeat_field(self) -> None:
        app = AppConfig()
        assert isinstance(app.heartbeat, HeartbeatConfig)
        assert app.heartbeat.enabled is True

    def test_heartbeat_config_round_trips(self, tmp_path: Path) -> None:
        path = tmp_path / "cfg.json"
        original = AppConfig(heartbeat=HeartbeatConfig(enabled=False, interval_minutes=15))
        save_config(original, path)
        loaded = load_config(path)
        assert loaded.heartbeat.enabled is False
        assert loaded.heartbeat.interval_minutes == 15

    # -- log_context_entries --

    def test_log_context_entries_default_is_7(self) -> None:
        cfg = HeartbeatConfig()
        assert cfg.log_context_entries == 7

    def test_log_context_entries_accepts_minimum_1(self) -> None:
        cfg = HeartbeatConfig(log_context_entries=1)
        assert cfg.log_context_entries == 1

    def test_log_context_entries_accepts_maximum_50(self) -> None:
        cfg = HeartbeatConfig(log_context_entries=50)
        assert cfg.log_context_entries == 50

    def test_log_context_entries_rejects_0(self) -> None:
        with pytest.raises(Exception):
            HeartbeatConfig(log_context_entries=0)

    def test_log_context_entries_rejects_51(self) -> None:
        with pytest.raises(Exception):
            HeartbeatConfig(log_context_entries=51)

    # -- log_max_retained --

    def test_log_max_retained_default_is_100(self) -> None:
        cfg = HeartbeatConfig()
        assert cfg.log_max_retained == 100

    def test_log_max_retained_accepts_minimum_10(self) -> None:
        cfg = HeartbeatConfig(log_max_retained=10)
        assert cfg.log_max_retained == 10

    def test_log_max_retained_rejects_9(self) -> None:
        with pytest.raises(Exception):
            HeartbeatConfig(log_max_retained=9)

    # -- tool_allowlist (46.2) --

    def test_tool_allowlist_defaults_to_empty_list(self) -> None:
        cfg = HeartbeatConfig()
        assert cfg.tool_allowlist == []

    def test_tool_allowlist_accepts_nonempty_list(self) -> None:
        cfg = HeartbeatConfig(tool_allowlist=["research_query", "memory_read"])
        assert cfg.tool_allowlist == ["research_query", "memory_read"]

    def test_tool_allowlist_round_trips_through_json(self, tmp_path: Path) -> None:
        path = tmp_path / "cfg.json"
        original = AppConfig(
            heartbeat=HeartbeatConfig(tool_allowlist=["research_query", "send_email"])
        )
        save_config(original, path)
        loaded = load_config(path)
        print(f"[test] tool_allowlist={loaded.heartbeat.tool_allowlist}")
        assert loaded.heartbeat.tool_allowlist == ["research_query", "send_email"]

    def test_empty_tool_allowlist_round_trips_through_json(self, tmp_path: Path) -> None:
        path = tmp_path / "cfg.json"
        original = AppConfig(heartbeat=HeartbeatConfig(tool_allowlist=[]))
        save_config(original, path)
        loaded = load_config(path)
        assert loaded.heartbeat.tool_allowlist == []

    # -- consolidation_days_to_keep (46.5) --

    def test_consolidation_days_to_keep_default_is_7(self) -> None:
        cfg = HeartbeatConfig()
        assert cfg.consolidation_days_to_keep == 7
        print(f"[test] default consolidation_days_to_keep={cfg.consolidation_days_to_keep}")

    def test_consolidation_days_to_keep_accepts_custom_value(self) -> None:
        cfg = HeartbeatConfig(consolidation_days_to_keep=14)
        assert cfg.consolidation_days_to_keep == 14

    def test_consolidation_days_to_keep_rejects_zero(self) -> None:
        with pytest.raises(Exception):
            HeartbeatConfig(consolidation_days_to_keep=0)

    def test_consolidation_days_to_keep_round_trips_through_json(self, tmp_path: Path) -> None:
        path = tmp_path / "cfg.json"
        original = AppConfig(heartbeat=HeartbeatConfig(consolidation_days_to_keep=30))
        save_config(original, path)
        loaded = load_config(path)
        assert loaded.heartbeat.consolidation_days_to_keep == 30
        print(
            f"[test] round-trip consolidation_days_to_keep={loaded.heartbeat.consolidation_days_to_keep}"
        )


# ---------------------------------------------------------------------------
# UsageReportConfig
# ---------------------------------------------------------------------------


class TestUsageReportConfig:
    def test_defaults(self) -> None:
        """UsageReportConfig has the correct default values."""
        cfg = UsageReportConfig()
        assert cfg.enabled is True
        assert cfg.send_on_shutdown is True
        assert cfg.scheduled_hour_utc == 8
        assert cfg.idle_session_timeout_minutes == 60
        assert cfg.report_window_hours == 24
        assert cfg.recipient_email is None
        print("[OK] all defaults correct")

    def test_scheduled_hour_utc_accepts_zero(self) -> None:
        """scheduled_hour_utc=0 is the lower boundary and is valid."""
        cfg = UsageReportConfig(scheduled_hour_utc=0)
        assert cfg.scheduled_hour_utc == 0

    def test_scheduled_hour_utc_accepts_twenty_three(self) -> None:
        """scheduled_hour_utc=23 is the upper boundary and is valid."""
        cfg = UsageReportConfig(scheduled_hour_utc=23)
        assert cfg.scheduled_hour_utc == 23

    def test_scheduled_hour_utc_rejects_negative(self) -> None:
        """scheduled_hour_utc below 0 raises a ValidationError."""
        with pytest.raises(Exception):
            UsageReportConfig(scheduled_hour_utc=-1)

    def test_scheduled_hour_utc_rejects_twenty_four(self) -> None:
        """scheduled_hour_utc above 23 raises a ValidationError."""
        with pytest.raises(Exception):
            UsageReportConfig(scheduled_hour_utc=24)

    def test_can_disable(self) -> None:
        """enabled=False disables the report feature."""
        cfg = UsageReportConfig(enabled=False)
        assert cfg.enabled is False

    def test_can_disable_shutdown_send(self) -> None:
        """send_on_shutdown=False suppresses the shutdown report."""
        cfg = UsageReportConfig(send_on_shutdown=False)
        assert cfg.send_on_shutdown is False

    def test_recipient_email_accepted(self) -> None:
        """An explicit recipient_email string is stored as-is."""
        cfg = UsageReportConfig(recipient_email="paul@example.com")
        assert cfg.recipient_email == "paul@example.com"

    def test_appconfig_has_usage_report_field(self) -> None:
        """AppConfig includes a usage_report field with correct defaults."""
        app = AppConfig()
        assert isinstance(app.usage_report, UsageReportConfig)
        assert app.usage_report.enabled is True
        assert app.usage_report.scheduled_hour_utc == 8
        print("[OK] AppConfig.usage_report present with defaults")

    def test_usage_report_config_round_trips(self, tmp_path: Path) -> None:
        """UsageReportConfig round-trips through save/load."""
        path = tmp_path / "cfg.json"
        original = AppConfig(
            usage_report=UsageReportConfig(
                enabled=False,
                send_on_shutdown=False,
                scheduled_hour_utc=12,
                report_window_hours=48,
                recipient_email="owner@example.com",
            )
        )
        save_config(original, path)
        loaded = load_config(path)
        assert loaded.usage_report.enabled is False
        assert loaded.usage_report.send_on_shutdown is False
        assert loaded.usage_report.scheduled_hour_utc == 12
        assert loaded.usage_report.report_window_hours == 48
        assert loaded.usage_report.recipient_email == "owner@example.com"
        print("[OK] UsageReportConfig round-trips correctly")
