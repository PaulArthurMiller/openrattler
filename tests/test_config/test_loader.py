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
    SecurityConfig,
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
