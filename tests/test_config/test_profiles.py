"""Tests for openrattler.config.profiles.

Testing focus:
- Each profile sets the expected layer values
- Applying a profile preserves explicit user overrides
- Unknown profile names raise ValueError
- The returned AppConfig is a new object (original is not mutated)
"""

from __future__ import annotations

import pytest

from openrattler.config.loader import AppConfig, SecurityConfig
from openrattler.config.profiles import SECURITY_PROFILES, apply_profile

# ---------------------------------------------------------------------------
# SECURITY_PROFILES catalogue
# ---------------------------------------------------------------------------


class TestSecurityProfilesCatalogue:
    def test_all_three_profiles_present(self) -> None:
        """The catalogue contains exactly the three documented profiles."""
        assert set(SECURITY_PROFILES.keys()) == {"minimal", "standard", "paranoid"}

    def test_each_profile_covers_all_layer_fields(self) -> None:
        """Every profile has an entry for all 14 boolean layer fields."""
        # These are the SecurityConfig fields that profiles govern.
        expected_fields = {
            "session_isolation",
            "channel_isolation",
            "agent_trust_levels",
            "pitch_catch",
            "need_to_know",
            "input_output_filtering",
            "approval_gates",
            "rate_limiting",
            "audit_logging",
            "memory_security",
            "heartbeat_history_sanitization",
            "heartbeat_tool_restriction",
            "approval_provenance",
            "dependency_hash_verification",
            "startup_integrity_check",
        }
        for profile_name, settings in SECURITY_PROFILES.items():
            missing = expected_fields - settings.keys()
            assert not missing, f"Profile {profile_name!r} is missing fields: {missing}"

    def test_minimal_non_negotiable_controls_on(self) -> None:
        """Minimal profile keeps session_isolation, filtering, and audit_logging on."""
        m = SECURITY_PROFILES["minimal"]
        assert m["session_isolation"] is True
        assert m["input_output_filtering"] is True
        assert m["audit_logging"] is True
        assert m["dependency_hash_verification"] is True

    def test_minimal_optional_layers_off(self) -> None:
        """Minimal profile disables optional layers."""
        m = SECURITY_PROFILES["minimal"]
        assert m["channel_isolation"] is False
        assert m["approval_gates"] is False
        assert m["memory_security"] is False
        assert m["startup_integrity_check"] is False

    def test_standard_all_core_layers_on(self) -> None:
        """Standard profile enables all 10 core security layers."""
        s = SECURITY_PROFILES["standard"]
        core_layers = [
            "session_isolation",
            "channel_isolation",
            "agent_trust_levels",
            "pitch_catch",
            "need_to_know",
            "input_output_filtering",
            "approval_gates",
            "rate_limiting",
            "audit_logging",
            "memory_security",
        ]
        for layer in core_layers:
            assert s[layer] is True, f"Standard profile should have {layer}=True"

    def test_standard_heartbeat_controls_on(self) -> None:
        """Standard profile enables heartbeat sanitization and tool restriction."""
        s = SECURITY_PROFILES["standard"]
        assert s["heartbeat_history_sanitization"] is True
        assert s["heartbeat_tool_restriction"] is True
        assert s["approval_provenance"] is True

    def test_standard_no_startup_integrity_check(self) -> None:
        """Standard profile does not enable the startup integrity check."""
        assert SECURITY_PROFILES["standard"]["startup_integrity_check"] is False

    def test_paranoid_all_controls_on(self) -> None:
        """Paranoid profile enables every single control."""
        p = SECURITY_PROFILES["paranoid"]
        for field, value in p.items():
            assert value is True, f"Paranoid profile should have {field}=True"

    def test_paranoid_is_superset_of_standard(self) -> None:
        """Every control enabled in standard is also enabled in paranoid."""
        s = SECURITY_PROFILES["standard"]
        p = SECURITY_PROFILES["paranoid"]
        for field, std_value in s.items():
            if std_value is True:
                assert p[field] is True, f"Paranoid should also have {field}=True"


# ---------------------------------------------------------------------------
# apply_profile
# ---------------------------------------------------------------------------


class TestApplyProfile:
    def test_unknown_profile_raises_value_error(self) -> None:
        """An unrecognised profile name raises ValueError."""
        with pytest.raises(ValueError, match="Unknown security profile"):
            apply_profile(AppConfig(), "ultra")

    def test_returns_new_object(self) -> None:
        """apply_profile does not mutate the original config."""
        original = AppConfig()
        result = apply_profile(original, "minimal")
        assert result is not original
        assert result.security is not original.security

    def test_profile_field_updated(self) -> None:
        """The returned config's security.profile matches the applied profile."""
        result = apply_profile(AppConfig(), "paranoid")
        assert result.security.profile == "paranoid"

    def test_minimal_profile_resolves_all_none_fields(self) -> None:
        """After apply_profile('minimal'), no layer field is None."""
        result = apply_profile(AppConfig(), "minimal")
        sec = result.security
        for field in SECURITY_PROFILES["minimal"]:
            assert getattr(sec, field) is not None, f"{field} should not be None after apply"

    def test_standard_profile_resolves_all_none_fields(self) -> None:
        """After apply_profile('standard'), no layer field is None."""
        result = apply_profile(AppConfig(), "standard")
        sec = result.security
        for field in SECURITY_PROFILES["standard"]:
            assert getattr(sec, field) is not None, f"{field} should not be None after apply"

    def test_paranoid_profile_sets_startup_integrity_check(self) -> None:
        """After apply_profile('paranoid'), startup_integrity_check is True."""
        result = apply_profile(AppConfig(), "paranoid")
        assert result.security.startup_integrity_check is True

    def test_user_override_preserved_over_profile(self) -> None:
        """A user-set False on approval_gates survives applying the standard profile."""
        config = AppConfig(security=SecurityConfig(approval_gates=False))
        result = apply_profile(config, "standard")
        # Standard sets approval_gates=True, but user explicitly set False
        assert result.security.approval_gates is False

    def test_user_override_true_preserved_in_minimal(self) -> None:
        """A user-set True on memory_security survives applying the minimal profile."""
        config = AppConfig(security=SecurityConfig(memory_security=True))
        result = apply_profile(config, "minimal")
        # Minimal sets memory_security=False, but user explicitly set True
        assert result.security.memory_security is True

    def test_none_field_filled_by_profile(self) -> None:
        """A None field (not explicitly set) is filled by the profile default."""
        # Start with default AppConfig — all layer fields are None
        config = AppConfig()
        assert config.security.session_isolation is None
        result = apply_profile(config, "minimal")
        assert result.security.session_isolation is True  # minimal default

    def test_mcp_setting_unchanged_by_apply_profile(self) -> None:
        """mcp_allow_auto_discovered is not modified by apply_profile."""
        config = AppConfig(security=SecurityConfig(mcp_allow_auto_discovered="deny"))
        result = apply_profile(config, "paranoid")
        assert result.security.mcp_allow_auto_discovered == "deny"

    def test_non_security_fields_unchanged(self) -> None:
        """apply_profile does not modify budget, agents, or channels."""
        config = AppConfig(budget={"daily_limit_usd": 99.0, "prefer_tier": "quality"})
        result = apply_profile(config, "standard")
        assert result.budget.daily_limit_usd == 99.0
        assert result.budget.prefer_tier == "quality"

    def test_multiple_overrides_all_preserved(self) -> None:
        """Multiple explicit user overrides are all preserved after apply_profile."""
        config = AppConfig(
            security=SecurityConfig(
                approval_gates=False,
                rate_limiting=False,
                startup_integrity_check=True,
            )
        )
        result = apply_profile(config, "standard")
        assert result.security.approval_gates is False
        assert result.security.rate_limiting is False
        assert result.security.startup_integrity_check is True
