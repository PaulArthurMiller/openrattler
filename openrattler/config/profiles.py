"""Security profile definitions and application logic.

Three built-in profiles (``minimal``, ``standard``, ``paranoid``) each set
all 10 security layers plus the additional controls defined in
``openrattler.config.loader.SecurityConfig``.

Use ``apply_profile`` to resolve a config:
1. The profile's default value is used for every layer whose config field is
   ``None`` (meaning "use profile default").
2. Fields explicitly set to ``True`` or ``False`` in the config are preserved
   as user overrides.

PROFILE SUMMARY
---------------
minimal  — Session isolation + filtering + audit always on; everything else off.
           Intended for local development and testing only.
standard — All 10 layers on with production-appropriate defaults.  Heartbeat
           sanitization, tool restriction, and provenance all enabled.
           Default for personal use.
paranoid — All controls maxed, including startup integrity check.  Intended
           for sensitive data, multi-user, or public deployments.

SECURITY NOTES
--------------
- All profiles keep ``session_isolation``, ``input_output_filtering``, and
  ``audit_logging`` enabled — these are the minimum non-negotiable controls.
- ``dependency_hash_verification`` is enabled in all profiles; it protects
  the supply chain regardless of runtime security level.
- ``startup_integrity_check`` is only enabled in paranoid because it adds
  startup latency; enable it manually in standard if you need it.
"""

from __future__ import annotations

from openrattler.config.loader import AppConfig, SecurityConfig

# ---------------------------------------------------------------------------
# Profile definitions
# ---------------------------------------------------------------------------

#: Resolved security-layer settings for each named profile.
#: Keys match ``SecurityConfig`` field names exactly (excluding ``profile``
#: and ``mcp_allow_auto_discovered``, which are not layer toggles).
SECURITY_PROFILES: dict[str, dict[str, bool]] = {
    # ------------------------------------------------------------------
    # minimal — development and testing only
    # ------------------------------------------------------------------
    "minimal": {
        "session_isolation": True,  # non-negotiable
        "channel_isolation": False,
        "agent_trust_levels": False,
        "pitch_catch": False,
        "need_to_know": False,
        "input_output_filtering": True,  # non-negotiable
        "approval_gates": False,
        "rate_limiting": False,
        "audit_logging": True,  # non-negotiable
        "memory_security": False,
        "heartbeat_history_sanitization": False,
        "heartbeat_tool_restriction": False,
        "approval_provenance": False,
        "dependency_hash_verification": True,  # always protect supply chain
        "startup_integrity_check": False,
    },
    # ------------------------------------------------------------------
    # standard — balanced security / usability for personal use
    # ------------------------------------------------------------------
    "standard": {
        "session_isolation": True,
        "channel_isolation": True,
        "agent_trust_levels": True,
        "pitch_catch": True,
        "need_to_know": True,
        "input_output_filtering": True,
        "approval_gates": True,
        "rate_limiting": True,
        "audit_logging": True,
        "memory_security": True,
        "heartbeat_history_sanitization": True,
        "heartbeat_tool_restriction": True,
        "approval_provenance": True,
        "dependency_hash_verification": True,
        "startup_integrity_check": False,
    },
    # ------------------------------------------------------------------
    # paranoid — all controls maxed; for sensitive or multi-user deployments
    # ------------------------------------------------------------------
    "paranoid": {
        "session_isolation": True,
        "channel_isolation": True,
        "agent_trust_levels": True,
        "pitch_catch": True,
        "need_to_know": True,
        "input_output_filtering": True,
        "approval_gates": True,
        "rate_limiting": True,
        "audit_logging": True,
        "memory_security": True,
        "heartbeat_history_sanitization": True,
        "heartbeat_tool_restriction": True,
        "approval_provenance": True,
        "dependency_hash_verification": True,
        "startup_integrity_check": True,
    },
}

#: Ordered from least to most restrictive — useful for comparisons.
PROFILE_ORDER: list[str] = ["minimal", "standard", "paranoid"]


# ---------------------------------------------------------------------------
# apply_profile
# ---------------------------------------------------------------------------


def apply_profile(config: AppConfig, profile: str) -> AppConfig:
    """Return a copy of *config* with security settings resolved against *profile*.

    For each boolean layer field in ``SecurityConfig``:
    - If the field is ``None`` (not explicitly overridden), the profile's
      default value is used.
    - If the field is ``True`` or ``False`` (explicitly set by the user),
      the user's value is preserved regardless of the profile.

    ``SecurityConfig.profile`` is updated to *profile* in the returned config.
    ``SecurityConfig.mcp_allow_auto_discovered`` is never modified by this
    function — it is an independent setting that profiles do not govern.

    Args:
        config:  The ``AppConfig`` to process.
        profile: One of ``"minimal"``, ``"standard"``, ``"paranoid"``.

    Returns:
        A new ``AppConfig`` whose ``security`` field is fully resolved
        (no ``None`` layer fields).

    Raises:
        ValueError: If *profile* is not a recognised profile name.

    Security notes:
    - The returned config is a new object; *config* is not mutated.
    - Explicit user overrides take precedence over profile defaults so that
      users can tighten individual layers beyond a profile (e.g. enable
      ``startup_integrity_check`` on a standard profile) or relax them for
      specific development needs.
    """
    if profile not in SECURITY_PROFILES:
        raise ValueError(
            f"Unknown security profile {profile!r}. " f"Valid profiles: {sorted(SECURITY_PROFILES)}"
        )

    defaults = SECURITY_PROFILES[profile]
    current = config.security

    # Build resolved values: user override where set, profile default where None.
    resolved: dict[str, object] = {"profile": profile}
    for field_name, profile_value in defaults.items():
        user_value: object = getattr(current, field_name)
        resolved[field_name] = user_value if user_value is not None else profile_value

    # Preserve mcp_allow_auto_discovered unchanged.
    resolved["mcp_allow_auto_discovered"] = current.mcp_allow_auto_discovered

    new_security = SecurityConfig.model_validate(resolved)
    return config.model_copy(update={"security": new_security})
