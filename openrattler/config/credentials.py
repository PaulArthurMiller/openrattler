"""Centralized credential management for OpenRattler.

Credentials live in two places:
- Environment variables (ANTHROPIC_API_KEY, SERPER_API_KEY, etc.)
- config.json channels.*.settings (Slack bot_token, Twilio SIDs, email password)

CredentialManager loads both sources into a private dict at startup. Values
never appear in repr, log lines, or exception messages — only canonical names do.

Design notes:
- The OR group (anthropic_api_key / openai_api_key) is validated together in
  missing_for_config(): if either key is loaded the whole group is satisfied.
- OPENRATTLER_WS_SECRET has a dev fallback in startup.py (_DEV_WS_SECRET).
  The manager loads the env var if set; if absent it is treated as not-loaded
  and startup.py's dev-fallback logic remains in effect.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from typing import Callable, Optional

from openrattler.config.loader import AppConfig

# ---------------------------------------------------------------------------
# Error type
# ---------------------------------------------------------------------------


class CredentialMissingError(RuntimeError):
    """Raised by CredentialManager.get() when a required credential is absent."""

    def __init__(self, name: str, env_var: Optional[str], how_to_fix: str) -> None:
        self.name = name
        self.env_var = env_var
        super().__init__(f"Credential '{name}' is required but not set. {how_to_fix}.")


# ---------------------------------------------------------------------------
# Credential spec — describes one credential entry in the registry
# ---------------------------------------------------------------------------


@dataclass
class _CredentialSpec:
    """Private descriptor for a single credential. Never instantiated externally."""

    name: str
    env_var: Optional[str]
    config_path: Optional[tuple[str, str]]  # (channel_name, settings_field)
    how_to_fix: str
    required_check: Callable[[AppConfig], bool]


# ---------------------------------------------------------------------------
# Helpers used only by required_check lambdas (must not import from tools/)
# ---------------------------------------------------------------------------


def _channel_enabled(config: AppConfig, channel_name: str) -> bool:
    ch = config.channels.get(channel_name)
    return ch is not None and ch.enabled


# ---------------------------------------------------------------------------
# Registry — one entry per credential, in a stable order
# ---------------------------------------------------------------------------

CREDENTIAL_REGISTRY: tuple[_CredentialSpec, ...] = (
    _CredentialSpec(
        name="anthropic_api_key",
        env_var="ANTHROPIC_API_KEY",
        config_path=None,
        how_to_fix="Set ANTHROPIC_API_KEY in your environment",
        required_check=lambda config: True,
    ),
    _CredentialSpec(
        name="openai_api_key",
        env_var="OPENAI_API_KEY",
        config_path=None,
        how_to_fix="Set OPENAI_API_KEY in your environment",
        # Not individually required — validated as OR with anthropic_api_key in 43.2.
        required_check=lambda config: False,
    ),
    _CredentialSpec(
        name="serper_api_key",
        env_var="SERPER_API_KEY",
        config_path=None,
        how_to_fix="Set SERPER_API_KEY in your environment",
        required_check=lambda config: any(
            "research_query" in agent.allowed_tools for agent in config.agents.values()
        ),
    ),
    _CredentialSpec(
        name="google_oauth_passphrase",
        env_var="GOOGLE_OAUTH_PASSPHRASE",
        config_path=None,
        how_to_fix="Set GOOGLE_OAUTH_PASSPHRASE in your environment",
        required_check=lambda config: config.google.enabled,
    ),
    _CredentialSpec(
        name="ws_secret",
        env_var="OPENRATTLER_WS_SECRET",
        config_path=None,
        how_to_fix="Set OPENRATTLER_WS_SECRET in your environment",
        # The gateway is always started by build_application(); treat as always
        # required. The dev fallback (_DEV_WS_SECRET) lives in startup.py and is
        # not a real credential — if the env var is absent the manager leaves
        # ws_secret out of _values and startup.py's fallback takes over.
        required_check=lambda config: True,
    ),
    _CredentialSpec(
        name="slack_bot_token",
        env_var=None,
        config_path=("slack", "bot_token"),
        how_to_fix="Add 'bot_token' to channels.slack.settings in config.json",
        required_check=lambda config: _channel_enabled(config, "slack"),
    ),
    _CredentialSpec(
        name="twilio_account_sid",
        env_var=None,
        config_path=("sms", "account_sid"),
        how_to_fix="Add 'account_sid' to channels.sms.settings in config.json",
        required_check=lambda config: _channel_enabled(config, "sms"),
    ),
    _CredentialSpec(
        name="twilio_auth_token",
        env_var=None,
        config_path=("sms", "auth_token"),
        how_to_fix="Add 'auth_token' to channels.sms.settings in config.json",
        required_check=lambda config: _channel_enabled(config, "sms"),
    ),
    _CredentialSpec(
        name="email_password",
        env_var=None,
        config_path=("email", "password"),
        how_to_fix="Add 'password' to channels.email.settings in config.json",
        required_check=lambda config: _channel_enabled(config, "email"),
    ),
)

# Canonical names that form the LLM OR group — either satisfies the requirement.
_LLM_OR_GROUP: frozenset[str] = frozenset({"anthropic_api_key", "openai_api_key"})


# ---------------------------------------------------------------------------
# CredentialManager
# ---------------------------------------------------------------------------


class CredentialManager:
    """Loads, stores, and validates application credentials.

    Reads from two sources at load() time:
    - Environment variables (for env-var credentials)
    - config.channels[name].settings (for channel credentials, when enabled)

    Values in _values are NEVER exposed via repr, str, or exception messages.
    """

    def __init__(self) -> None:
        self._values: dict[str, str] = {}

    def load(self, config: AppConfig) -> None:
        """Read all credentials from env vars and enabled config channels.

        Idempotent — safe to call twice; the second call refreshes the store.
        """
        self._values = {}

        for spec in CREDENTIAL_REGISTRY:
            if spec.env_var is not None:
                value = os.environ.get(spec.env_var, "")
                if value:
                    self._values[spec.name] = value
            elif spec.config_path is not None:
                channel_name, settings_field = spec.config_path
                channel = config.channels.get(channel_name)
                if channel is not None and channel.enabled:
                    raw = channel.settings.get(settings_field, "")
                    value = str(raw) if raw else ""
                    if value:
                        self._values[spec.name] = value

    def get(self, name: str) -> str:
        """Return the credential value for the given canonical name.

        Raises CredentialMissingError with an actionable message if absent.
        """
        if name in self._values:
            return self._values[name]

        spec = next((s for s in CREDENTIAL_REGISTRY if s.name == name), None)
        env_var = spec.env_var if spec else None
        how_to_fix = spec.how_to_fix if spec else f"Ensure '{name}' is configured."
        raise CredentialMissingError(name=name, env_var=env_var, how_to_fix=how_to_fix)

    def is_present(self, name: str) -> bool:
        """True if the credential is loaded and non-empty."""
        return bool(self._values.get(name))

    def loaded_names(self) -> list[str]:
        """Sorted list of canonical credential names currently in the store."""
        return sorted(self._values.keys())

    def missing_for_config(self, config: AppConfig) -> list[_CredentialSpec]:
        """Return specs that are required by config but absent from the store.

        LLM OR logic: if either anthropic_api_key or openai_api_key is loaded,
        neither is reported as missing. If both are absent, one entry is returned
        (for anthropic_api_key, the primary).
        """
        missing: list[_CredentialSpec] = []
        llm_present = any(self.is_present(name) for name in _LLM_OR_GROUP)

        for spec in CREDENTIAL_REGISTRY:
            if spec.name in _LLM_OR_GROUP:
                # Handle the OR group as a unit: report once if the whole group absent.
                if not llm_present and spec.name == "anthropic_api_key":
                    missing.append(spec)
                continue

            if spec.required_check(config) and not self.is_present(spec.name):
                missing.append(spec)

        return missing

    def __repr__(self) -> str:
        return f"CredentialManager({len(self._values)} credentials loaded, values redacted)"

    def __str__(self) -> str:
        return self.__repr__()


# ---------------------------------------------------------------------------
# Convenience constructor
# ---------------------------------------------------------------------------


def build_credential_manager(config: AppConfig) -> CredentialManager:
    """Construct, load, and return a CredentialManager in one call."""
    manager = CredentialManager()
    manager.load(config)
    return manager
