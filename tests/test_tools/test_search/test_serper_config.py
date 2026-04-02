"""Tests for serper_config.py — SerperConfig dataclass and get_api_key()."""

import os
import pytest

from openrattler.tools.search.serper_config import (
    ALL_SERPER_ENDPOINTS,
    DEFAULT_ENABLED_ENDPOINTS,
    SerperConfig,
    get_api_key,
)


class TestSerperConfig:
    """SerperConfig construction and validation."""

    def test_default_config_constructs_without_error(self):
        cfg = SerperConfig()
        assert cfg.max_results == 10
        assert cfg.request_timeout_seconds == 10.0
        assert cfg.max_retries == 2
        assert cfg.safe_search == "active"
        assert cfg.enabled_endpoints == DEFAULT_ENABLED_ENDPOINTS
        print("OK: default SerperConfig constructs cleanly")

    def test_enabled_endpoints_defaults_are_subset_of_all(self):
        cfg = SerperConfig()
        assert cfg.enabled_endpoints <= ALL_SERPER_ENDPOINTS
        print(f"OK: default endpoints {cfg.enabled_endpoints} are all known")

    def test_unknown_endpoint_in_enabled_endpoints_raises_value_error(self):
        with pytest.raises(ValueError, match="Unknown Serper endpoints"):
            SerperConfig(enabled_endpoints=frozenset({"not_a_real_endpoint"}))
        print("OK: unknown endpoint raises ValueError")

    def test_max_results_below_1_raises_value_error(self):
        with pytest.raises(ValueError, match="max_results must be between"):
            SerperConfig(max_results=0)
        print("OK: max_results=0 raises ValueError")

    def test_max_results_above_100_raises_value_error(self):
        with pytest.raises(ValueError, match="max_results must be between"):
            SerperConfig(max_results=101)
        print("OK: max_results=101 raises ValueError")

    def test_max_results_at_boundaries_are_valid(self):
        low = SerperConfig(max_results=1)
        high = SerperConfig(max_results=100)
        assert low.max_results == 1
        assert high.max_results == 100
        print("OK: max_results=1 and max_results=100 are both valid")

    def test_request_timeout_zero_raises_value_error(self):
        with pytest.raises(ValueError, match="request_timeout_seconds must be positive"):
            SerperConfig(request_timeout_seconds=0.0)
        print("OK: request_timeout_seconds=0 raises ValueError")

    def test_request_timeout_negative_raises_value_error(self):
        with pytest.raises(ValueError, match="request_timeout_seconds must be positive"):
            SerperConfig(request_timeout_seconds=-1.0)
        print("OK: request_timeout_seconds=-1 raises ValueError")

    def test_max_retries_negative_raises_value_error(self):
        with pytest.raises(ValueError, match="max_retries must be non-negative"):
            SerperConfig(max_retries=-1)
        print("OK: max_retries=-1 raises ValueError")

    def test_max_retries_zero_is_valid(self):
        cfg = SerperConfig(max_retries=0)
        assert cfg.max_retries == 0
        print("OK: max_retries=0 is valid (no retries)")

    def test_invalid_safe_search_raises_value_error(self):
        with pytest.raises(ValueError, match="safe_search must be"):
            SerperConfig(safe_search="maybe")
        print("OK: safe_search='maybe' raises ValueError")

    def test_safe_search_off_is_valid(self):
        cfg = SerperConfig(safe_search="off")
        assert cfg.safe_search == "off"
        print("OK: safe_search='off' is valid")

    def test_safe_search_none_is_valid(self):
        cfg = SerperConfig(safe_search=None)
        assert cfg.safe_search is None
        print("OK: safe_search=None is valid")

    def test_from_app_config_maps_dict_correctly(self):
        raw = {
            "enabled_endpoints": ["search", "news"],
            "max_results": 5,
            "request_timeout_seconds": 15.0,
            "max_retries": 3,
            "retry_delay_seconds": 2.0,
            "max_response_bytes": 256_000,
            "max_field_chars": 1_000,
            "credit_warning_threshold": 200,
            "default_country": "gb",
            "default_language": "en-gb",
            "safe_search": "off",
        }
        cfg = SerperConfig.from_app_config(raw)
        assert cfg.enabled_endpoints == frozenset({"search", "news"})
        assert cfg.max_results == 5
        assert cfg.request_timeout_seconds == 15.0
        assert cfg.max_retries == 3
        assert cfg.retry_delay_seconds == 2.0
        assert cfg.max_response_bytes == 256_000
        assert cfg.max_field_chars == 1_000
        assert cfg.credit_warning_threshold == 200
        assert cfg.default_country == "gb"
        assert cfg.default_language == "en-gb"
        assert cfg.safe_search == "off"
        print("OK: from_app_config maps all fields correctly")

    def test_from_app_config_uses_defaults_for_missing_keys(self):
        cfg = SerperConfig.from_app_config({})
        # Should use DEFAULT_ENABLED_ENDPOINTS as base
        assert cfg.enabled_endpoints == DEFAULT_ENABLED_ENDPOINTS
        assert cfg.max_results == 10
        assert cfg.safe_search == "active"
        print("OK: from_app_config with empty dict uses all defaults")


class TestGetApiKey:
    """get_api_key() reads from environment, never from config."""

    def test_key_present_in_environment_returns_correctly(self, monkeypatch):
        monkeypatch.setenv("SERPER_API_KEY", "test-key-abc123")
        key = get_api_key()
        assert key == "test-key-abc123"
        print("OK: get_api_key() returns env var value")

    def test_key_absent_raises_runtime_error(self, monkeypatch):
        monkeypatch.delenv("SERPER_API_KEY", raising=False)
        with pytest.raises(RuntimeError, match="SERPER_API_KEY environment variable is not set"):
            get_api_key()
        print("OK: absent SERPER_API_KEY raises RuntimeError")

    def test_key_empty_string_raises_runtime_error(self, monkeypatch):
        monkeypatch.setenv("SERPER_API_KEY", "")
        with pytest.raises(RuntimeError, match="SERPER_API_KEY environment variable is not set"):
            get_api_key()
        print("OK: empty SERPER_API_KEY raises RuntimeError")
