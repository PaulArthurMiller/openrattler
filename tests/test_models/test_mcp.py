"""Tests for openrattler.models.mcp — MCP data models."""

import pytest
from pydantic import ValidationError

from openrattler.models.mcp import (
    MCPCallRecord,
    MCPDataAccessPermissions,
    MCPFileSystemPermissions,
    MCPNetworkPermissions,
    MCPPermissions,
    MCPSecurityConfig,
    MCPServerManifest,
    MCPToolManifestEntry,
)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _stdio_manifest(**kwargs: object) -> MCPServerManifest:
    """Return a minimal valid stdio manifest."""
    defaults: dict = dict(
        server_id="weather-mcp",
        version="1.0.0",
        publisher="Acme Corp",
        transport="stdio",
        command="/usr/bin/weather-mcp",
    )
    defaults.update(kwargs)
    return MCPServerManifest(**defaults)


def _http_manifest(**kwargs: object) -> MCPServerManifest:
    """Return a minimal valid streamable-HTTP manifest."""
    defaults: dict = dict(
        server_id="dominos-mcp",
        version="2.1.0",
        publisher="Dominos Inc",
        transport="streamable_http",
        url="https://mcp.dominos.example.com",
    )
    defaults.update(kwargs)
    return MCPServerManifest(**defaults)


# ---------------------------------------------------------------------------
# TestMCPServerManifest
# ---------------------------------------------------------------------------


class TestMCPServerManifest:
    """Construction, validation, and serialization of MCPServerManifest."""

    def test_valid_stdio_manifest(self) -> None:
        m = _stdio_manifest()
        assert m.server_id == "weather-mcp"
        assert m.transport == "stdio"
        assert m.command == "/usr/bin/weather-mcp"
        assert m.url is None

    def test_valid_http_manifest(self) -> None:
        m = _http_manifest()
        assert m.server_id == "dominos-mcp"
        assert m.transport == "streamable_http"
        assert m.url == "https://mcp.dominos.example.com"
        assert m.command is None

    def test_defaults_are_restrictive(self) -> None:
        m = _stdio_manifest()
        assert m.trust_tier == "user_installed"
        assert m.verified is False
        assert m.permissions.exec is False
        assert m.permissions.financial is False
        assert m.tools == []

    def test_server_id_valid_formats(self) -> None:
        for sid in ["a", "abc", "abc-123", "abc_def", "a1b2c3", "weather-mcp-v2"]:
            m = _stdio_manifest(server_id=sid)
            assert m.server_id == sid

    def test_server_id_rejects_uppercase(self) -> None:
        with pytest.raises(ValidationError, match="server_id"):
            _stdio_manifest(server_id="WeatherMCP")

    def test_server_id_rejects_dots(self) -> None:
        with pytest.raises(ValidationError, match="server_id"):
            _stdio_manifest(server_id="weather.mcp")

    def test_server_id_rejects_spaces(self) -> None:
        with pytest.raises(ValidationError, match="server_id"):
            _stdio_manifest(server_id="weather mcp")

    def test_server_id_rejects_leading_hyphen(self) -> None:
        with pytest.raises(ValidationError, match="server_id"):
            _stdio_manifest(server_id="-weather-mcp")

    def test_server_id_rejects_empty(self) -> None:
        with pytest.raises(ValidationError):
            _stdio_manifest(server_id="")

    def test_stdio_requires_command(self) -> None:
        with pytest.raises(ValidationError, match="command"):
            MCPServerManifest(
                server_id="test-mcp",
                version="1.0.0",
                publisher="Test",
                transport="stdio",
                # command deliberately omitted
            )

    def test_http_requires_url(self) -> None:
        with pytest.raises(ValidationError, match="url"):
            MCPServerManifest(
                server_id="test-mcp",
                version="1.0.0",
                publisher="Test",
                transport="streamable_http",
                # url deliberately omitted
            )

    def test_stdio_with_url_is_valid(self) -> None:
        """URL may be present on stdio manifests (it's simply unused)."""
        m = _stdio_manifest(url="https://example.com")
        assert m.url == "https://example.com"
        assert m.command is not None

    def test_tool_list_serialization_round_trip(self) -> None:
        tools = [
            MCPToolManifestEntry(name="get_forecast", requires_approval=False),
            MCPToolManifestEntry(
                name="send_alert",
                requires_approval=True,
                cost_estimate="low",
                side_effects="sends a push notification",
            ),
        ]
        m = _stdio_manifest(tools=tools)
        data = m.model_dump()
        restored = MCPServerManifest(**data)
        assert len(restored.tools) == 2
        assert restored.tools[0].name == "get_forecast"
        assert restored.tools[1].requires_approval is True
        assert restored.tools[1].side_effects == "sends a push notification"

    def test_args_and_env_defaults(self) -> None:
        m = _stdio_manifest()
        assert m.args == []
        assert m.env == {}

    def test_args_and_env_stored(self) -> None:
        m = _stdio_manifest(args=["--port", "8080"], env={"API_KEY_REF": "vault:weather/key"})
        assert m.args == ["--port", "8080"]
        assert m.env == {"API_KEY_REF": "vault:weather/key"}

    def test_trust_tier_bundled(self) -> None:
        m = _stdio_manifest(trust_tier="bundled")
        assert m.trust_tier == "bundled"

    def test_trust_tier_auto_discovered(self) -> None:
        m = _stdio_manifest(trust_tier="auto_discovered")
        assert m.trust_tier == "auto_discovered"

    def test_trust_tier_rejects_unknown(self) -> None:
        with pytest.raises(ValidationError):
            _stdio_manifest(trust_tier="untrusted")  # type: ignore[arg-type]


# ---------------------------------------------------------------------------
# TestMCPPermissions
# ---------------------------------------------------------------------------


class TestMCPPermissions:
    """MCPPermissions defaults are restrictive; explicit grants required."""

    def test_defaults_all_empty(self) -> None:
        p = MCPPermissions()
        assert p.network.allowed_domains == []
        assert p.network.deny_all_others is True
        assert p.data_access.read == []
        assert p.data_access.write == []
        assert p.file_system.read == []
        assert p.file_system.write == []
        assert p.exec is False
        assert p.financial is False
        assert p.max_cost_per_transaction is None

    def test_max_cost_per_transaction_zero_allowed(self) -> None:
        p = MCPPermissions(max_cost_per_transaction=0)
        assert p.max_cost_per_transaction == 0.0

    def test_max_cost_per_transaction_positive(self) -> None:
        p = MCPPermissions(max_cost_per_transaction=49.99)
        assert p.max_cost_per_transaction == 49.99

    def test_max_cost_per_transaction_negative_rejected(self) -> None:
        with pytest.raises(ValidationError):
            MCPPermissions(max_cost_per_transaction=-0.01)

    def test_network_permissions_domain_allowlist(self) -> None:
        p = MCPPermissions(
            network=MCPNetworkPermissions(
                allowed_domains=["api.openweathermap.org", "weather.example.com"],
                deny_all_others=True,
            )
        )
        assert len(p.network.allowed_domains) == 2
        assert p.network.deny_all_others is True

    def test_no_path_chars_in_domains_slash(self) -> None:
        with pytest.raises(ValidationError, match="path characters"):
            MCPNetworkPermissions(allowed_domains=["api.example.com/v1"])

    def test_no_path_chars_in_domains_backslash(self) -> None:
        with pytest.raises(ValidationError, match="path characters"):
            MCPNetworkPermissions(allowed_domains=["api.example.com\\v1"])

    def test_deny_all_others_false_allows_open_network(self) -> None:
        p = MCPNetworkPermissions(allowed_domains=[], deny_all_others=False)
        assert p.deny_all_others is False

    def test_data_access_read_write(self) -> None:
        p = MCPDataAccessPermissions(
            read=["user.address", "user.phone"],
            write=["user.preferences"],
        )
        assert "user.address" in p.read
        assert "user.preferences" in p.write

    def test_file_system_permissions(self) -> None:
        p = MCPFileSystemPermissions(
            read=["/home/user/documents"],
            write=["/tmp/mcp-output"],
        )
        assert p.read == ["/home/user/documents"]
        assert p.write == ["/tmp/mcp-output"]


# ---------------------------------------------------------------------------
# TestMCPSecurityConfig
# ---------------------------------------------------------------------------


class TestMCPSecurityConfig:
    """MCPSecurityConfig defaults and constraint validation."""

    def test_defaults(self) -> None:
        cfg = MCPSecurityConfig()
        assert cfg.allow_bundled is True
        assert cfg.allow_user_installed is True
        assert cfg.allow_auto_discovered == "deny"
        assert cfg.require_multi_channel_auth_for_financial is True
        assert cfg.financial_transaction_limit == 100.00
        assert cfg.approve_every_tool_call is False
        assert cfg.network_isolation == "strict"
        assert cfg.max_response_size_bytes == 100_000
        assert cfg.call_timeout_seconds == 30

    def test_call_timeout_minimum_boundary(self) -> None:
        cfg = MCPSecurityConfig(call_timeout_seconds=5)
        assert cfg.call_timeout_seconds == 5

    def test_call_timeout_maximum_boundary(self) -> None:
        cfg = MCPSecurityConfig(call_timeout_seconds=300)
        assert cfg.call_timeout_seconds == 300

    def test_call_timeout_below_minimum_rejected(self) -> None:
        with pytest.raises(ValidationError):
            MCPSecurityConfig(call_timeout_seconds=4)

    def test_call_timeout_above_maximum_rejected(self) -> None:
        with pytest.raises(ValidationError):
            MCPSecurityConfig(call_timeout_seconds=301)

    def test_financial_limit_zero_allowed(self) -> None:
        cfg = MCPSecurityConfig(financial_transaction_limit=0)
        assert cfg.financial_transaction_limit == 0.0

    def test_financial_limit_negative_rejected(self) -> None:
        with pytest.raises(ValidationError):
            MCPSecurityConfig(financial_transaction_limit=-1.0)

    def test_auto_discovered_allow(self) -> None:
        cfg = MCPSecurityConfig(allow_auto_discovered="allow")
        assert cfg.allow_auto_discovered == "allow"

    def test_auto_discovered_prompt(self) -> None:
        cfg = MCPSecurityConfig(allow_auto_discovered="prompt")
        assert cfg.allow_auto_discovered == "prompt"

    def test_auto_discovered_invalid_rejected(self) -> None:
        with pytest.raises(ValidationError):
            MCPSecurityConfig(allow_auto_discovered="maybe")  # type: ignore[arg-type]

    def test_network_isolation_options(self) -> None:
        for level in ("strict", "moderate", "none"):
            cfg = MCPSecurityConfig(network_isolation=level)  # type: ignore[arg-type]
            assert cfg.network_isolation == level

    def test_approve_every_tool_call_flag(self) -> None:
        cfg = MCPSecurityConfig(approve_every_tool_call=True)
        assert cfg.approve_every_tool_call is True


# ---------------------------------------------------------------------------
# TestMCPCallRecord
# ---------------------------------------------------------------------------


class TestMCPCallRecord:
    """MCPCallRecord construction and security properties."""

    def test_construction_minimal(self) -> None:
        record = MCPCallRecord(
            server_id="weather-mcp",
            tool_name="get_forecast",
            trust_tier="user_installed",
            params_keys=["city", "units"],
            required_approval=False,
        )
        assert record.server_id == "weather-mcp"
        assert record.tool_name == "get_forecast"
        assert record.trust_tier == "user_installed"
        assert record.required_approval is False
        assert record.success is True
        assert record.error is None
        assert record.approval_result is None
        assert record.response_size_bytes is None
        assert record.suspicious_patterns == []
        assert record.duration_ms is None

    def test_params_keys_stores_only_keys(self) -> None:
        """Keys are stored; caller must ensure values are not included."""
        args = {"city": "New York", "api_key": "sk-secret-value", "units": "metric"}
        record = MCPCallRecord(
            server_id="weather-mcp",
            tool_name="get_forecast",
            trust_tier="bundled",
            params_keys=list(args.keys()),  # keys only — values excluded by caller
            required_approval=False,
        )
        # Verify only keys are present; values are not stored in the model at all
        assert set(record.params_keys) == {"city", "api_key", "units"}
        dumped = record.model_dump()
        dumped_str = str(dumped)
        assert "sk-secret-value" not in dumped_str
        assert "New York" not in dumped_str

    def test_construction_full(self) -> None:
        record = MCPCallRecord(
            server_id="dominos-mcp",
            tool_name="place_order",
            trust_tier="user_installed",
            params_keys=["address", "items", "payment_token"],
            required_approval=True,
            approval_result="approved",
            response_size_bytes=1024,
            suspicious_patterns=["prompt_injection"],
            duration_ms=850,
            success=True,
        )
        assert record.approval_result == "approved"
        assert record.response_size_bytes == 1024
        assert "prompt_injection" in record.suspicious_patterns
        assert record.duration_ms == 850

    def test_failed_call_record(self) -> None:
        record = MCPCallRecord(
            server_id="weather-mcp",
            tool_name="get_forecast",
            trust_tier="auto_discovered",
            params_keys=["city"],
            required_approval=False,
            success=False,
            error="Connection timed out after 30 seconds",
        )
        assert record.success is False
        assert "timed out" in (record.error or "")

    def test_serialization_round_trip(self) -> None:
        record = MCPCallRecord(
            server_id="weather-mcp",
            tool_name="get_forecast",
            trust_tier="bundled",
            params_keys=["city", "units"],
            required_approval=False,
            approval_result="not_required",
            response_size_bytes=512,
            duration_ms=120,
        )
        data = record.model_dump()
        restored = MCPCallRecord(**data)
        assert restored.server_id == record.server_id
        assert restored.tool_name == record.tool_name
        assert restored.params_keys == record.params_keys
        assert restored.response_size_bytes == record.response_size_bytes
        assert restored.duration_ms == record.duration_ms


# ---------------------------------------------------------------------------
# TestMCPTrustTier
# ---------------------------------------------------------------------------


class TestMCPTrustTier:
    """Trust tier literal validation via MCPServerManifest."""

    def test_bundled_accepted(self) -> None:
        m = _stdio_manifest(trust_tier="bundled")
        assert m.trust_tier == "bundled"

    def test_user_installed_accepted(self) -> None:
        m = _stdio_manifest(trust_tier="user_installed")
        assert m.trust_tier == "user_installed"

    def test_auto_discovered_accepted(self) -> None:
        m = _stdio_manifest(trust_tier="auto_discovered")
        assert m.trust_tier == "auto_discovered"

    def test_unknown_tier_rejected(self) -> None:
        with pytest.raises(ValidationError):
            _stdio_manifest(trust_tier="trusted")  # type: ignore[arg-type]

    def test_empty_string_rejected(self) -> None:
        with pytest.raises(ValidationError):
            _stdio_manifest(trust_tier="")  # type: ignore[arg-type]

    def test_case_sensitive(self) -> None:
        with pytest.raises(ValidationError):
            _stdio_manifest(trust_tier="Bundled")  # type: ignore[arg-type]
