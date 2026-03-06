"""Tests for openrattler.mcp.bridge — MCPToolBridge security layer.

Test classes:
    TestParamSanitization     — sensitive field handling
    TestResponseValidation    — size limit and suspicious pattern detection
    TestFinancialLimits       — financial permission checks
    TestApprovalFlow          — approval gate behaviour
    TestFullExecutionPath     — end-to-end happy and error paths
    TestAuditLogging          — MCPCallRecord produced on every call
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from openrattler.mcp.bridge import MCPToolBridge, SecurityError
from openrattler.models.agents import AgentConfig, TrustLevel
from openrattler.models.mcp import (
    MCPCallRecord,
    MCPDataAccessPermissions,
    MCPPermissions,
    MCPSecurityConfig,
    MCPServerManifest,
    MCPToolManifestEntry,
)
from openrattler.models.tools import ToolResult
from openrattler.security.approval import ApprovalResult
from openrattler.storage.audit import AuditLog

# ---------------------------------------------------------------------------
# Shared fixtures and helpers
# ---------------------------------------------------------------------------


def _make_manifest(
    *,
    server_id: str = "test-server",
    trust_tier: str = "bundled",
    financial: bool = False,
    max_cost_per_transaction: float | None = None,
    data_access_read: list[str] | None = None,
    tools: list[MCPToolManifestEntry] | None = None,
) -> MCPServerManifest:
    """Build a minimal MCPServerManifest for testing."""
    permissions = MCPPermissions(
        data_access=MCPDataAccessPermissions(read=data_access_read or []),
        financial=financial,
        max_cost_per_transaction=max_cost_per_transaction,
    )
    return MCPServerManifest(
        server_id=server_id,
        version="1.0.0",
        publisher="test",
        verified=True,
        trust_tier=trust_tier,  # type: ignore[arg-type]
        permissions=permissions,
        tools=tools or [],
        transport="stdio",
        command="python",
    )


def _make_agent(trust_level: TrustLevel = TrustLevel.mcp) -> AgentConfig:
    return AgentConfig(
        agent_id="agent:test",
        name="Test Agent",
        description="Bridge test agent",
        model="claude-sonnet-4-5",
        trust_level=trust_level,
        session_key="session-abc",
    )


def _make_security_config(
    *,
    max_response_size_bytes: int = 100_000,
    financial_transaction_limit: float = 100.00,
    approve_every_tool_call: bool = False,
    call_timeout_seconds: int = 30,
) -> MCPSecurityConfig:
    return MCPSecurityConfig(
        max_response_size_bytes=max_response_size_bytes,
        financial_transaction_limit=financial_transaction_limit,
        approve_every_tool_call=approve_every_tool_call,
        call_timeout_seconds=call_timeout_seconds,
    )


def _make_bridge(
    *,
    manifest: MCPServerManifest | None = None,
    security_config: MCPSecurityConfig | None = None,
    approval_manager: Any = None,
    audit: Any = None,
    conn_result: dict[str, Any] | None = None,
    conn_exception: Exception | None = None,
) -> tuple[MCPToolBridge, MagicMock]:
    """Build an MCPToolBridge with a mock MCPManager and optionally a mock conn."""
    manifest = manifest or _make_manifest()
    security_config = security_config or _make_security_config()

    mock_manager = MagicMock()
    mock_manager.get_manifest.return_value = manifest

    mock_conn = MagicMock()
    if conn_exception is not None:
        mock_conn.call_tool = AsyncMock(side_effect=conn_exception)
    else:
        mock_conn.call_tool = AsyncMock(return_value=conn_result or {"data": "ok"})
    mock_manager.get_connection.return_value = mock_conn

    bridge = MCPToolBridge(
        mcp_manager=mock_manager,
        security_config=security_config,
        approval_manager=approval_manager,
        audit=audit,
    )
    return bridge, mock_manager


# ---------------------------------------------------------------------------
# TestParamSanitization
# ---------------------------------------------------------------------------


class TestParamSanitization:
    """_sanitize_params strips sensitive fields not in the manifest read list."""

    def _manifest_with_read(self, read: list[str]) -> MCPServerManifest:
        return _make_manifest(data_access_read=read)

    def test_sensitive_field_stripped_when_not_in_read_list(self) -> None:
        bridge, _ = _make_bridge()
        manifest = self._manifest_with_read(["user.location"])
        result = bridge._sanitize_params(
            {"user.email": "a@b.com", "user.location": "London"},
            manifest,
        )
        assert "user.email" not in result
        assert result["user.location"] == "London"

    def test_payment_field_stripped_when_not_in_read_list(self) -> None:
        bridge, _ = _make_bridge()
        manifest = self._manifest_with_read([])
        result = bridge._sanitize_params({"payment.card": "4111..."}, manifest)
        assert "payment.card" not in result

    def test_credentials_field_stripped_when_not_in_read_list(self) -> None:
        bridge, _ = _make_bridge()
        manifest = self._manifest_with_read([])
        result = bridge._sanitize_params({"credentials.api_key": "secret"}, manifest)
        assert "credentials.api_key" not in result

    def test_non_sensitive_field_always_passes_through(self) -> None:
        bridge, _ = _make_bridge()
        manifest = self._manifest_with_read([])
        result = bridge._sanitize_params(
            {"location": "NYC", "days": 3, "query": "weather"},
            manifest,
        )
        assert result == {"location": "NYC", "days": 3, "query": "weather"}

    def test_sensitive_field_allowed_when_in_read_list(self) -> None:
        bridge, _ = _make_bridge()
        manifest = self._manifest_with_read(["user.email", "user.phone"])
        result = bridge._sanitize_params(
            {"user.email": "a@b.com", "user.phone": "555-0100"},
            manifest,
        )
        assert result == {"user.email": "a@b.com", "user.phone": "555-0100"}

    def test_empty_read_list_strips_all_sensitive_fields(self) -> None:
        bridge, _ = _make_bridge()
        manifest = self._manifest_with_read([])
        result = bridge._sanitize_params(
            {
                "user.name": "Alice",
                "payment.billing": "123 Main St",
                "credentials.token": "tok_xyz",
                "city": "Berlin",
            },
            manifest,
        )
        assert "user.name" not in result
        assert "payment.billing" not in result
        assert "credentials.token" not in result
        assert result["city"] == "Berlin"

    def test_mixed_sensitive_and_non_sensitive(self) -> None:
        bridge, _ = _make_bridge()
        manifest = self._manifest_with_read(["user.location"])
        result = bridge._sanitize_params(
            {
                "user.location": "Paris",
                "user.email": "x@y.com",
                "query": "forecast",
            },
            manifest,
        )
        assert result == {"user.location": "Paris", "query": "forecast"}


# ---------------------------------------------------------------------------
# TestResponseValidation
# ---------------------------------------------------------------------------


class TestResponseValidation:
    """_validate_response checks size and suspicious patterns."""

    def test_response_under_size_limit_passes(self) -> None:
        bridge, _ = _make_bridge(
            security_config=_make_security_config(max_response_size_bytes=1000)
        )
        manifest = _make_manifest()
        result, patterns = bridge._validate_response({"data": "small"}, manifest)
        assert result == {"data": "small"}
        assert patterns == []

    def test_response_over_size_limit_raises_security_error(self) -> None:
        bridge, _ = _make_bridge(security_config=_make_security_config(max_response_size_bytes=10))
        manifest = _make_manifest()
        large = {"data": "x" * 100}
        with pytest.raises(SecurityError, match="exceeds size limit"):
            bridge._validate_response(large, manifest)

    def test_suspicious_pattern_detected_returns_category(self) -> None:
        bridge, _ = _make_bridge()
        manifest = _make_manifest()
        suspicious_payload = {"output": "api_key: abc123"}
        _, patterns = bridge._validate_response(suspicious_payload, manifest)
        assert "credential_leak" in patterns

    def test_bearer_token_pattern_detected(self) -> None:
        bridge, _ = _make_bridge()
        manifest = _make_manifest()
        payload = {"auth": "Bearer eyJhbGciOiJIUzI1NiJ9.abc.xyz"}
        _, patterns = bridge._validate_response(payload, manifest)
        assert "credential_leak" in patterns

    def test_private_key_pattern_detected(self) -> None:
        bridge, _ = _make_bridge()
        manifest = _make_manifest()
        payload = {"content": "-----BEGIN RSA PRIVATE KEY-----\nMIIE..."}
        _, patterns = bridge._validate_response(payload, manifest)
        assert "credential_leak" in patterns

    def test_clean_response_returns_empty_suspicious_list(self) -> None:
        bridge, _ = _make_bridge()
        manifest = _make_manifest()
        payload = {"forecast": "Sunny, 22°C", "humidity": 60}
        _, patterns = bridge._validate_response(payload, manifest)
        assert patterns == []

    def test_duplicate_pattern_categories_deduplicated(self) -> None:
        """Multiple credential patterns in one response → only one 'credential_leak' entry."""
        bridge, _ = _make_bridge()
        manifest = _make_manifest()
        payload = {"a": "api_key: abc", "b": "password: xyz"}
        _, patterns = bridge._validate_response(payload, manifest)
        assert patterns.count("credential_leak") == 1


# ---------------------------------------------------------------------------
# TestFinancialLimits
# ---------------------------------------------------------------------------


class TestFinancialLimits:
    """_check_financial_limits enforces financial caps."""

    def _tool_entry(self) -> MCPToolManifestEntry:
        return MCPToolManifestEntry(name="pay", requires_approval=False)

    def test_non_financial_server_skips_check(self) -> None:
        bridge, _ = _make_bridge(
            security_config=_make_security_config(financial_transaction_limit=10.0)
        )
        manifest = _make_manifest(financial=False)
        # Should not raise even with a large amount.
        bridge._check_financial_limits(self._tool_entry(), manifest, {"amount": 9999.0})

    def test_financial_tool_within_limit_passes(self) -> None:
        bridge, _ = _make_bridge(
            security_config=_make_security_config(financial_transaction_limit=100.0)
        )
        manifest = _make_manifest(financial=True, max_cost_per_transaction=50.0)
        bridge._check_financial_limits(self._tool_entry(), manifest, {"amount": 25.0})

    def test_financial_tool_over_config_limit_raises_permission_error(self) -> None:
        bridge, _ = _make_bridge(
            security_config=_make_security_config(financial_transaction_limit=50.0)
        )
        manifest = _make_manifest(financial=True)
        with pytest.raises(PermissionError, match="global limit"):
            bridge._check_financial_limits(self._tool_entry(), manifest, {"amount": 75.0})

    def test_financial_tool_over_manifest_limit_raises_permission_error(self) -> None:
        bridge, _ = _make_bridge(
            security_config=_make_security_config(financial_transaction_limit=500.0)
        )
        manifest = _make_manifest(financial=True, max_cost_per_transaction=30.0)
        with pytest.raises(PermissionError, match="manifest limit"):
            bridge._check_financial_limits(self._tool_entry(), manifest, {"amount": 40.0})

    def test_no_amount_in_params_defaults_to_zero(self) -> None:
        bridge, _ = _make_bridge(
            security_config=_make_security_config(financial_transaction_limit=100.0)
        )
        manifest = _make_manifest(financial=True)
        # Zero amount should always pass.
        bridge._check_financial_limits(self._tool_entry(), manifest, {})


# ---------------------------------------------------------------------------
# TestApprovalFlow
# ---------------------------------------------------------------------------


class TestApprovalFlow:
    """Approval gate wired into execute()."""

    def _approved_manager(self) -> MagicMock:
        mgr = MagicMock()
        mgr.default_timeout_seconds = 30
        mgr.request_approval = AsyncMock(
            return_value=ApprovalResult(
                approval_id="appr-1",
                approved=True,
                decided_by="cli:user",
                timestamp=datetime.now(timezone.utc),
            )
        )
        return mgr

    def _denied_manager(self) -> MagicMock:
        mgr = MagicMock()
        mgr.default_timeout_seconds = 30
        mgr.request_approval = AsyncMock(
            return_value=ApprovalResult(
                approval_id="appr-2",
                approved=False,
                decided_by="cli:user",
                timestamp=datetime.now(timezone.utc),
            )
        )
        return mgr

    @pytest.mark.asyncio
    async def test_tool_requiring_approval_triggers_approval_manager(self) -> None:
        tool_entry = MCPToolManifestEntry(name="send-sms", requires_approval=True)
        manifest = _make_manifest(tools=[tool_entry])
        appr_mgr = self._approved_manager()
        bridge, _ = _make_bridge(manifest=manifest, approval_manager=appr_mgr)
        agent = _make_agent()

        await bridge.execute(
            server_id="test-server",
            tool_name="send-sms",
            params={},
            agent_config=agent,
            session_key="sess",
            trace_id="t1",
        )

        appr_mgr.request_approval.assert_awaited_once()

    @pytest.mark.asyncio
    async def test_denied_approval_returns_error_tool_result(self) -> None:
        tool_entry = MCPToolManifestEntry(name="send-sms", requires_approval=True)
        manifest = _make_manifest(tools=[tool_entry])
        bridge, _ = _make_bridge(manifest=manifest, approval_manager=self._denied_manager())
        agent = _make_agent()

        result = await bridge.execute(
            server_id="test-server",
            tool_name="send-sms",
            params={},
            agent_config=agent,
            session_key="sess",
            trace_id="t1",
        )

        assert result.success is False
        assert "denied" in (result.error or "").lower()

    @pytest.mark.asyncio
    async def test_approved_call_proceeds_to_execution(self) -> None:
        tool_entry = MCPToolManifestEntry(name="send-sms", requires_approval=True)
        manifest = _make_manifest(tools=[tool_entry])
        bridge, mock_mgr = _make_bridge(
            manifest=manifest,
            approval_manager=self._approved_manager(),
            conn_result={"sent": True},
        )
        agent = _make_agent()

        result = await bridge.execute(
            server_id="test-server",
            tool_name="send-sms",
            params={},
            agent_config=agent,
            session_key="sess",
            trace_id="t1",
        )

        assert result.success is True
        mock_mgr.get_connection.return_value.call_tool.assert_awaited_once()

    @pytest.mark.asyncio
    async def test_tool_without_approval_skips_approval_manager(self) -> None:
        tool_entry = MCPToolManifestEntry(name="get-data", requires_approval=False)
        manifest = _make_manifest(tools=[tool_entry])
        appr_mgr = self._approved_manager()
        bridge, _ = _make_bridge(manifest=manifest, approval_manager=appr_mgr)
        agent = _make_agent()

        await bridge.execute(
            server_id="test-server",
            tool_name="get-data",
            params={},
            agent_config=agent,
            session_key="sess",
            trace_id="t1",
        )

        appr_mgr.request_approval.assert_not_awaited()

    @pytest.mark.asyncio
    async def test_approve_every_tool_call_config_triggers_approval(self) -> None:
        """approve_every_tool_call=True requires approval even for non-approval tools."""
        tool_entry = MCPToolManifestEntry(name="get-data", requires_approval=False)
        manifest = _make_manifest(tools=[tool_entry])
        appr_mgr = self._approved_manager()
        cfg = _make_security_config(approve_every_tool_call=True)
        bridge, _ = _make_bridge(
            manifest=manifest,
            security_config=cfg,
            approval_manager=appr_mgr,
        )
        agent = _make_agent()

        await bridge.execute(
            server_id="test-server",
            tool_name="get-data",
            params={},
            agent_config=agent,
            session_key="sess",
            trace_id="t1",
        )

        appr_mgr.request_approval.assert_awaited_once()


# ---------------------------------------------------------------------------
# TestFullExecutionPath
# ---------------------------------------------------------------------------


class TestFullExecutionPath:
    """End-to-end execute() paths — happy, error, and wrong trust level."""

    @pytest.mark.asyncio
    async def test_successful_call_returns_tool_result(self) -> None:
        bridge, _ = _make_bridge(conn_result={"forecast": "sunny"})
        agent = _make_agent()

        result = await bridge.execute(
            server_id="test-server",
            tool_name="get_forecast",
            params={"location": "London"},
            agent_config=agent,
            session_key="sess",
            trace_id="tr1",
        )

        assert result.success is True
        assert result.result == {"forecast": "sunny"}
        assert result.error is None

    @pytest.mark.asyncio
    async def test_connection_error_returns_error_tool_result(self) -> None:
        bridge, _ = _make_bridge(conn_exception=ConnectionError("timeout"))
        agent = _make_agent()

        result = await bridge.execute(
            server_id="test-server",
            tool_name="get_forecast",
            params={},
            agent_config=agent,
            session_key="sess",
            trace_id="tr2",
        )

        assert result.success is False
        assert "timeout" in (result.error or "")

    @pytest.mark.asyncio
    async def test_server_not_found_returns_error_tool_result(self) -> None:
        bridge, mock_mgr = _make_bridge()
        mock_mgr.get_manifest.side_effect = KeyError("no-such-server")
        agent = _make_agent()

        result = await bridge.execute(
            server_id="no-such-server",
            tool_name="tool",
            params={},
            agent_config=agent,
            session_key="sess",
            trace_id="tr3",
        )

        assert result.success is False

    @pytest.mark.asyncio
    async def test_wrong_trust_level_returns_error_tool_result(self) -> None:
        bridge, _ = _make_bridge()
        agent = _make_agent(trust_level=TrustLevel.main)  # 'main', not 'mcp'

        result = await bridge.execute(
            server_id="test-server",
            tool_name="tool",
            params={},
            agent_config=agent,
            session_key="sess",
            trace_id="tr4",
        )

        assert result.success is False
        assert "trust level" in (result.error or "").lower()

    @pytest.mark.asyncio
    async def test_response_over_size_limit_returns_error_tool_result(self) -> None:
        huge = {"data": "x" * 200}
        bridge, _ = _make_bridge(
            security_config=_make_security_config(max_response_size_bytes=50),
            conn_result=huge,
        )
        agent = _make_agent()

        result = await bridge.execute(
            server_id="test-server",
            tool_name="get_data",
            params={},
            agent_config=agent,
            session_key="sess",
            trace_id="tr5",
        )

        assert result.success is False
        assert "size" in (result.error or "").lower()

    @pytest.mark.asyncio
    async def test_trace_id_used_as_call_id(self) -> None:
        bridge, _ = _make_bridge(conn_result={"ok": True})
        agent = _make_agent()

        result = await bridge.execute(
            server_id="test-server",
            tool_name="tool",
            params={},
            agent_config=agent,
            session_key="sess",
            trace_id="my-trace-999",
        )

        assert result.call_id == "my-trace-999"

    @pytest.mark.asyncio
    async def test_permission_error_returns_error_tool_result(self) -> None:
        """PermissionError (e.g. financial limit) propagates as error ToolResult."""
        bridge, _ = _make_bridge(
            manifest=_make_manifest(financial=True),
            security_config=_make_security_config(financial_transaction_limit=10.0),
            conn_result={"ok": True},
        )
        agent = _make_agent()

        result = await bridge.execute(
            server_id="test-server",
            tool_name="pay",
            params={"amount": 500.0},
            agent_config=agent,
            session_key="sess",
            trace_id="tr6",
        )

        assert result.success is False
        assert "global limit" in (result.error or "")


# ---------------------------------------------------------------------------
# TestAuditLogging
# ---------------------------------------------------------------------------


class TestAuditLogging:
    """MCPCallRecord is logged on every call."""

    def _make_audit(self) -> tuple[AuditLog, list[Any]]:
        captured: list[Any] = []

        async def _log(event: Any) -> None:
            captured.append(event)

        audit = MagicMock(spec=AuditLog)
        audit.log = _log
        return audit, captured

    @pytest.mark.asyncio
    async def test_successful_call_produces_audit_event(self) -> None:
        audit, captured = self._make_audit()
        bridge, _ = _make_bridge(conn_result={"data": "ok"}, audit=audit)
        agent = _make_agent()

        await bridge.execute(
            server_id="test-server",
            tool_name="get_data",
            params={"query": "x"},
            agent_config=agent,
            session_key="sess-1",
            trace_id="tr",
        )

        assert len(captured) == 1
        event = captured[0]
        assert event.event == "mcp_tool_call"

    @pytest.mark.asyncio
    async def test_audit_record_includes_timing(self) -> None:
        audit, captured = self._make_audit()
        bridge, _ = _make_bridge(conn_result={"d": "ok"}, audit=audit)
        agent = _make_agent()

        await bridge.execute(
            server_id="test-server",
            tool_name="t",
            params={},
            agent_config=agent,
            session_key="s",
            trace_id="tr",
        )

        details = captured[0].details
        assert "duration_ms" in details
        assert isinstance(details["duration_ms"], int)

    @pytest.mark.asyncio
    async def test_audit_record_includes_response_size(self) -> None:
        audit, captured = self._make_audit()
        conn_result = {"message": "hello world"}
        bridge, _ = _make_bridge(conn_result=conn_result, audit=audit)
        agent = _make_agent()

        await bridge.execute(
            server_id="test-server",
            tool_name="t",
            params={},
            agent_config=agent,
            session_key="s",
            trace_id="tr",
        )

        details = captured[0].details
        expected_size = len(json.dumps(conn_result).encode("utf-8"))
        assert details["response_size_bytes"] == expected_size

    @pytest.mark.asyncio
    async def test_audit_record_includes_params_keys_only(self) -> None:
        """Param values must never appear in audit records."""
        audit, captured = self._make_audit()
        bridge, _ = _make_bridge(conn_result={"ok": True}, audit=audit)
        agent = _make_agent()

        await bridge.execute(
            server_id="test-server",
            tool_name="t",
            params={"query": "secret_value", "city": "London"},
            agent_config=agent,
            session_key="s",
            trace_id="tr",
        )

        details = captured[0].details
        assert "params_keys" in details
        # Keys present
        assert set(details["params_keys"]) == {"query", "city"}
        # Values must not appear
        audit_str = json.dumps(details)
        assert "secret_value" not in audit_str

    @pytest.mark.asyncio
    async def test_suspicious_patterns_recorded_in_audit(self) -> None:
        audit, captured = self._make_audit()
        suspicious_result = {"output": "api_key: sk-abc123"}
        bridge, _ = _make_bridge(conn_result=suspicious_result, audit=audit)
        agent = _make_agent()

        await bridge.execute(
            server_id="test-server",
            tool_name="t",
            params={},
            agent_config=agent,
            session_key="s",
            trace_id="tr",
        )

        details = captured[0].details
        assert "credential_leak" in details["suspicious_patterns"]

    @pytest.mark.asyncio
    async def test_error_path_still_produces_audit_event(self) -> None:
        audit, captured = self._make_audit()
        bridge, _ = _make_bridge(
            conn_exception=RuntimeError("server blew up"),
            audit=audit,
        )
        agent = _make_agent()

        result = await bridge.execute(
            server_id="test-server",
            tool_name="t",
            params={},
            agent_config=agent,
            session_key="s",
            trace_id="tr",
        )

        assert result.success is False
        assert len(captured) == 1
        assert captured[0].details["success"] is False

    @pytest.mark.asyncio
    async def test_approval_result_recorded_in_audit(self) -> None:
        audit, captured = self._make_audit()
        tool_entry = MCPToolManifestEntry(name="act", requires_approval=True)
        manifest = _make_manifest(tools=[tool_entry])

        mgr = MagicMock()
        mgr.default_timeout_seconds = 30
        mgr.request_approval = AsyncMock(
            return_value=ApprovalResult(
                approval_id="a1",
                approved=True,
                decided_by="cli:user",
                timestamp=datetime.now(timezone.utc),
            )
        )

        bridge, _ = _make_bridge(manifest=manifest, approval_manager=mgr, audit=audit)
        agent = _make_agent()

        await bridge.execute(
            server_id="test-server",
            tool_name="act",
            params={},
            agent_config=agent,
            session_key="s",
            trace_id="tr",
        )

        details = captured[0].details
        assert details["approval_result"] == "approved"

    @pytest.mark.asyncio
    async def test_no_audit_log_does_not_raise(self) -> None:
        """Bridge without an AuditLog must not raise."""
        bridge, _ = _make_bridge(audit=None, conn_result={"ok": True})
        agent = _make_agent()

        result = await bridge.execute(
            server_id="test-server",
            tool_name="t",
            params={},
            agent_config=agent,
            session_key="s",
            trace_id="tr",
        )
        assert result.success is True
