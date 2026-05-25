"""Tests for GoogleCredentialManager — encryption, passphrase resolution,
authorisation state, credential retrieval, and audit logging.

All tests use tmp_path and mock the Google libraries so no real API calls are
made.  The real Fernet encryption code runs in every test that exercises
encrypt/decrypt so the security-critical path is always exercised.
"""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from cryptography.fernet import InvalidToken

from openrattler.auth.google_oauth import AuthorizationError, GoogleCredentialManager
from openrattler.models.audit import AuditEvent
from openrattler.storage.audit import AuditLog

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_TEST_PASSPHRASE = "test-passphrase-for-unit-tests"
_TEST_SCOPES = ["https://www.googleapis.com/auth/gmail.readonly"]

_SAMPLE_TOKEN_DATA: dict[str, Any] = {
    "token": "access_token_abc123",
    "refresh_token": "refresh_token_xyz456",
    "token_uri": "https://oauth2.googleapis.com/token",
    "client_id": "client-id.apps.googleusercontent.com",
    "client_secret": "client-secret",
    "scopes": _TEST_SCOPES,
}

_SAMPLE_SECRETS = {
    "installed": {
        "client_id": "client-id.apps.googleusercontent.com",
        "client_secret": "client-secret",
        "redirect_uris": ["http://localhost"],
        "auth_uri": "https://accounts.google.com/o/oauth2/auth",
        "token_uri": "https://oauth2.googleapis.com/token",
    }
}


def _make_manager(
    tmp_path: Path,
    *,
    audit: AuditLog | None = None,
    passphrase_provider=None,
) -> GoogleCredentialManager:
    """Create a manager instance pointing at tmp_path."""
    return GoogleCredentialManager(
        credentials_path=tmp_path,
        scopes=_TEST_SCOPES,
        audit=audit,
        passphrase_provider=passphrase_provider,
    )


def _write_encrypted_token(manager: GoogleCredentialManager, passphrase: str) -> None:
    """Encrypt _SAMPLE_TOKEN_DATA and write it to the manager's token file."""
    encrypted = manager._encrypt(json.dumps(_SAMPLE_TOKEN_DATA), passphrase)
    (manager._credentials_path / manager._token_file).write_bytes(encrypted)


def _write_client_secrets(tmp_path: Path) -> None:
    """Write a minimal client_secrets.json into tmp_path."""
    (tmp_path / "client_secrets.json").write_text(json.dumps(_SAMPLE_SECRETS))


def _make_audit(tmp_path: Path) -> AuditLog:
    return AuditLog(tmp_path / "audit.jsonl")


# ---------------------------------------------------------------------------
# TestEncryption
# ---------------------------------------------------------------------------


class TestEncryption:
    """Verify the encrypt / decrypt round-trip and salt behaviour."""

    def test_encrypt_decrypt_roundtrip(self, tmp_path: Path) -> None:
        manager = _make_manager(tmp_path)
        plaintext = "sensitive token data"
        encrypted = manager._encrypt(plaintext, _TEST_PASSPHRASE)
        result = manager._decrypt(encrypted, _TEST_PASSPHRASE)
        assert result == plaintext

    def test_wrong_passphrase_fails_decrypt(self, tmp_path: Path) -> None:
        manager = _make_manager(tmp_path)
        encrypted = manager._encrypt("some data", _TEST_PASSPHRASE)
        with pytest.raises(InvalidToken):
            manager._decrypt(encrypted, "wrong-passphrase")

    def test_different_data_produces_different_ciphertext(self, tmp_path: Path) -> None:
        # Fernet uses random IV so even same data differs — but different data must differ.
        manager = _make_manager(tmp_path)
        enc_a = manager._encrypt("data-a", _TEST_PASSPHRASE)
        enc_b = manager._encrypt("data-b", _TEST_PASSPHRASE)
        assert enc_a != enc_b

    def test_salt_created_on_first_load(self, tmp_path: Path) -> None:
        manager = _make_manager(tmp_path)
        salt_path = tmp_path / "oauth_salt.bin"
        assert not salt_path.exists()

        salt = manager._load_salt()

        assert salt_path.exists()
        assert len(salt) == 32
        # Second load returns the same bytes (not regenerated).
        assert manager._load_salt() == salt


# ---------------------------------------------------------------------------
# TestPassphraseResolution
# ---------------------------------------------------------------------------


class TestPassphraseResolution:
    """Verify passphrase resolution order and the 'never stored' invariant."""

    def test_env_var_used_when_set(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("GOOGLE_OAUTH_PASSPHRASE", _TEST_PASSPHRASE)
        manager = _make_manager(tmp_path)

        with patch("getpass.getpass") as mock_getpass:
            result = manager._resolve_passphrase()

        assert result == _TEST_PASSPHRASE
        mock_getpass.assert_not_called()

    def test_interactive_prompt_used_when_env_absent(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.delenv("GOOGLE_OAUTH_PASSPHRASE", raising=False)
        manager = _make_manager(tmp_path)

        with patch("getpass.getpass", return_value="typed-passphrase") as mock_getpass:
            result = manager._resolve_passphrase()

        mock_getpass.assert_called_once()
        assert result == "typed-passphrase"

    def test_passphrase_not_stored_on_instance(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """After _resolve_passphrase(), no instance attribute equals the passphrase string."""
        monkeypatch.delenv("GOOGLE_OAUTH_PASSPHRASE", raising=False)
        manager = _make_manager(tmp_path)

        with patch("getpass.getpass", return_value=_TEST_PASSPHRASE):
            manager._resolve_passphrase()

        # Check no instance attribute is the passphrase string itself.
        for attr_val in vars(manager).values():
            assert attr_val != _TEST_PASSPHRASE


# ---------------------------------------------------------------------------
# TestAuthorizationState
# ---------------------------------------------------------------------------


class TestAuthorizationState:
    """Verify is_authorized() and path validation."""

    def test_is_authorized_false_when_no_token_file(self, tmp_path: Path) -> None:
        manager = _make_manager(tmp_path)
        assert manager.is_authorized() is False

    def test_is_authorized_true_when_token_file_exists(self, tmp_path: Path) -> None:
        manager = _make_manager(tmp_path)
        (tmp_path / manager._token_file).write_bytes(b"fake-encrypted-data")
        assert manager.is_authorized() is True

    def test_credentials_path_rejects_path_traversal(self, tmp_path: Path) -> None:
        traversal_path = tmp_path / ".." / "evil"
        with pytest.raises(ValueError, match=r"\.\."):
            GoogleCredentialManager(credentials_path=traversal_path, scopes=_TEST_SCOPES)


# ---------------------------------------------------------------------------
# TestGetCredentials
# ---------------------------------------------------------------------------


class TestGetCredentials:
    """Verify credential loading, refresh, and error conditions."""

    async def test_raises_when_not_authorized(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("GOOGLE_OAUTH_PASSPHRASE", _TEST_PASSPHRASE)
        manager = _make_manager(tmp_path)
        with pytest.raises(AuthorizationError):
            await manager.get_credentials()

    async def test_returns_valid_credentials_without_refresh(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("GOOGLE_OAUTH_PASSPHRASE", _TEST_PASSPHRASE)
        manager = _make_manager(tmp_path)
        _write_encrypted_token(manager, _TEST_PASSPHRASE)

        mock_creds = MagicMock()
        mock_creds.expired = False
        mock_creds.refresh_token = "refresh_token_xyz456"

        with patch("google.oauth2.credentials.Credentials", return_value=mock_creds):
            creds = await manager.get_credentials()

        mock_creds.refresh.assert_not_called()
        assert creds is mock_creds

    async def test_refreshes_expired_token_silently(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("GOOGLE_OAUTH_PASSPHRASE", _TEST_PASSPHRASE)
        manager = _make_manager(tmp_path)
        _write_encrypted_token(manager, _TEST_PASSPHRASE)

        mock_creds = MagicMock()
        mock_creds.expired = True
        mock_creds.refresh_token = "refresh_token_xyz456"
        mock_creds.token = "new_access_token"
        mock_creds.token_uri = "https://oauth2.googleapis.com/token"
        mock_creds.client_id = "client-id"
        mock_creds.client_secret = "client-secret"
        mock_creds.scopes = _TEST_SCOPES
        mock_creds.expiry = None

        with (
            patch("google.oauth2.credentials.Credentials", return_value=mock_creds),
            patch("google.auth.transport.requests.Request") as mock_request_cls,
        ):
            await manager.get_credentials()

        mock_creds.refresh.assert_called_once_with(mock_request_cls.return_value)

    async def test_invalid_grant_clears_token_file_and_raises(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """invalid_grant during refresh must delete the token file and raise AuthorizationError."""
        monkeypatch.setenv("GOOGLE_OAUTH_PASSPHRASE", _TEST_PASSPHRASE)
        manager = _make_manager(tmp_path)
        _write_encrypted_token(manager, _TEST_PASSPHRASE)

        token_path = tmp_path / manager._token_file
        assert token_path.exists()

        mock_creds = MagicMock()
        mock_creds.expired = True
        mock_creds.refresh_token = "stale_refresh_token"
        mock_creds.expiry = None
        mock_creds.refresh.side_effect = Exception("invalid_grant: Bad Request")

        with (
            patch("google.oauth2.credentials.Credentials", return_value=mock_creds),
            patch("google.auth.transport.requests.Request"),
        ):
            with pytest.raises(AuthorizationError, match="refresh token has expired"):
                await manager.get_credentials()

        # Token file must be deleted so is_authorized() returns False.
        assert not token_path.exists()

    def test_clear_tokens_removes_token_file(self, tmp_path: Path) -> None:
        """clear_tokens() must delete the token file."""
        manager = _make_manager(tmp_path)
        token_path = tmp_path / manager._token_file
        token_path.write_bytes(b"fake-encrypted-content")

        assert token_path.exists()
        manager.clear_tokens()
        assert not token_path.exists()

    def test_clear_tokens_noop_when_no_file(self, tmp_path: Path) -> None:
        """clear_tokens() must not raise when the token file does not exist."""
        manager = _make_manager(tmp_path)
        manager.clear_tokens()  # should not raise

    async def test_refreshed_tokens_re_encrypted(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """After refresh, the token file on disk is updated with new token data."""
        monkeypatch.setenv("GOOGLE_OAUTH_PASSPHRASE", _TEST_PASSPHRASE)
        manager = _make_manager(tmp_path)
        _write_encrypted_token(manager, _TEST_PASSPHRASE)

        token_path = tmp_path / manager._token_file
        original_bytes = token_path.read_bytes()

        mock_creds = MagicMock()
        mock_creds.expired = True
        mock_creds.refresh_token = "refresh_token_xyz456"
        mock_creds.token = "refreshed_access_token_NEW"
        mock_creds.token_uri = "https://oauth2.googleapis.com/token"
        mock_creds.client_id = "client-id"
        mock_creds.client_secret = "client-secret"
        mock_creds.scopes = _TEST_SCOPES
        mock_creds.expiry = None

        with (
            patch("google.oauth2.credentials.Credentials", return_value=mock_creds),
            patch("google.auth.transport.requests.Request"),
        ):
            await manager.get_credentials()

        updated_bytes = token_path.read_bytes()
        # File must have been rewritten.
        assert updated_bytes != original_bytes
        # Decrypted updated file must contain the new token.
        decrypted = manager._decrypt(updated_bytes, _TEST_PASSPHRASE)
        data = json.loads(decrypted)
        assert data["token"] == "refreshed_access_token_NEW"


# ---------------------------------------------------------------------------
# TestAuditLogging
# ---------------------------------------------------------------------------


class TestAuditLogging:
    """Verify that authorize, revoke, and refresh write the correct audit events,
    and that token values never appear in any audit record."""

    async def test_authorize_writes_audit_event(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("GOOGLE_OAUTH_PASSPHRASE", _TEST_PASSPHRASE)
        audit = _make_audit(tmp_path)
        manager = _make_manager(tmp_path, audit=audit)
        _write_client_secrets(tmp_path)

        mock_flow = MagicMock()
        mock_flow.authorization_url.return_value = (
            "https://accounts.google.com/o/oauth2/auth?...",
            "state",
        )
        mock_creds = MagicMock()
        mock_creds.token = "access_token_abc"
        mock_creds.refresh_token = "refresh_token_xyz"
        mock_creds.token_uri = "https://oauth2.googleapis.com/token"
        mock_creds.client_id = "client-id"
        mock_creds.client_secret = "secret"
        mock_creds.scopes = _TEST_SCOPES
        mock_creds.expiry = None
        mock_flow.credentials = mock_creds

        logged_events: list[AuditEvent] = []

        async def _capture_log(event: AuditEvent) -> None:
            logged_events.append(event)

        audit.log = _capture_log  # type: ignore[method-assign]

        with (
            patch(
                "google_auth_oauthlib.flow.InstalledAppFlow.from_client_secrets_file",
                return_value=mock_flow,
            ),
            patch("webbrowser.open"),
            patch.object(
                manager, "_wait_for_oauth_callback", new=AsyncMock(return_value="auth_code_123")
            ),
        ):
            await manager.authorize()

        assert any(e.event == "oauth_authorized" for e in logged_events)

    async def test_revoke_writes_audit_event(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("GOOGLE_OAUTH_PASSPHRASE", _TEST_PASSPHRASE)
        audit = _make_audit(tmp_path)
        manager = _make_manager(tmp_path, audit=audit)
        _write_encrypted_token(manager, _TEST_PASSPHRASE)

        logged_events: list[AuditEvent] = []

        async def _capture_log(event: AuditEvent) -> None:
            logged_events.append(event)

        audit.log = _capture_log  # type: ignore[method-assign]

        with patch("httpx.AsyncClient") as mock_client_cls:
            mock_client = AsyncMock()
            mock_client.__aenter__ = AsyncMock(return_value=mock_client)
            mock_client.__aexit__ = AsyncMock(return_value=False)
            mock_response = MagicMock()
            mock_response.status_code = 200
            mock_client.post = AsyncMock(return_value=mock_response)
            mock_client_cls.return_value = mock_client

            await manager.revoke()

        assert any(e.event == "oauth_revoked" for e in logged_events)

    async def test_token_refresh_writes_audit_event(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("GOOGLE_OAUTH_PASSPHRASE", _TEST_PASSPHRASE)
        audit = _make_audit(tmp_path)
        manager = _make_manager(tmp_path, audit=audit)
        _write_encrypted_token(manager, _TEST_PASSPHRASE)

        logged_events: list[AuditEvent] = []

        async def _capture_log(event: AuditEvent) -> None:
            logged_events.append(event)

        audit.log = _capture_log  # type: ignore[method-assign]

        mock_creds = MagicMock()
        mock_creds.expired = True
        mock_creds.refresh_token = "refresh_token_xyz456"
        mock_creds.token = "new_token"
        mock_creds.token_uri = "https://oauth2.googleapis.com/token"
        mock_creds.client_id = "client-id"
        mock_creds.client_secret = "secret"
        mock_creds.scopes = _TEST_SCOPES
        mock_creds.expiry = None

        with (
            patch("google.oauth2.credentials.Credentials", return_value=mock_creds),
            patch("google.auth.transport.requests.Request"),
        ):
            await manager.get_credentials()

        assert any(e.event == "oauth_token_refreshed" for e in logged_events)

    async def test_token_value_not_in_any_audit_event(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Token values must never appear in any audit event's details."""
        monkeypatch.setenv("GOOGLE_OAUTH_PASSPHRASE", _TEST_PASSPHRASE)
        audit = _make_audit(tmp_path)
        manager = _make_manager(tmp_path, audit=audit)
        _write_encrypted_token(manager, _TEST_PASSPHRASE)

        logged_events: list[AuditEvent] = []

        async def _capture_log(event: AuditEvent) -> None:
            logged_events.append(event)

        audit.log = _capture_log  # type: ignore[method-assign]

        access_token = _SAMPLE_TOKEN_DATA["token"]
        refresh_token = _SAMPLE_TOKEN_DATA["refresh_token"]

        mock_creds = MagicMock()
        mock_creds.expired = True
        mock_creds.refresh_token = refresh_token
        mock_creds.token = access_token
        mock_creds.token_uri = "https://oauth2.googleapis.com/token"
        mock_creds.client_id = "client-id"
        mock_creds.client_secret = "secret"
        mock_creds.scopes = _TEST_SCOPES
        mock_creds.expiry = None

        with (
            patch("google.oauth2.credentials.Credentials", return_value=mock_creds),
            patch("google.auth.transport.requests.Request"),
        ):
            await manager.get_credentials()

        for event in logged_events:
            event_str = json.dumps(event.model_dump(), default=str)
            assert (
                access_token not in event_str
            ), f"Access token appeared in audit event: {event.event}"
            assert (
                refresh_token not in event_str
            ), f"Refresh token appeared in audit event: {event.event}"
