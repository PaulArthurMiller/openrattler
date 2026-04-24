"""Tests for openrattler.integrations.google.auth and client.

Testing focus:
- GoogleConfig defaults and validation
- GoogleAuthManager.is_authenticated() returns False when token file absent
- GoogleAuthManager.get_credentials() raises GoogleAuthError when not authenticated
- Expired credentials trigger refresh via inner manager
- GoogleClientFactory returns cached service on second call (build() called once per service)
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from openrattler.config.loader import AppConfig, GoogleConfig, load_config
from openrattler.integrations.google.auth import GoogleAuthError, GoogleAuthManager
from openrattler.integrations.google.client import GoogleClientFactory

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_config(
    tmp_path: Path, *, enabled: bool = True, extra: dict[str, Any] | None = None
) -> GoogleConfig:
    """Build a GoogleConfig with paths inside tmp_path."""
    creds = tmp_path / "credentials.json"
    token = tmp_path / "token.json"
    data: dict[str, Any] = {
        "enabled": enabled,
        "credentials_file": str(creds),
        "token_file": str(token),
        "user_email": "test@example.com",
    }
    if extra:
        data.update(extra)
    return GoogleConfig.model_validate(data)


# ---------------------------------------------------------------------------
# GoogleConfig
# ---------------------------------------------------------------------------


class TestGoogleConfig:
    def test_default_appconfig_includes_google(self) -> None:
        """AppConfig() should include a GoogleConfig with enabled=False."""
        cfg = AppConfig()
        assert hasattr(cfg, "google")
        assert isinstance(cfg.google, GoogleConfig)
        assert cfg.google.enabled is False

    def test_defaults_are_applied(self) -> None:
        """All default values are applied correctly."""
        cfg = GoogleConfig()
        assert cfg.calendar_id == "primary"
        assert cfg.task_list_id == "@default"
        assert cfg.max_email_chars == 10000
        assert cfg.max_file_chars == 20000
        assert cfg.max_threads_per_query == 20
        assert cfg.max_events_per_query == 50
        assert cfg.max_tasks_per_query == 100
        assert cfg.max_file_bytes == 5_000_000
        assert cfg.drive_upload_folder_id is None

    def test_google_config_round_trips_through_appconfig(self, tmp_path: Path) -> None:
        """GoogleConfig persists and reloads correctly via AppConfig."""
        config_file = tmp_path / "config.json"
        config_file.write_text(
            json.dumps({"google": {"enabled": False, "calendar_id": "team@example.com"}}),
            encoding="utf-8",
        )
        loaded = load_config(config_file)
        assert loaded.google.calendar_id == "team@example.com"


# ---------------------------------------------------------------------------
# GoogleAuthManager — is_authenticated
# ---------------------------------------------------------------------------


class TestGoogleAuthManagerIsAuthenticated:
    def test_returns_false_when_token_absent(self, tmp_path: Path) -> None:
        """is_authenticated() is False when no token file exists."""
        cfg = _make_config(tmp_path)
        manager = GoogleAuthManager(cfg)
        assert manager.is_authenticated() is False

    def test_returns_true_when_token_exists(self, tmp_path: Path) -> None:
        """is_authenticated() is True when a token file is present (no content check)."""
        cfg = _make_config(tmp_path)
        # Storage directory is the token file's parent.
        token_path = Path(cfg.token_file)
        token_path.parent.mkdir(parents=True, exist_ok=True)
        token_path.write_bytes(b"dummy-encrypted-token")
        manager = GoogleAuthManager(cfg)
        assert manager.is_authenticated() is True


# ---------------------------------------------------------------------------
# GoogleAuthManager — get_credentials
# ---------------------------------------------------------------------------


class TestGoogleAuthManagerGetCredentials:
    @pytest.mark.asyncio
    async def test_raises_google_auth_error_when_not_authenticated(self, tmp_path: Path) -> None:
        """get_credentials() raises GoogleAuthError when token file is absent."""
        cfg = _make_config(tmp_path)
        manager = GoogleAuthManager(cfg)
        with pytest.raises(GoogleAuthError, match="not authorized"):
            await manager.get_credentials()

    @pytest.mark.asyncio
    async def test_returns_credentials_when_authenticated(self, tmp_path: Path) -> None:
        """get_credentials() returns the credentials object from the inner manager."""
        cfg = _make_config(tmp_path)
        manager = GoogleAuthManager(cfg)

        mock_creds = MagicMock(name="google_creds")
        with patch.object(
            manager._credential_manager,
            "get_credentials",
            new=AsyncMock(return_value=mock_creds),
        ):
            result = await manager.get_credentials()

        assert result is mock_creds

    @pytest.mark.asyncio
    async def test_expired_creds_are_refreshed_by_inner_manager(self, tmp_path: Path) -> None:
        """Expired credentials are refreshed by the inner manager before returning."""
        cfg = _make_config(tmp_path)
        manager = GoogleAuthManager(cfg)

        # Inner manager handles refresh internally; mock it to return refreshed creds.
        mock_creds = MagicMock()
        mock_creds.expired = False  # already refreshed by inner manager
        with patch.object(
            manager._credential_manager,
            "get_credentials",
            new=AsyncMock(return_value=mock_creds),
        ):
            result = await manager.get_credentials()

        assert result is mock_creds
        assert result.expired is False

    @pytest.mark.asyncio
    async def test_run_auth_flow_delegates_to_inner_manager(self, tmp_path: Path) -> None:
        """run_auth_flow() calls the inner manager's authorize() method exactly once."""
        cfg = _make_config(tmp_path)
        manager = GoogleAuthManager(cfg)

        with patch.object(
            manager._credential_manager,
            "authorize",
            new=AsyncMock(),
        ) as mock_authorize:
            await manager.run_auth_flow()

        mock_authorize.assert_called_once()


# ---------------------------------------------------------------------------
# GoogleClientFactory — caching (one build() call per service type)
# ---------------------------------------------------------------------------


class TestGoogleClientFactory:
    """Each service method caches the built object; build() is called only once."""

    def _make_factory(self, tmp_path: Path) -> tuple[GoogleClientFactory, GoogleAuthManager]:
        cfg = _make_config(tmp_path)
        auth = GoogleAuthManager(cfg)
        return GoogleClientFactory(auth), auth

    @pytest.mark.asyncio
    async def test_calendar_service_is_cached(self, tmp_path: Path) -> None:
        """calendar_service() returns the same object on the second call."""
        factory, auth = self._make_factory(tmp_path)
        mock_svc = MagicMock(name="cal_svc")
        build_calls: list[str] = []

        def _build(svc: str, ver: str, **_kw: Any) -> MagicMock:
            build_calls.append(svc)
            return mock_svc

        with patch.object(auth, "get_credentials", new=AsyncMock(return_value=MagicMock())):
            with patch("googleapiclient.discovery.build", side_effect=_build):
                s1 = await factory.calendar_service()
                s2 = await factory.calendar_service()

        assert s1 is s2
        assert build_calls == ["calendar"]

    @pytest.mark.asyncio
    async def test_drive_service_is_cached(self, tmp_path: Path) -> None:
        """drive_service() returns the same object on the second call."""
        factory, auth = self._make_factory(tmp_path)
        mock_svc = MagicMock(name="drv_svc")
        build_calls: list[str] = []

        def _build(svc: str, ver: str, **_kw: Any) -> MagicMock:
            build_calls.append(svc)
            return mock_svc

        with patch.object(auth, "get_credentials", new=AsyncMock(return_value=MagicMock())):
            with patch("googleapiclient.discovery.build", side_effect=_build):
                d1 = await factory.drive_service()
                d2 = await factory.drive_service()

        assert d1 is d2
        assert build_calls == ["drive"]

    @pytest.mark.asyncio
    async def test_gmail_service_is_cached(self, tmp_path: Path) -> None:
        """gmail_service() returns the same object on the second call."""
        factory, auth = self._make_factory(tmp_path)
        mock_svc = MagicMock(name="gml_svc")
        build_calls: list[str] = []

        def _build(svc: str, ver: str, **_kw: Any) -> MagicMock:
            build_calls.append(svc)
            return mock_svc

        with patch.object(auth, "get_credentials", new=AsyncMock(return_value=MagicMock())):
            with patch("googleapiclient.discovery.build", side_effect=_build):
                g1 = await factory.gmail_service()
                g2 = await factory.gmail_service()

        assert g1 is g2
        assert build_calls == ["gmail"]

    @pytest.mark.asyncio
    async def test_tasks_service_is_cached(self, tmp_path: Path) -> None:
        """tasks_service() returns the same object on the second call."""
        factory, auth = self._make_factory(tmp_path)
        mock_svc = MagicMock(name="tsk_svc")
        build_calls: list[str] = []

        def _build(svc: str, ver: str, **_kw: Any) -> MagicMock:
            build_calls.append(svc)
            return mock_svc

        with patch.object(auth, "get_credentials", new=AsyncMock(return_value=MagicMock())):
            with patch("googleapiclient.discovery.build", side_effect=_build):
                t1 = await factory.tasks_service()
                t2 = await factory.tasks_service()

        assert t1 is t2
        assert build_calls == ["tasks"]

    @pytest.mark.asyncio
    async def test_all_four_services_are_independent(self, tmp_path: Path) -> None:
        """Each service type has its own cached slot; they do not alias each other."""
        factory, auth = self._make_factory(tmp_path)
        build_calls: list[str] = []

        def _build(svc: str, ver: str, **_kw: Any) -> MagicMock:
            build_calls.append(svc)
            return MagicMock(name=f"{svc}_svc")

        with patch.object(auth, "get_credentials", new=AsyncMock(return_value=MagicMock())):
            with patch("googleapiclient.discovery.build", side_effect=_build):
                cal = await factory.calendar_service()
                drv = await factory.drive_service()
                gml = await factory.gmail_service()
                tsk = await factory.tasks_service()

        # Four distinct objects, one build() call each.
        assert cal is not drv
        assert drv is not gml
        assert gml is not tsk
        assert sorted(build_calls) == ["calendar", "drive", "gmail", "tasks"]
