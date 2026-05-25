"""Google API service factory for the 41.x integration layer.

``GoogleClientFactory`` builds and caches the four Google API service objects
used by the tool handlers in ``tools/builtin/``:

  - ``calendar_service()``  → Calendar API v3
  - ``drive_service()``     → Drive API v3
  - ``gmail_service()``     → Gmail API v1
  - ``tasks_service()``     → Tasks API v1

All services are lazily initialized on first access and cached for the lifetime
of the factory instance.  The underlying credentials are fetched from
``GoogleAuthManager`` on each first-call, which handles silent token refresh.

SECURITY NOTES
--------------
- Service objects hold the OAuth credentials; the factory should not be
  shared across trust boundaries.
- Service creation is deferred until first use so a startup error in one
  service (e.g. network unreachable) does not block the others.
"""

from __future__ import annotations

import logging
from typing import Any, Optional

from openrattler.integrations.google.auth import GoogleAuthManager

logger = logging.getLogger(__name__)


class GoogleClientFactory:
    """Factory that lazily builds and caches Google API service objects.

    Args:
        auth: ``GoogleAuthManager`` providing OAuth credentials.
    """

    def __init__(self, auth: GoogleAuthManager) -> None:
        self._auth = auth
        self._calendar: Optional[Any] = None
        self._drive: Optional[Any] = None
        self._gmail: Optional[Any] = None
        self._tasks: Optional[Any] = None

    # ------------------------------------------------------------------
    # Service accessors — lazy, cached
    # ------------------------------------------------------------------

    async def calendar_service(self) -> Any:
        """Return the Google Calendar API v3 service (cached after first call)."""
        if self._calendar is None:
            self._calendar = await self._build("calendar", "v3")
        return self._calendar

    async def drive_service(self) -> Any:
        """Return the Google Drive API v3 service (cached after first call)."""
        if self._drive is None:
            self._drive = await self._build("drive", "v3")
        return self._drive

    async def gmail_service(self) -> Any:
        """Return the Gmail API v1 service (cached after first call)."""
        if self._gmail is None:
            self._gmail = await self._build("gmail", "v1")
        return self._gmail

    async def tasks_service(self) -> Any:
        """Return the Google Tasks API v1 service (cached after first call)."""
        if self._tasks is None:
            self._tasks = await self._build("tasks", "v1")
        return self._tasks

    def reset(self) -> None:
        """Clear all cached service objects so they are rebuilt on next call.

        Call this after an ``invalid_grant`` error so the stale service (with
        expired credentials baked in) is not reused on subsequent tool calls.
        """
        self._calendar = None
        self._drive = None
        self._gmail = None
        self._tasks = None
        logger.debug("GoogleClientFactory: service cache cleared.")

    def clear_auth(self) -> None:
        """Clear service cache and delete the stored credential token file.

        Convenience wrapper that combines ``reset()`` and
        ``auth.clear_credentials()``.  Call from tool handlers when they detect
        an ``invalid_grant`` error inside an API ``execute()`` call.
        """
        self.reset()
        self._auth.clear_credentials()

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    async def _build(self, service_name: str, version: str) -> Any:
        """Build a Google API service using the current credentials."""
        from googleapiclient.discovery import build

        creds = await self._auth.get_credentials()
        svc = build(service_name, version, credentials=creds)
        logger.debug("Built Google API service: %s %s", service_name, version)
        return svc
