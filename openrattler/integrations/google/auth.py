"""Google OAuth 2.0 authentication manager for the 41.x integration layer.

``GoogleAuthManager`` wraps ``GoogleCredentialManager`` from ``openrattler.auth``
to provide the interface used by the 41.x tool handlers:

  - ``is_authenticated()``  — check without side effects
  - ``get_credentials()``   — return a live ``google.oauth2.credentials.Credentials``
                              object, refreshing silently if needed
  - ``run_auth_flow()``     — run the browser-based consent flow once

Tokens are stored via the existing Fernet-encrypted storage so the security
posture of the credential layer is not downgraded by the 41.x tools.

SECURITY NOTES
--------------
- Token storage is delegated to ``GoogleCredentialManager``, which uses
  Fernet encryption at rest (PBKDF2-derived key, per-installation salt).
- ``get_credentials()`` raises ``GoogleAuthError`` if not authenticated,
  giving callers a typed exception to catch rather than ``AuthorizationError``
  from the inner manager.
- ``GOOGLE_OAUTH_PASSPHRASE`` env var is read by the inner manager; this
  class never touches it directly.
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import TYPE_CHECKING, Any

from openrattler.auth.google_oauth import AuthorizationError, GoogleCredentialManager
from openrattler.config.loader import GoogleConfig

if TYPE_CHECKING:
    pass  # avoid circular imports

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Exception
# ---------------------------------------------------------------------------


class GoogleAuthError(Exception):
    """Raised when valid credentials are requested but are unavailable.

    Callers should catch this and surface a helpful message directing the
    user to run ``openrattler auth google`` or ``openrattler google-auth``.
    """


# ---------------------------------------------------------------------------
# GoogleAuthManager
# ---------------------------------------------------------------------------


class GoogleAuthManager:
    """Authentication manager for the Google Workspace integration layer.

    Wraps ``GoogleCredentialManager`` to provide the credential lifecycle used
    by ``GoogleClientFactory`` and the 41.x tool handlers.

    Args:
        config: ``GoogleConfig`` section from ``AppConfig``.
    """

    def __init__(self, config: GoogleConfig) -> None:
        credentials_file = Path(config.credentials_file)
        token_file_path = Path(config.token_file)
        # Derive the credentials directory and token filename from the config paths.
        creds_dir = credentials_file.parent
        token_filename = token_file_path.name

        # Ensure both config paths live in the same directory; if the token path
        # specifies a different directory, use its parent instead.
        token_dir = token_file_path.parent
        if token_dir != creds_dir:
            # Use the token file's directory for storage; put client secrets there too.
            storage_dir = token_dir
        else:
            storage_dir = creds_dir

        self._credential_manager = GoogleCredentialManager(
            credentials_path=storage_dir,
            scopes=_GOOGLE_WORKSPACE_SCOPES,
            client_secrets_file=credentials_file.name,
            token_file=token_filename,
        )

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def is_authenticated(self) -> bool:
        """Return ``True`` if valid (non-expired) credentials appear to exist.

        This checks only for file presence — it does not validate token contents
        or perform a network call.  Use ``get_credentials()`` for that.
        """
        return self._credential_manager.is_authorized()

    async def get_credentials(self) -> Any:
        """Load and return valid Google OAuth 2.0 credentials.

        If the access token is expired it is silently refreshed using the
        stored refresh token.  Returns a ``google.oauth2.credentials.Credentials``
        object ready to pass to ``googleapiclient.discovery.build()``.

        Raises:
            GoogleAuthError: If not authenticated (token file absent).

        Security notes:
        - Token values are never logged.
        - The refresh passphrase is resolved from ``GOOGLE_OAUTH_PASSPHRASE`` by
          the inner manager; it is never stored on this object.
        """
        try:
            return await self._credential_manager.get_credentials()
        except AuthorizationError as exc:
            raise GoogleAuthError(
                "Google Workspace not authorized.  "
                "Run 'openrattler auth google' or 'openrattler google-auth' "
                "to complete the OAuth flow."
            ) from exc

    def clear_credentials(self) -> None:
        """Delete the stored token file without revoking at Google.

        Call this when Google returns ``invalid_grant`` from inside an API call
        (not during an explicit refresh) so ``is_authorized()`` returns ``False``
        and subsequent attempts surface a clean error rather than repeated API failures.
        """
        self._credential_manager.clear_tokens()
        logger.info("GoogleAuthManager: credentials cleared — re-auth required.")

    async def run_auth_flow(self) -> None:
        """Run the browser-based OAuth consent flow.

        Opens the user's browser, waits for the redirect callback, exchanges
        the code for tokens, and saves encrypted tokens to disk.

        Raises:
            FileNotFoundError: If ``credentials_file`` (client secrets) is absent.
        """
        logger.info("Starting Google OAuth consent flow…")
        await self._credential_manager.authorize()
        logger.info("Google OAuth flow complete.")


# Scopes requested during the auth flow — all four Google Workspace APIs.
_GOOGLE_WORKSPACE_SCOPES: list[str] = [
    "https://www.googleapis.com/auth/calendar.events",
    "https://www.googleapis.com/auth/tasks",
    "https://www.googleapis.com/auth/drive",
    "https://www.googleapis.com/auth/gmail.modify",
]
