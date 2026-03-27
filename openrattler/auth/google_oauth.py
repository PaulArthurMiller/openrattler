"""Google OAuth 2.0 credential manager with Fernet-encrypted token storage.

``GoogleCredentialManager`` handles the full lifecycle of a Google OAuth 2.0
credential set:
  - Initial authorisation via browser-based consent flow
  - Encrypted storage at rest (Fernet + PBKDF2HMAC)
  - Silent automatic refresh when the access token expires
  - Explicit revocation with local cleanup

SECURITY DESIGN
---------------
- Tokens are never written to disk in plaintext.
- The encryption passphrase is resolved from ``GOOGLE_OAUTH_PASSPHRASE``
  first so that automated restarts work without interactive input.
- The passphrase string is never stored as an instance attribute; it is
  returned to the immediate caller (``_encrypt`` / ``_decrypt``) and
  discarded as soon as the call returns.
- The derived Fernet key is not stored after the encrypt/decrypt call.
- Token values (access token, refresh token) are never written to the
  audit log — only event names and scopes are recorded.
- ``client_secrets.json`` identifies the app to Google but does not
  grant access; it must still be kept out of public repositories.
"""

from __future__ import annotations

import asyncio
import getpass
import json
import logging
import os
import webbrowser
from pathlib import Path
from typing import Any, Callable, Optional

import httpx
from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import base64

from openrattler.models.audit import AuditEvent
from openrattler.storage.audit import AuditLog

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

#: Number of PBKDF2 iterations — OWASP recommends ≥ 310 000 for SHA-256;
#: 480 000 is used here for a comfortable safety margin.
_PBKDF2_ITERATIONS: int = 480_000

#: Length of the random salt in bytes.
_SALT_LENGTH: int = 32

#: Google's OAuth token revocation endpoint.
_GOOGLE_REVOKE_URL: str = "https://oauth2.googleapis.com/revoke"

#: Default token URI for Google OAuth 2.0.
_GOOGLE_TOKEN_URI: str = "https://oauth2.googleapis.com/token"


# ---------------------------------------------------------------------------
# Exceptions
# ---------------------------------------------------------------------------


class AuthorizationError(Exception):
    """Raised when credentials are requested but the user has not yet authorized.

    Call ``openrattler auth google`` (or ``manager.authorize()``) to complete
    the OAuth flow and store encrypted credentials before calling
    ``get_credentials()``.
    """


# ---------------------------------------------------------------------------
# GoogleCredentialManager
# ---------------------------------------------------------------------------


class GoogleCredentialManager:
    """Manages Google OAuth 2.0 tokens with Fernet encryption at rest.

    Args:
        credentials_path:   Directory where ``client_secrets.json``,
                            ``google_tokens.enc``, and ``oauth_salt.bin``
                            are stored.  Must not contain ``..``.
        scopes:             OAuth 2.0 scopes requested during authorisation.
        audit:              Optional audit log.  When provided, ``authorize``,
                            ``revoke``, and token refresh events are recorded.
        passphrase_provider: Optional callable that returns the encryption
                            passphrase.  Used as a fallback when
                            ``GOOGLE_OAUTH_PASSPHRASE`` is not set and avoids
                            an interactive ``getpass`` prompt (useful in tests).
        client_secrets_file: Filename of the OAuth client secrets within
                            ``credentials_path``.  Default ``client_secrets.json``.
        token_file:         Filename of the encrypted token within
                            ``credentials_path``.  Default ``google_tokens.enc``.
        callback_port:      Localhost port for the temporary OAuth callback
                            server during ``authorize()``.  Default ``8765``.

    SECURITY NOTES
    --------------
    - Tokens are never stored in plaintext.
    - The passphrase is resolved on every encrypt/decrypt call; it is never
      stored as an instance attribute.
    - ``client_secrets.json`` path is validated to reject ``..`` traversal.
    """

    def __init__(
        self,
        credentials_path: Path,
        scopes: list[str],
        audit: Optional[AuditLog] = None,
        passphrase_provider: Optional[Callable[[], str]] = None,
        client_secrets_file: str = "client_secrets.json",
        token_file: str = "google_tokens.enc",
        callback_port: int = 8765,
    ) -> None:
        self._validate_credentials_path(credentials_path)
        # Create the directory if it doesn't exist so salt / tokens can be written.
        credentials_path.mkdir(parents=True, exist_ok=True, mode=0o700)

        self._credentials_path = credentials_path
        self._scopes = scopes
        self._audit = audit
        # Store the callable, not the passphrase string.
        self._passphrase_provider = passphrase_provider
        self._client_secrets_file = client_secrets_file
        self._token_file = token_file
        self._callback_port = callback_port

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def is_authorized(self) -> bool:
        """Return ``True`` if an encrypted token file exists on disk.

        Does not validate token contents — use ``get_credentials()`` for that.
        """
        return (self._credentials_path / self._token_file).exists()

    async def authorize(self) -> None:
        """Run the full browser-based OAuth consent flow.

        Reads ``client_secrets.json``, constructs the authorisation URL, opens
        the user's browser, starts a temporary ``aiohttp`` callback server to
        receive the redirect code, exchanges the code for tokens, encrypts the
        tokens, and writes them to ``google_tokens.enc``.  The temporary
        callback server is shut down as soon as one valid callback is received.

        Raises:
            FileNotFoundError: If ``client_secrets.json`` is absent.

        Security notes:
        - Token values are never logged; only the scopes are audit-recorded.
        - The callback server shuts down immediately after the first valid
          callback so it does not linger as an open port.
        """
        from google_auth_oauthlib.flow import InstalledAppFlow

        client_secrets = self._credentials_path / self._client_secrets_file
        if not client_secrets.exists():
            raise FileNotFoundError(
                f"client_secrets.json not found at {client_secrets}. "
                "Download it from Google Cloud Console and place it there."
            )

        flow = InstalledAppFlow.from_client_secrets_file(str(client_secrets), self._scopes)
        redirect_uri = f"http://localhost:{self._callback_port}"
        flow.redirect_uri = redirect_uri
        auth_url, _ = flow.authorization_url(prompt="consent")

        logger.info("Opening browser for Google OAuth authorisation…")
        webbrowser.open(auth_url)

        auth_code = await self._wait_for_oauth_callback(self._callback_port)

        flow.fetch_token(code=auth_code)
        creds = flow.credentials

        passphrase = self._resolve_passphrase()
        token_data = json.dumps(
            {
                "token": creds.token,
                "refresh_token": creds.refresh_token,
                "token_uri": creds.token_uri or _GOOGLE_TOKEN_URI,
                "client_id": creds.client_id,
                "client_secret": creds.client_secret,
                "scopes": list(creds.scopes or self._scopes),
            }
        )
        encrypted = self._encrypt(token_data, passphrase)
        token_path = self._credentials_path / self._token_file
        token_path.write_bytes(encrypted)

        logger.info("Google OAuth authorisation complete; tokens encrypted and saved.")

        if self._audit is not None:
            await self._audit.log(
                AuditEvent(
                    event="oauth_authorized",
                    agent_id="google_oauth",
                    details={"scopes": self._scopes},
                )
            )

    async def get_credentials(self) -> Any:
        """Load, decrypt, and return valid Google OAuth 2.0 credentials.

        If the access token is expired, it is silently refreshed using the
        stored refresh token (no browser interaction).  The refreshed tokens
        are re-encrypted and written back to disk.

        Returns:
            ``google.oauth2.credentials.Credentials`` — ready for use with
            the Google API client library.

        Raises:
            AuthorizationError: If no token file exists (not yet authorised).

        Security notes:
        - The passphrase is resolved fresh on each call; it is not cached.
        - Token values are never written to the audit log.
        """
        import google.oauth2.credentials
        import google.auth.transport.requests

        token_path = self._credentials_path / self._token_file
        if not token_path.exists():
            raise AuthorizationError(
                "Not yet authorised. Run 'openrattler auth google' to complete the OAuth flow."
            )

        passphrase = self._resolve_passphrase()
        encrypted = token_path.read_bytes()
        token_data_str = self._decrypt(encrypted, passphrase)
        token_data: dict[str, Any] = json.loads(token_data_str)

        creds = google.oauth2.credentials.Credentials(  # type: ignore[no-untyped-call]
            token=token_data.get("token"),
            refresh_token=token_data.get("refresh_token"),
            token_uri=token_data.get("token_uri", _GOOGLE_TOKEN_URI),
            client_id=token_data.get("client_id"),
            client_secret=token_data.get("client_secret"),
            scopes=token_data.get("scopes"),
        )

        if creds.expired and creds.refresh_token:
            logger.debug("Google access token expired; refreshing silently…")
            creds.refresh(google.auth.transport.requests.Request())

            # Re-encrypt and persist the refreshed tokens immediately.
            refreshed_data = json.dumps(
                {
                    "token": creds.token,
                    "refresh_token": creds.refresh_token,
                    "token_uri": creds.token_uri or _GOOGLE_TOKEN_URI,
                    "client_id": creds.client_id,
                    "client_secret": creds.client_secret,
                    "scopes": list(creds.scopes or self._scopes),
                }
            )
            new_encrypted = self._encrypt(refreshed_data, passphrase)
            token_path.write_bytes(new_encrypted)

            logger.debug("Refreshed tokens re-encrypted and saved.")

            if self._audit is not None:
                await self._audit.log(
                    AuditEvent(
                        event="oauth_token_refreshed",
                        agent_id="google_oauth",
                        details={"scopes": self._scopes},
                    )
                )

        return creds

    async def revoke(self) -> None:
        """Revoke the stored token and delete the local token file.

        Calls Google's token revocation endpoint, then removes
        ``google_tokens.enc``.  After this call, ``is_authorized()`` returns
        ``False`` and ``get_credentials()`` raises ``AuthorizationError``.

        Security notes:
        - The token value sent to the revocation endpoint is not logged.
        - If the revocation HTTP request fails (e.g. network unavailable),
          a warning is logged but the local file is still deleted so the
          user can re-authorise cleanly.
        """
        token_path = self._credentials_path / self._token_file
        if not token_path.exists():
            logger.warning("revoke() called but no token file exists; nothing to revoke.")
            return

        # Decrypt to retrieve the access token for the revocation call.
        passphrase = self._resolve_passphrase()
        encrypted = token_path.read_bytes()
        try:
            token_data_str = self._decrypt(encrypted, passphrase)
            token_data = json.loads(token_data_str)
            access_token = token_data.get("token", "")
        except (InvalidToken, json.JSONDecodeError, KeyError):
            logger.warning("revoke(): could not decrypt token; skipping revocation API call.")
            access_token = ""

        if access_token:
            try:
                async with httpx.AsyncClient(timeout=10.0) as client:
                    resp = await client.post(
                        _GOOGLE_REVOKE_URL,
                        params={"token": access_token},
                        headers={"Content-Type": "application/x-www-form-urlencoded"},
                    )
                if resp.status_code != 200:
                    logger.warning(
                        "Google token revocation returned %d; token may still be active.",
                        resp.status_code,
                    )
            except httpx.HTTPError:
                logger.warning(
                    "Google token revocation request failed; deleting local file anyway."
                )

        # Always delete the local token file regardless of API call result.
        token_path.unlink(missing_ok=True)
        logger.info("Google OAuth tokens revoked and local file deleted.")

        if self._audit is not None:
            await self._audit.log(
                AuditEvent(
                    event="oauth_revoked",
                    agent_id="google_oauth",
                    details={},
                )
            )

    # ------------------------------------------------------------------
    # Passphrase resolution
    # ------------------------------------------------------------------

    def _resolve_passphrase(self) -> str:
        """Return the encryption passphrase without storing it on self.

        Resolution order:
        1. ``GOOGLE_OAUTH_PASSPHRASE`` environment variable (read fresh each call).
        2. Injected ``passphrase_provider`` callable (if set at construction).
        3. Interactive ``getpass`` prompt.

        The returned string is used immediately by the caller (``_encrypt`` or
        ``_decrypt``) and is never assigned to an instance attribute.
        """
        env_val = os.environ.get("GOOGLE_OAUTH_PASSPHRASE")
        if env_val:
            return env_val
        if self._passphrase_provider is not None:
            return self._passphrase_provider()
        return getpass.getpass("Enter Google OAuth passphrase: ")

    # ------------------------------------------------------------------
    # Encryption / decryption
    # ------------------------------------------------------------------

    def _encrypt(self, data: str, passphrase: str) -> bytes:
        """Encrypt *data* with Fernet using a PBKDF2-derived key.

        Args:
            data:       Plaintext string (token JSON) to encrypt.
            passphrase: Encryption passphrase (never stored after this call).

        Returns:
            Fernet-encrypted bytes.

        Security notes:
        - Key derivation uses PBKDF2HMAC with SHA-256 and 480 000 iterations.
        - The derived key object is not stored after this method returns.
        - A unique salt (per-installation, not per-call) is loaded from disk.
        """
        salt = self._load_salt()
        key = self._derive_key(passphrase, salt)
        return Fernet(key).encrypt(data.encode("utf-8"))

    def _decrypt(self, data: bytes, passphrase: str) -> str:
        """Decrypt Fernet-encrypted *data* back to a plaintext string.

        Args:
            data:       Fernet-encrypted bytes.
            passphrase: Decryption passphrase.

        Returns:
            Decrypted plaintext string.

        Raises:
            ``cryptography.fernet.InvalidToken``: If the passphrase is wrong
            or the ciphertext has been tampered with.
        """
        salt = self._load_salt()
        key = self._derive_key(passphrase, salt)
        return Fernet(key).decrypt(data).decode("utf-8")

    def _derive_key(self, passphrase: str, salt: bytes) -> bytes:
        """Derive a 32-byte Fernet key from *passphrase* and *salt*.

        Uses PBKDF2HMAC with SHA-256 and ``_PBKDF2_ITERATIONS`` rounds.
        The derived key is returned to the caller and not stored.
        """
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=_PBKDF2_ITERATIONS,
        )
        return base64.urlsafe_b64encode(kdf.derive(passphrase.encode("utf-8")))

    def _load_salt(self) -> bytes:
        """Return the installation-specific salt, creating it on first use.

        The salt is stored at ``{credentials_path}/oauth_salt.bin``.  If the
        file does not exist, 32 random bytes are generated, written to disk,
        and returned.  The salt is installation-specific but not secret.
        """
        salt_path = self._credentials_path / "oauth_salt.bin"
        if salt_path.exists():
            return salt_path.read_bytes()
        salt = os.urandom(_SALT_LENGTH)
        salt_path.write_bytes(salt)
        return salt

    # ------------------------------------------------------------------
    # Path validation
    # ------------------------------------------------------------------

    def _validate_credentials_path(self, path: Path) -> None:
        """Reject paths that contain path traversal components.

        Args:
            path: The credentials directory path to validate.

        Raises:
            ValueError: If ``..`` appears in any component of *path*.
        """
        if ".." in path.parts:
            raise ValueError(
                f"Credentials path must not contain '..': {path}. "
                "Path traversal is not permitted."
            )

    # ------------------------------------------------------------------
    # Internal OAuth callback server
    # ------------------------------------------------------------------

    async def _wait_for_oauth_callback(self, port: int) -> str:
        """Start a temporary aiohttp server and wait for the OAuth callback.

        Google redirects the user's browser to ``http://localhost:{port}/?code=…``
        after consent is granted.  This method captures that code and shuts the
        server down immediately so it does not linger as an open port.

        Args:
            port: Localhost port to listen on.

        Returns:
            The authorisation code received from Google.
        """
        from aiohttp import web

        code_received: asyncio.Event = asyncio.Event()
        captured_code: list[str] = []

        async def _handle_callback(request: web.Request) -> web.Response:
            code = request.rel_url.query.get("code", "")
            if code:
                captured_code.append(code)
                code_received.set()
            return web.Response(
                text=(
                    "Authorization complete. You can close this window and "
                    "return to the terminal."
                ),
                content_type="text/plain",
            )

        app = web.Application()
        app.router.add_get("/", _handle_callback)

        runner = web.AppRunner(app)
        await runner.setup()
        site = web.TCPSite(runner, "localhost", port)

        try:
            await site.start()
            logger.debug("OAuth callback server listening on localhost:%d", port)
            await code_received.wait()
        finally:
            await runner.cleanup()
            logger.debug("OAuth callback server shut down.")

        return captured_code[0] if captured_code else ""
