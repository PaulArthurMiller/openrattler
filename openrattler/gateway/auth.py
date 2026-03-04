"""Token-based authentication for the Gateway WebSocket server.

``TokenAuth`` uses HMAC-SHA256 over a Base64-encoded JSON payload to produce
self-contained signed tokens.  No external JWT library is required.

Token format::

    <base64url-payload>.<hex-hmac-signature>

where ``payload`` is ``{"channel_id": "...", "iat": <unix-seconds>}``.

SECURITY NOTES (SU-007)
------------------------
- Secrets are compared with ``hmac.compare_digest`` to prevent timing attacks.
- Expired tokens are rejected by validating ``iat + expiry_seconds >= now()``.
- Any modification to the payload (or to the signature) causes validation to
  fail because the re-computed HMAC will not match.
- Token generation uses ``secrets``-quality randomness only indirectly (via the
  caller-supplied secret).  The secret should be at least 32 bytes of random
  data and must be kept out of config files or version control.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import time
from typing import Optional

_SEP = "."


class TokenAuth:
    """HMAC-signed, expiring token generator / validator.

    Args:
        secret:          Signing secret.  Must be a non-empty string.  Treat
                         it like a password — never log or expose it.
        expiry_seconds:  How long a token remains valid after issuance.
                         Pass ``0`` to disable expiry (useful in tests only).

    Security notes:
    - All signature comparisons use ``hmac.compare_digest`` (constant-time).
    - ``validate_token`` catches all exceptions internally and returns ``None``
      rather than leaking internal state via error messages.
    """

    def __init__(self, secret: str, expiry_seconds: int = 3600) -> None:
        if not secret:
            raise ValueError("TokenAuth secret must not be empty")
        self._secret: bytes = secret.encode("utf-8")
        self._expiry_seconds = expiry_seconds

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _sign(self, payload_b64: str) -> str:
        """Return the hex HMAC-SHA256 of *payload_b64* under the stored secret."""
        return hmac.new(self._secret, payload_b64.encode("utf-8"), hashlib.sha256).hexdigest()

    @staticmethod
    def _b64_encode(data: bytes) -> str:
        """URL-safe Base64 encode without padding."""
        return base64.urlsafe_b64encode(data).rstrip(b"=").decode("utf-8")

    @staticmethod
    def _b64_decode(s: str) -> bytes:
        """URL-safe Base64 decode, restoring padding."""
        pad = -len(s) % 4
        return base64.urlsafe_b64decode(s + "=" * pad)

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def generate_token(self, channel_id: str) -> str:
        """Create a signed token encoding *channel_id* and the current time.

        Args:
            channel_id: The channel identity to embed in the token.

        Returns:
            An opaque token string safe to transmit in an HTTP header.

        Security notes:
        - ``iat`` (issued-at) is recorded so ``validate_token`` can enforce
          expiry without any server-side state.
        """
        payload = {"channel_id": channel_id, "iat": int(time.time())}
        payload_b64 = self._b64_encode(json.dumps(payload, separators=(",", ":")).encode("utf-8"))
        sig = self._sign(payload_b64)
        return f"{payload_b64}{_SEP}{sig}"

    def validate_token(self, token: str) -> Optional[str]:
        """Validate *token* and return the embedded ``channel_id``, or ``None``.

        Returns ``None`` when:
        - The token is malformed (missing separator, bad Base64, etc.)
        - The HMAC signature does not match.
        - The token has expired (``iat + expiry_seconds < now()``).
        - ``channel_id`` is absent or empty in the payload.

        Security notes:
        - All comparisons use ``hmac.compare_digest`` to prevent timing attacks.
        - All exceptions are swallowed; callers cannot distinguish the failure
          reason (avoids leaking information about the token structure).
        """
        try:
            parts = token.split(_SEP, 1)
            if len(parts) != 2:
                return None
            payload_b64, sig = parts

            # Constant-time signature check
            expected = self._sign(payload_b64)
            if not hmac.compare_digest(sig, expected):
                return None

            # Decode payload
            payload = json.loads(self._b64_decode(payload_b64))

            channel_id = payload.get("channel_id")
            if not isinstance(channel_id, str) or not channel_id:
                return None

            iat = payload.get("iat")
            if not isinstance(iat, (int, float)):
                return None

            # Expiry check (0 means no expiry)
            if self._expiry_seconds > 0:
                if time.time() - float(iat) > self._expiry_seconds:
                    return None

            return channel_id

        except Exception:  # noqa: BLE001
            return None
