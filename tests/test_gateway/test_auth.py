"""Tests for TokenAuth — token generation, validation, expiry, tampering."""

from __future__ import annotations

import time

import pytest

from openrattler.gateway.auth import TokenAuth

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _auth(expiry: int = 3600) -> TokenAuth:
    return TokenAuth(secret="test-secret-key-32-bytes-padded!", expiry_seconds=expiry)


# ---------------------------------------------------------------------------
# Construction
# ---------------------------------------------------------------------------


def test_empty_secret_raises() -> None:
    with pytest.raises(ValueError, match="secret"):
        TokenAuth(secret="")


# ---------------------------------------------------------------------------
# Round-trip
# ---------------------------------------------------------------------------


def test_generate_validate_round_trip() -> None:
    auth = _auth()
    token = auth.generate_token("telegram:u123")
    result = auth.validate_token(token)
    assert result == "telegram:u123"


def test_different_channel_ids() -> None:
    auth = _auth()
    for channel_id in ("cli", "telegram:123", "slack:T1:U2", "mcp"):
        token = auth.generate_token(channel_id)
        assert auth.validate_token(token) == channel_id


def test_no_expiry_zero_always_valid() -> None:
    auth = TokenAuth(secret="s3cr3t", expiry_seconds=0)
    token = auth.generate_token("ch")
    assert auth.validate_token(token) == "ch"


# ---------------------------------------------------------------------------
# Expiry
# ---------------------------------------------------------------------------


def test_expired_token_rejected(monkeypatch: pytest.MonkeyPatch) -> None:
    auth = TokenAuth(secret="s3cr3t", expiry_seconds=60)
    token = auth.generate_token("ch")
    # Simulate the token being used 120 seconds after issuance
    original_time = time.time
    monkeypatch.setattr(time, "time", lambda: original_time() + 120)
    assert auth.validate_token(token) is None


def test_non_expired_token_accepted(monkeypatch: pytest.MonkeyPatch) -> None:
    auth = TokenAuth(secret="s3cr3t", expiry_seconds=3600)
    token = auth.generate_token("ch")
    original_time = time.time
    monkeypatch.setattr(time, "time", lambda: original_time() + 30)
    assert auth.validate_token(token) == "ch"


# ---------------------------------------------------------------------------
# Tampered tokens
# ---------------------------------------------------------------------------


def test_tampered_signature_rejected() -> None:
    auth = _auth()
    token = auth.generate_token("ch")
    parts = token.split(".", 1)
    tampered = parts[0] + ".deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef12345678"
    assert auth.validate_token(tampered) is None


def test_tampered_payload_rejected() -> None:
    auth = _auth()
    token = auth.generate_token("ch")
    import base64
    import json

    parts = token.split(".", 1)
    # Decode payload, change channel_id, re-encode, keep original signature
    pad = -len(parts[0]) % 4
    payload = json.loads(base64.urlsafe_b64decode(parts[0] + "=" * pad))
    payload["channel_id"] = "evil"
    new_b64 = (
        base64.urlsafe_b64encode(json.dumps(payload, separators=(",", ":")).encode())
        .rstrip(b"=")
        .decode()
    )
    tampered = new_b64 + "." + parts[1]
    assert auth.validate_token(tampered) is None


def test_wrong_secret_rejected() -> None:
    auth1 = TokenAuth(secret="correct-secret-xxxxxxxxxx", expiry_seconds=3600)
    auth2 = TokenAuth(secret="wrong-secret-yyyyyyyyyy!", expiry_seconds=3600)
    token = auth1.generate_token("ch")
    assert auth2.validate_token(token) is None


# ---------------------------------------------------------------------------
# Malformed tokens
# ---------------------------------------------------------------------------


def test_empty_string_rejected() -> None:
    assert _auth().validate_token("") is None


def test_no_separator_rejected() -> None:
    assert _auth().validate_token("nodotinhere") is None


def test_garbage_rejected() -> None:
    assert _auth().validate_token("!!!not.a.valid.token!!!") is None


def test_missing_channel_id_rejected() -> None:
    import base64
    import hashlib
    import hmac
    import json

    secret = "test-secret-key-32-bytes-padded!"
    payload = {"iat": int(time.time())}  # no channel_id
    payload_b64 = (
        base64.urlsafe_b64encode(json.dumps(payload, separators=(",", ":")).encode())
        .rstrip(b"=")
        .decode()
    )
    sig = hmac.new(secret.encode(), payload_b64.encode(), hashlib.sha256).hexdigest()
    token = f"{payload_b64}.{sig}"
    assert _auth().validate_token(token) is None
