"""Tests for serper_client.py — HTTP client with mocked network calls."""

import json
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from openrattler.tools.search.serper_client import (
    SerperAuthError,
    SerperClient,
    SerperClientError,
    SerperEndpointNotAllowedError,
    SerperRateLimitError,
    SerperResponseTooLargeError,
    _parse_credits,
)
from openrattler.tools.search.serper_config import SerperConfig
from openrattler.tools.search.serper_models import SerperCredits
from openrattler.tools.search.serper_sanitizer import SerperSanitizationError

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _minimal_search_config(
    max_retries: int = 0,
    retry_delay_seconds: float = 0.0,
    max_response_bytes: int = 512_000,
    credit_warning_threshold: int = 0,
) -> SerperConfig:
    """Config with retries and delay stripped for fast unit tests."""
    return SerperConfig(
        max_retries=max_retries,
        retry_delay_seconds=retry_delay_seconds,
        max_response_bytes=max_response_bytes,
        credit_warning_threshold=credit_warning_threshold,
    )


def _make_mock_response(
    status: int,
    body: bytes,
    headers: dict | None = None,
) -> MagicMock:
    """Build a mock aiohttp response object."""
    mock_resp = MagicMock()
    mock_resp.status = status
    mock_resp.read = AsyncMock(return_value=body)
    mock_resp.headers = headers or {}
    mock_resp.__aenter__ = AsyncMock(return_value=mock_resp)
    mock_resp.__aexit__ = AsyncMock(return_value=False)
    return mock_resp


def _make_mock_session(mock_response: MagicMock) -> MagicMock:
    """Build a mock aiohttp ClientSession whose post/get return the response."""
    mock_session = MagicMock()
    mock_session.post = MagicMock(return_value=mock_response)
    mock_session.get = MagicMock(return_value=mock_response)
    mock_session.__aenter__ = AsyncMock(return_value=mock_session)
    mock_session.__aexit__ = AsyncMock(return_value=False)
    return mock_session


CLEAN_SEARCH_JSON = json.dumps(
    {
        "organic": [
            {
                "title": "Python tutorial",
                "link": "https://example.com/python",
                "snippet": "Learn Python",
            },
        ]
    }
).encode()


# ---------------------------------------------------------------------------
# TestEndpointAllowlist
# ---------------------------------------------------------------------------


class TestEndpointAllowlist:
    """Allowlist enforcement before any network call."""

    async def test_disabled_endpoint_raises_before_http(self, monkeypatch):
        monkeypatch.setenv("SERPER_API_KEY", "test-key")
        # Default config only enables search/news/images — 'videos' is disabled
        cfg = _minimal_search_config()
        client = SerperClient(cfg)
        with pytest.raises(
            SerperEndpointNotAllowedError, match="not in the enabled endpoints list"
        ):
            await client.search(endpoint="videos", query="test")
        print("OK: disabled endpoint raises SerperEndpointNotAllowedError without HTTP")

    async def test_enabled_endpoint_proceeds_to_http(self, monkeypatch):
        monkeypatch.setenv("SERPER_API_KEY", "test-key")
        cfg = _minimal_search_config()
        mock_resp = _make_mock_response(200, CLEAN_SEARCH_JSON)
        mock_session = _make_mock_session(mock_resp)
        with patch("aiohttp.ClientSession", return_value=mock_session):
            raw, credits = await client_search_with(cfg, "search", "python")
        # If we reach here without exception, the allowlist passed
        assert "organic" in raw
        print("OK: enabled endpoint proceeds to HTTP call")


async def client_search_with(cfg, endpoint, query):
    """Helper to invoke SerperClient.search() in tests."""
    client = SerperClient(cfg)
    return await client.search(endpoint=endpoint, query=query)


# ---------------------------------------------------------------------------
# TestAuthErrors
# ---------------------------------------------------------------------------


class TestAuthErrors:
    """HTTP 401/403 map to SerperAuthError."""

    async def test_http_401_raises_auth_error(self, monkeypatch):
        monkeypatch.setenv("SERPER_API_KEY", "bad-key")
        cfg = _minimal_search_config()
        mock_resp = _make_mock_response(401, b"")
        mock_session = _make_mock_session(mock_resp)
        with patch("aiohttp.ClientSession", return_value=mock_session):
            with pytest.raises(SerperAuthError):
                await SerperClient(cfg).search(endpoint="search", query="test")
        print("OK: HTTP 401 raises SerperAuthError")

    async def test_http_403_raises_auth_error(self, monkeypatch):
        monkeypatch.setenv("SERPER_API_KEY", "bad-key")
        cfg = _minimal_search_config()
        mock_resp = _make_mock_response(403, b"")
        mock_session = _make_mock_session(mock_resp)
        with patch("aiohttp.ClientSession", return_value=mock_session):
            with pytest.raises(SerperAuthError):
                await SerperClient(cfg).search(endpoint="search", query="test")
        print("OK: HTTP 403 raises SerperAuthError")


# ---------------------------------------------------------------------------
# TestRateLimitError
# ---------------------------------------------------------------------------


class TestRateLimitError:
    """HTTP 429 maps to SerperRateLimitError."""

    async def test_http_429_raises_rate_limit_error(self, monkeypatch):
        monkeypatch.setenv("SERPER_API_KEY", "test-key")
        cfg = _minimal_search_config()
        mock_resp = _make_mock_response(429, b"")
        mock_session = _make_mock_session(mock_resp)
        with patch("aiohttp.ClientSession", return_value=mock_session):
            with pytest.raises(SerperRateLimitError):
                await SerperClient(cfg).search(endpoint="search", query="test")
        print("OK: HTTP 429 raises SerperRateLimitError")


# ---------------------------------------------------------------------------
# TestResponseSizeCap
# ---------------------------------------------------------------------------


class TestResponseSizeCap:
    """Response size limit enforced before JSON parsing."""

    async def test_response_exceeding_cap_raises_too_large(self, monkeypatch):
        monkeypatch.setenv("SERPER_API_KEY", "test-key")
        # Cap at 10 bytes, response is much larger
        cfg = _minimal_search_config(max_response_bytes=10)
        mock_resp = _make_mock_response(200, b"x" * 100)
        mock_session = _make_mock_session(mock_resp)
        with patch("aiohttp.ClientSession", return_value=mock_session):
            with pytest.raises(SerperResponseTooLargeError):
                await SerperClient(cfg).search(endpoint="search", query="test")
        print("OK: oversized response raises SerperResponseTooLargeError")

    async def test_response_within_cap_proceeds(self, monkeypatch):
        monkeypatch.setenv("SERPER_API_KEY", "test-key")
        cfg = _minimal_search_config()
        mock_resp = _make_mock_response(200, CLEAN_SEARCH_JSON)
        mock_session = _make_mock_session(mock_resp)
        with patch("aiohttp.ClientSession", return_value=mock_session):
            raw, _ = await SerperClient(cfg).search(endpoint="search", query="test")
        assert isinstance(raw, dict)
        print("OK: response within cap proceeds to return dict")


# ---------------------------------------------------------------------------
# TestRetryBehavior
# ---------------------------------------------------------------------------


class TestRetryBehavior:
    """Retry logic for transient server errors."""

    async def test_5xx_error_retries_up_to_max_then_raises(self, monkeypatch):
        monkeypatch.setenv("SERPER_API_KEY", "test-key")
        cfg = _minimal_search_config(max_retries=2, retry_delay_seconds=0.0)
        mock_resp = _make_mock_response(503, b"")
        mock_session = _make_mock_session(mock_resp)
        call_count = 0

        original_post = mock_session.post

        def counting_post(*args, **kwargs):
            nonlocal call_count
            call_count += 1
            return original_post(*args, **kwargs)

        mock_session.post = counting_post
        with patch("aiohttp.ClientSession", return_value=mock_session):
            with pytest.raises(SerperClientError):
                await SerperClient(cfg).search(endpoint="search", query="test")
        # max_retries=2 means 3 total attempts (first + 2 retries)
        assert call_count == 3
        print(f"OK: 5xx error retried {call_count} times then raised SerperClientError")

    async def test_4xx_error_does_not_retry(self, monkeypatch):
        monkeypatch.setenv("SERPER_API_KEY", "test-key")
        cfg = _minimal_search_config(max_retries=2, retry_delay_seconds=0.0)
        mock_resp = _make_mock_response(401, b"")
        mock_session = _make_mock_session(mock_resp)
        call_count = 0
        original_post = mock_session.post

        def counting_post(*args, **kwargs):
            nonlocal call_count
            call_count += 1
            return original_post(*args, **kwargs)

        mock_session.post = counting_post
        with patch("aiohttp.ClientSession", return_value=mock_session):
            with pytest.raises(SerperAuthError):
                await SerperClient(cfg).search(endpoint="search", query="test")
        # 401 should not retry — exactly 1 attempt
        assert call_count == 1
        print("OK: 401 error does NOT retry (exactly 1 attempt)")


# ---------------------------------------------------------------------------
# TestCreditParsing
# ---------------------------------------------------------------------------


class TestCreditParsing:
    """_parse_credits() extracts header values correctly."""

    def test_headers_with_all_credit_fields_parse_correctly(self):
        headers = {
            "X-Credits-Used": "5",
            "X-RateLimit-Remaining": "4995",
            "X-RateLimit-Limit": "50000",
        }
        credits = _parse_credits(headers)
        assert credits.credits_used == 5
        assert credits.credits_remaining == 4995
        assert credits.plan_limit == 50000
        print("OK: all credit headers parsed correctly")

    def test_missing_headers_return_none(self):
        credits = _parse_credits({})
        assert credits.credits_used is None
        assert credits.credits_remaining is None
        assert credits.plan_limit is None
        print("OK: missing headers return None (no crash)")

    def test_non_integer_header_returns_none(self):
        headers = {"X-Credits-Used": "not-a-number"}
        credits = _parse_credits(headers)
        assert credits.credits_used is None
        print("OK: non-integer header value returns None")

    async def test_low_credits_trigger_warning_log(self, monkeypatch, caplog):
        monkeypatch.setenv("SERPER_API_KEY", "test-key")
        # Threshold=500, response has 100 remaining
        cfg = _minimal_search_config(credit_warning_threshold=500)
        credit_headers = {
            "X-Credits-Used": "1",
            "X-RateLimit-Remaining": "100",
            "X-RateLimit-Limit": "50000",
        }
        mock_resp = _make_mock_response(200, CLEAN_SEARCH_JSON, headers=credit_headers)
        mock_session = _make_mock_session(mock_resp)
        import logging

        with caplog.at_level(logging.WARNING, logger="openrattler.tools.search.serper_client"):
            with patch("aiohttp.ClientSession", return_value=mock_session):
                await SerperClient(cfg).search(endpoint="search", query="test")
        assert any("LOW CREDITS" in record.message for record in caplog.records)
        print("OK: credits below threshold triggers LOW CREDITS warning")


# ---------------------------------------------------------------------------
# TestSanitizationInvocation
# ---------------------------------------------------------------------------


class TestSanitizationInvocation:
    """Sanitizer is called before results are returned."""

    async def test_sanitizer_called_before_returning_result(self, monkeypatch):
        monkeypatch.setenv("SERPER_API_KEY", "test-key")
        cfg = _minimal_search_config()
        mock_resp = _make_mock_response(200, CLEAN_SEARCH_JSON)
        mock_session = _make_mock_session(mock_resp)
        sanitizer_called = []

        def mock_sanitizer(raw_json, endpoint, trace_id, audit_log_fn=None):
            sanitizer_called.append(True)
            return raw_json

        with patch("aiohttp.ClientSession", return_value=mock_session):
            with patch(
                "openrattler.tools.search.serper_client.sanitize_serper_response",
                side_effect=mock_sanitizer,
            ):
                await SerperClient(cfg).search(endpoint="search", query="test")

        assert len(sanitizer_called) == 1
        print("OK: sanitizer was called exactly once before returning result")

    async def test_sanitization_error_propagates_without_swallowing(self, monkeypatch):
        monkeypatch.setenv("SERPER_API_KEY", "test-key")
        cfg = _minimal_search_config()
        mock_resp = _make_mock_response(200, CLEAN_SEARCH_JSON)
        mock_session = _make_mock_session(mock_resp)

        def mock_sanitizer_raises(raw_json, endpoint, trace_id, audit_log_fn=None):
            raise SerperSanitizationError("flagged in test")

        with patch("aiohttp.ClientSession", return_value=mock_session):
            with patch(
                "openrattler.tools.search.serper_client.sanitize_serper_response",
                side_effect=mock_sanitizer_raises,
            ):
                with pytest.raises(SerperSanitizationError):
                    await SerperClient(cfg).search(endpoint="search", query="test")
        print("OK: SerperSanitizationError propagates from client without swallowing")
