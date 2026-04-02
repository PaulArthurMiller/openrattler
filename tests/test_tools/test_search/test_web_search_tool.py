"""Tests for web_search_tool.py — web_search and web_lens entry points."""

import json
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from openrattler.tools.search.serper_client import (
    SerperClientError,
    SerperEndpointNotAllowedError,
)
from openrattler.tools.search.serper_config import SerperConfig
from openrattler.tools.search.serper_sanitizer import SerperSanitizationError
from openrattler.tools.search.web_search_tool import (
    WebLensParams,
    WebSearchParams,
    web_lens,
    web_search,
)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _default_config() -> SerperConfig:
    return SerperConfig()


def _lens_config() -> SerperConfig:
    """Config with lens endpoint enabled for web_lens tests."""
    return SerperConfig(enabled_endpoints=frozenset({"search", "news", "images", "lens"}))


def _make_search_result_raw() -> dict:
    """Minimal valid Serper search API response."""
    return {
        "organic": [
            {
                "title": "Python Tutorial",
                "link": "https://docs.python.org/tutorial",
                "snippet": "Official Python tutorial",
                "position": 1,
                "sitelinks": [],
            },
            {
                "title": "Real Python",
                "link": "https://realpython.com",
                "snippet": "Python tutorials and guides",
                "position": 2,
                "sitelinks": [],
            },
        ],
        "answerBox": {
            "title": "Python",
            "answer": "A high-level programming language",
        },
        "knowledgeGraph": {
            "title": "Python (programming language)",
            "description": "Python is a high-level, general-purpose programming language.",
        },
        "peopleAlsoAsk": [
            {"question": "What is Python used for?", "snippet": "Data science, web dev, etc."},
        ],
        "relatedSearches": [
            {"query": "python tutorial for beginners"},
        ],
    }


def _make_news_result_raw() -> dict:
    """Minimal valid Serper news API response."""
    return {
        "news": [
            {
                "title": "Python 4.0 announced",
                "link": "https://news.example.com/python4",
                "snippet": "Major new release",
                "source": "Tech News",
                "position": 1,
            }
        ]
    }


def _make_images_result_raw() -> dict:
    return {
        "images": [
            {
                "title": "Python logo",
                "link": "https://python.org/logo.png",
                "imageUrl": "https://python.org/logo.png",
                "source": "python.org",
                "position": 1,
            }
        ]
    }


def _make_lens_result_raw() -> dict:
    return {
        "visualMatches": [
            {
                "title": "Python Logo",
                "link": "https://python.org",
                "source": "python.org",
                "position": 1,
            }
        ],
        "textInImage": [
            {"text": "Python"},
        ],
    }


async def _call_web_search_with_mock(
    params: dict,
    config: SerperConfig,
    raw_response: dict,
    credit_headers: dict | None = None,
) -> dict:
    """Call web_search() with a mocked SerperClient that returns raw_response."""
    response_bytes = json.dumps(raw_response).encode()
    mock_resp = MagicMock()
    mock_resp.status = 200
    mock_resp.read = AsyncMock(return_value=response_bytes)
    mock_resp.headers = credit_headers or {}
    mock_resp.__aenter__ = AsyncMock(return_value=mock_resp)
    mock_resp.__aexit__ = AsyncMock(return_value=False)

    mock_session = MagicMock()
    mock_session.post = MagicMock(return_value=mock_resp)
    mock_session.get = MagicMock(return_value=mock_resp)
    mock_session.__aenter__ = AsyncMock(return_value=mock_session)
    mock_session.__aexit__ = AsyncMock(return_value=False)

    with patch("aiohttp.ClientSession", return_value=mock_session):
        return await web_search(params=params, config=config, trace_id="test-trace")


# ---------------------------------------------------------------------------
# TestWebSearchParams
# ---------------------------------------------------------------------------


class TestWebSearchParams:
    """WebSearchParams validation."""

    def test_unknown_endpoint_raises_validation_error(self):
        with pytest.raises(Exception):
            WebSearchParams.model_validate({"query": "test", "endpoint": "not_real"})
        print("OK: unknown endpoint raises validation error")

    def test_num_above_20_raises_validation_error(self):
        with pytest.raises(Exception):
            WebSearchParams.model_validate({"query": "test", "num": 25})
        print("OK: num>20 raises validation error")

    def test_page_below_1_raises_validation_error(self):
        with pytest.raises(Exception):
            WebSearchParams.model_validate({"query": "test", "page": 0})
        print("OK: page<1 raises validation error")

    def test_valid_minimal_params_pass(self):
        p = WebSearchParams.model_validate({"query": "python tutorial"})
        assert p.query == "python tutorial"
        assert p.endpoint == "search"  # default
        print("OK: minimal valid params pass validation")

    def test_valid_params_with_overrides_pass(self):
        p = WebSearchParams.model_validate(
            {
                "query": "latest python news",
                "endpoint": "news",
                "num": 5,
                "gl": "gb",
                "hl": "en",
                "tbs": "qdr:d",
                "page": 2,
            }
        )
        assert p.endpoint == "news"
        assert p.num == 5
        assert p.page == 2
        print("OK: valid params with overrides pass")


# ---------------------------------------------------------------------------
# TestWebSearchTool
# ---------------------------------------------------------------------------


class TestWebSearchTool:
    """web_search() behavior for all result states."""

    async def test_endpoint_not_allowed_returns_structured_error(self, monkeypatch):
        monkeypatch.setenv("SERPER_API_KEY", "test-key")
        cfg = _default_config()  # videos not in default endpoints

        async def mock_search(*args, **kwargs):
            raise SerperEndpointNotAllowedError("videos not allowed")

        with patch("openrattler.tools.search.web_search_tool.SerperClient") as MockClient:
            MockClient.return_value.search = mock_search
            result = await web_search(
                params={"query": "test", "endpoint": "videos"},
                config=cfg,
            )
        assert result["status"] == "error"
        assert result["error"] == "endpoint_not_allowed"
        assert "trace_id" in result
        print("OK: endpoint_not_allowed returns structured error dict")

    async def test_sanitization_failed_returns_structured_error(self, monkeypatch):
        monkeypatch.setenv("SERPER_API_KEY", "test-key")
        cfg = _default_config()

        async def mock_search(*args, **kwargs):
            raise SerperSanitizationError("flagged")

        with patch("openrattler.tools.search.web_search_tool.SerperClient") as MockClient:
            MockClient.return_value.search = mock_search
            result = await web_search(params={"query": "test"}, config=cfg)
        assert result["status"] == "error"
        assert result["error"] == "sanitization_failed"
        print("OK: sanitization_failed returns structured error dict")

    async def test_client_error_returns_structured_error(self, monkeypatch):
        monkeypatch.setenv("SERPER_API_KEY", "test-key")
        cfg = _default_config()

        async def mock_search(*args, **kwargs):
            raise SerperClientError("network down")

        with patch("openrattler.tools.search.web_search_tool.SerperClient") as MockClient:
            MockClient.return_value.search = mock_search
            result = await web_search(params={"query": "test"}, config=cfg)
        assert result["status"] == "error"
        assert result["error"] == "search_failed"
        print("OK: SerperClientError returns structured error dict")

    async def test_successful_search_returns_ok_status_and_results(self, monkeypatch):
        monkeypatch.setenv("SERPER_API_KEY", "test-key")
        cfg = _default_config()
        result = await _call_web_search_with_mock(
            params={"query": "python"},
            config=cfg,
            raw_response=_make_search_result_raw(),
        )
        assert result["status"] == "ok"
        assert isinstance(result["results"], list)
        assert len(result["results"]) == 2
        assert "trace_id" in result
        assert result["query"] == "python"
        print("OK: successful search returns status=ok with results and trace_id")

    async def test_credits_remaining_in_result_matches_headers(self, monkeypatch):
        monkeypatch.setenv("SERPER_API_KEY", "test-key")
        cfg = _default_config()
        credit_headers = {"X-RateLimit-Remaining": "4500", "X-Credits-Used": "5"}
        result = await _call_web_search_with_mock(
            params={"query": "python"},
            config=cfg,
            raw_response=_make_search_result_raw(),
            credit_headers=credit_headers,
        )
        assert result["credits_remaining"] == 4500
        print("OK: credits_remaining in result matches parsed response headers")

    async def test_search_endpoint_result_fields_are_correct(self, monkeypatch):
        monkeypatch.setenv("SERPER_API_KEY", "test-key")
        cfg = _default_config()
        result = await _call_web_search_with_mock(
            params={"query": "python"},
            config=cfg,
            raw_response=_make_search_result_raw(),
        )
        assert result["endpoint"] == "search"
        first = result["results"][0]
        assert "title" in first
        assert "url" in first
        assert "domain" in first
        assert "snippet" in first
        assert "sitelinks" in first
        print("OK: search endpoint result has correct fields")

    async def test_domain_in_results_is_system_derived_from_url(self, monkeypatch):
        monkeypatch.setenv("SERPER_API_KEY", "test-key")
        cfg = _default_config()
        result = await _call_web_search_with_mock(
            params={"query": "python"},
            config=cfg,
            raw_response=_make_search_result_raw(),
        )
        first = result["results"][0]
        # Domain must be derived from URL, not from any payload domain field
        assert first["domain"] == "docs.python.org"
        print("OK: domain is system-derived from URL (docs.python.org)")

    async def test_news_endpoint_result_fields_are_correct(self, monkeypatch):
        monkeypatch.setenv("SERPER_API_KEY", "test-key")
        cfg = _default_config()
        result = await _call_web_search_with_mock(
            params={"query": "python news", "endpoint": "news"},
            config=cfg,
            raw_response=_make_news_result_raw(),
        )
        assert result["status"] == "ok"
        assert result["endpoint"] == "news"
        first = result["results"][0]
        assert "title" in first
        assert "url" in first
        assert "snippet" in first
        assert "source" in first
        assert "domain" in first
        print("OK: news endpoint result has correct fields")

    async def test_images_endpoint_result_fields_are_correct(self, monkeypatch):
        monkeypatch.setenv("SERPER_API_KEY", "test-key")
        cfg = _default_config()
        result = await _call_web_search_with_mock(
            params={"query": "python logo", "endpoint": "images"},
            config=cfg,
            raw_response=_make_images_result_raw(),
        )
        assert result["status"] == "ok"
        first = result["results"][0]
        assert "title" in first
        assert "url" in first
        assert "image_url" in first
        assert "domain" in first
        print("OK: images endpoint result has correct fields")


# ---------------------------------------------------------------------------
# TestWebLensParams
# ---------------------------------------------------------------------------


class TestWebLensParams:
    """WebLensParams validation — URL scheme enforcement."""

    def test_valid_https_image_url_passes(self):
        p = WebLensParams.model_validate({"imageUrl": "https://example.com/image.jpg"})
        assert p.imageUrl == "https://example.com/image.jpg"
        print("OK: HTTPS image URL passes validation")

    def test_valid_http_image_url_passes(self):
        p = WebLensParams.model_validate({"imageUrl": "http://example.com/image.jpg"})
        assert p.imageUrl == "http://example.com/image.jpg"
        print("OK: HTTP image URL passes validation")

    def test_data_uri_scheme_raises_validation_error(self):
        with pytest.raises(Exception, match="http or https scheme"):
            WebLensParams.model_validate({"imageUrl": "data:image/png;base64,abc123"})
        print("OK: data: URI raises validation error")

    def test_file_scheme_raises_validation_error(self):
        with pytest.raises(Exception, match="http or https scheme"):
            WebLensParams.model_validate({"imageUrl": "file:///home/user/photo.jpg"})
        print("OK: file:// URI raises validation error")

    def test_url_with_no_hostname_raises_validation_error(self):
        with pytest.raises(Exception):
            WebLensParams.model_validate({"imageUrl": "https://"})
        print("OK: URL with no hostname raises validation error")

    def test_missing_image_url_raises_validation_error(self):
        with pytest.raises(Exception):
            WebLensParams.model_validate({})
        print("OK: missing imageUrl raises validation error")


# ---------------------------------------------------------------------------
# TestWebLensTool
# ---------------------------------------------------------------------------


class TestWebLensTool:
    """web_lens() behavior."""

    async def test_lens_not_in_enabled_endpoints_returns_error(self, monkeypatch):
        monkeypatch.setenv("SERPER_API_KEY", "test-key")
        cfg = _default_config()  # lens not in default set
        result = await web_lens(
            params={"imageUrl": "https://example.com/photo.jpg"},
            config=cfg,
        )
        assert result["status"] == "error"
        assert result["error"] == "endpoint_not_allowed"
        print("OK: lens not in enabled_endpoints returns endpoint_not_allowed error")

    async def test_client_error_returns_lens_failed_error(self, monkeypatch):
        monkeypatch.setenv("SERPER_API_KEY", "test-key")
        cfg = _lens_config()

        async def mock_execute(*args, **kwargs):
            raise SerperClientError("network down")

        with patch("openrattler.tools.search.web_search_tool.SerperClient") as MockClient:
            MockClient.return_value._execute_request = mock_execute
            result = await web_lens(
                params={"imageUrl": "https://example.com/photo.jpg"},
                config=cfg,
            )
        assert result["status"] == "error"
        assert result["error"] == "lens_failed"
        print("OK: SerperClientError in web_lens returns lens_failed error dict")

    async def test_sanitization_failure_returns_error(self, monkeypatch):
        monkeypatch.setenv("SERPER_API_KEY", "test-key")
        cfg = _lens_config()

        async def mock_execute(*args, **kwargs):
            raise SerperSanitizationError("flagged")

        with patch("openrattler.tools.search.web_search_tool.SerperClient") as MockClient:
            MockClient.return_value._execute_request = mock_execute
            result = await web_lens(
                params={"imageUrl": "https://example.com/photo.jpg"},
                config=cfg,
            )
        assert result["status"] == "error"
        assert result["error"] == "sanitization_failed"
        print("OK: SerperSanitizationError in web_lens returns sanitization_failed error")

    async def test_successful_lens_call_returns_ok_with_results(self, monkeypatch):
        monkeypatch.setenv("SERPER_API_KEY", "test-key")
        cfg = _lens_config()
        raw = _make_lens_result_raw()
        from openrattler.tools.search.serper_models import SerperCredits

        async def mock_execute(*args, **kwargs):
            return raw, SerperCredits()

        with patch("openrattler.tools.search.web_search_tool.SerperClient") as MockClient:
            MockClient.return_value._execute_request = mock_execute
            result = await web_lens(
                params={"imageUrl": "https://example.com/photo.jpg"},
                config=cfg,
            )
        assert result["status"] == "ok"
        assert isinstance(result["results"], list)
        assert "trace_id" in result
        print("OK: successful Lens call returns status=ok with results")

    async def test_image_url_in_result_matches_submitted_url(self, monkeypatch):
        monkeypatch.setenv("SERPER_API_KEY", "test-key")
        cfg = _lens_config()
        raw = _make_lens_result_raw()
        from openrattler.tools.search.serper_models import SerperCredits

        async def mock_execute(*args, **kwargs):
            return raw, SerperCredits()

        submitted_url = "https://example.com/bird-photo.jpg"
        with patch("openrattler.tools.search.web_search_tool.SerperClient") as MockClient:
            MockClient.return_value._execute_request = mock_execute
            result = await web_lens(
                params={"imageUrl": submitted_url},
                config=cfg,
            )
        # image_url in result is set by the system from the validated input
        assert result["image_url"] == submitted_url
        print("OK: image_url in result matches submitted URL (set by system)")

    async def test_text_in_image_populated_from_response(self, monkeypatch):
        monkeypatch.setenv("SERPER_API_KEY", "test-key")
        cfg = _lens_config()
        raw = _make_lens_result_raw()
        from openrattler.tools.search.serper_models import SerperCredits

        async def mock_execute(*args, **kwargs):
            return raw, SerperCredits()

        with patch("openrattler.tools.search.web_search_tool.SerperClient") as MockClient:
            MockClient.return_value._execute_request = mock_execute
            result = await web_lens(
                params={"imageUrl": "https://example.com/photo.jpg"},
                config=cfg,
            )
        assert "text_in_image" in result
        assert "Python" in result["text_in_image"]
        print("OK: text_in_image populated from textInImage response field")

    async def test_submitted_image_url_set_by_system_not_payload(self, monkeypatch):
        """The submittedImageUrl on SerperResponse is set by the system, not from payload."""
        monkeypatch.setenv("SERPER_API_KEY", "test-key")
        cfg = _lens_config()
        # Raw response does NOT include submittedImageUrl — system sets it
        raw = _make_lens_result_raw()
        assert "submittedImageUrl" not in raw  # Confirm it's absent from payload
        from openrattler.tools.search.serper_models import SerperCredits

        async def mock_execute(*args, **kwargs):
            return raw, SerperCredits()

        submitted = "https://example.com/real-photo.jpg"
        with patch("openrattler.tools.search.web_search_tool.SerperClient") as MockClient:
            MockClient.return_value._execute_request = mock_execute
            result = await web_lens(
                params={"imageUrl": submitted},
                config=cfg,
            )
        assert result["image_url"] == submitted
        print("OK: submitted image URL is set by system, not accepted from payload")
