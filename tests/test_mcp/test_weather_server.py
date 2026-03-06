"""Tests for the bundled weather MCP server.

Tests the NWS API wrappers directly by mocking httpx calls.

Test classes:
    TestGetForecast — valid coordinates return formatted forecast, API errors handled
    TestGetAlerts   — valid state returns alerts list, no-alerts case, cap at 5
"""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from openrattler.mcp.servers.weather import NWS_API_BASE, get_alerts, get_forecast

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _mock_response(json_data: object, status_code: int = 200) -> MagicMock:
    """Build a mock httpx response."""
    resp = MagicMock()
    resp.status_code = status_code
    resp.json = MagicMock(return_value=json_data)
    resp.raise_for_status = MagicMock()
    if status_code >= 400:
        import httpx

        resp.raise_for_status = MagicMock(
            side_effect=httpx.HTTPStatusError(
                f"HTTP {status_code}",
                request=MagicMock(),
                response=resp,
            )
        )
    return resp


def _point_response(forecast_url: str) -> object:
    return {"properties": {"forecast": forecast_url}}


def _forecast_response(periods: list[dict[str, object]]) -> object:
    return {"properties": {"periods": periods}}


def _period(name: str, temp: int, unit: str = "F", short: str = "Sunny") -> dict[str, object]:
    return {
        "name": name,
        "temperature": temp,
        "temperatureUnit": unit,
        "shortForecast": short,
    }


def _alert(event: str, headline: str) -> dict[str, object]:
    return {"properties": {"event": event, "headline": headline}}


def _patch_client(responses: list[MagicMock]) -> object:
    """Return a context manager patch for httpx.AsyncClient."""
    mock_client = AsyncMock()
    mock_client.get = AsyncMock(side_effect=responses)
    cm = MagicMock()
    cm.__aenter__ = AsyncMock(return_value=mock_client)
    cm.__aexit__ = AsyncMock(return_value=None)
    return patch("openrattler.mcp.servers.weather.httpx.AsyncClient", return_value=cm)


# ---------------------------------------------------------------------------
# TestGetForecast
# ---------------------------------------------------------------------------


class TestGetForecast:
    """get_forecast() fetches NWS forecast for lat/long coordinates."""

    async def test_returns_formatted_forecast_for_three_periods(self) -> None:
        """Returns formatted text with up to 3 forecast periods."""
        forecast_url = f"{NWS_API_BASE}/forecast/test"
        periods = [
            _period("Tonight", 55, "F", "Clear"),
            _period("Wednesday", 72, "F", "Partly Cloudy"),
            _period("Wednesday Night", 48, "F", "Cloudy"),
            _period("Thursday", 65, "F", "Rainy"),  # Should be excluded
        ]
        responses = [
            _mock_response(_point_response(forecast_url)),
            _mock_response(_forecast_response(periods)),
        ]

        with _patch_client(responses):
            result = await get_forecast(latitude=38.89, longitude=-77.04)

        lines = result.strip().split("\n")
        assert len(lines) == 3
        assert "Tonight" in lines[0]
        assert "55°F" in lines[0]
        assert "Clear" in lines[0]
        assert "Wednesday" in lines[1]
        assert "72°F" in lines[1]
        assert "Thursday" not in result  # Capped at 3

    async def test_correct_nws_api_urls_called(self) -> None:
        """Calls the NWS points endpoint then the returned forecast URL."""
        forecast_url = "https://api.weather.gov/gridpoints/LWX/96,70/forecast"
        mock_client = AsyncMock()
        mock_client.get = AsyncMock(
            side_effect=[
                _mock_response(_point_response(forecast_url)),
                _mock_response(_forecast_response([_period("Today", 70, "F", "Sunny")])),
            ]
        )
        cm = MagicMock()
        cm.__aenter__ = AsyncMock(return_value=mock_client)
        cm.__aexit__ = AsyncMock(return_value=None)

        with patch("openrattler.mcp.servers.weather.httpx.AsyncClient", return_value=cm):
            await get_forecast(latitude=38.89, longitude=-77.04)

        calls = mock_client.get.call_args_list
        assert len(calls) == 2
        assert "38.89,-77.04" in calls[0].args[0]
        assert calls[1].args[0] == forecast_url

    async def test_single_period_response(self) -> None:
        """Returns a single line when the server only returns one period."""
        forecast_url = f"{NWS_API_BASE}/forecast/x"
        responses = [
            _mock_response(_point_response(forecast_url)),
            _mock_response(_forecast_response([_period("Now", 60, "F", "Foggy")])),
        ]
        with _patch_client(responses):
            result = await get_forecast(latitude=37.0, longitude=-122.0)

        assert "Now" in result
        assert "60°F" in result
        assert result.count("\n") == 0  # Single line

    async def test_nws_api_error_propagates(self) -> None:
        """HTTPStatusError from NWS is raised (not swallowed)."""
        import httpx

        responses = [_mock_response({}, status_code=500)]
        with _patch_client(responses):
            with pytest.raises(httpx.HTTPStatusError):
                await get_forecast(latitude=0.0, longitude=0.0)


# ---------------------------------------------------------------------------
# TestGetAlerts
# ---------------------------------------------------------------------------


class TestGetAlerts:
    """get_alerts() fetches NWS weather alerts for a US state."""

    async def test_returns_formatted_alerts(self) -> None:
        """Returns bulleted list of active alerts for the state."""
        features = [
            _alert("Tornado Warning", "Tornado Warning in effect until 6 PM"),
            _alert("Flash Flood Watch", "Flash Flood Watch in effect"),
        ]
        response = _mock_response({"features": features})

        with _patch_client([response]):
            result = await get_alerts(state="TX")

        assert "Tornado Warning" in result
        assert "Flash Flood Watch" in result
        assert result.startswith("- ")

    async def test_no_alerts_returns_message(self) -> None:
        """Returns a descriptive message when there are no active alerts."""
        response = _mock_response({"features": []})

        with _patch_client([response]):
            result = await get_alerts(state="CA")

        assert "No active alerts" in result
        assert "CA" in result

    async def test_caps_at_five_alerts(self) -> None:
        """Returns at most 5 alerts even if the API returns more."""
        features = [_alert(f"Event {i}", f"Headline {i}") for i in range(10)]
        response = _mock_response({"features": features})

        with _patch_client([response]):
            result = await get_alerts(state="FL")

        lines = [line for line in result.strip().split("\n") if line.startswith("- ")]
        assert len(lines) == 5

    async def test_correct_api_url_called(self) -> None:
        """Calls the NWS alerts endpoint with the correct state parameter."""
        mock_client = AsyncMock()
        mock_client.get = AsyncMock(return_value=_mock_response({"features": []}))
        cm = MagicMock()
        cm.__aenter__ = AsyncMock(return_value=mock_client)
        cm.__aexit__ = AsyncMock(return_value=None)

        with patch("openrattler.mcp.servers.weather.httpx.AsyncClient", return_value=cm):
            await get_alerts(state="WA")

        url_called = mock_client.get.call_args.args[0]
        assert "alerts/active" in url_called
        assert "area=WA" in url_called

    async def test_missing_properties_handled_gracefully(self) -> None:
        """Alerts with missing event/headline fields don't crash."""
        features = [{"properties": {}}]  # No 'event' or 'headline' keys
        response = _mock_response({"features": features})

        with _patch_client([response]):
            result = await get_alerts(state="NY")

        assert "Unknown" in result  # Fallback from props.get('event', 'Unknown')
