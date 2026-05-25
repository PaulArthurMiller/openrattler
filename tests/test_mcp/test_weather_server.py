"""Tests for the bundled weather MCP server.

Tests the NWS API wrappers directly by mocking httpx calls.

Test classes:
    TestGetForecast          — valid coordinates return formatted forecast, API errors handled
    TestGetAlerts            — valid state returns alerts list, no-alerts case, cap at 5
    TestGetHourlyForecast    — 24-hour hourly breakdown, wind info included
    TestGetExtendedForecast  — full 7-day detailed forecast
    TestGetForecastDiscussion — AFD lookup by CWA office
    TestGetRadarStations     — haversine filtering and sorting of nearby stations
"""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from openrattler.mcp.servers.weather import (
    NWS_API_BASE,
    _haversine,
    get_alerts,
    get_extended_forecast,
    get_forecast,
    get_forecast_discussion,
    get_hourly_forecast,
    get_radar_stations,
)

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


def _point_response(
    forecast_url: str,
    hourly_url: str = "https://api.weather.gov/hourly",
    cwa: str = "LWX",
) -> object:
    return {
        "properties": {
            "forecast": forecast_url,
            "forecastHourly": hourly_url,
            "cwa": cwa,
        }
    }


def _forecast_response(periods: list[dict[str, object]]) -> object:
    return {"properties": {"periods": periods}}


def _period(
    name: str,
    temp: int,
    unit: str = "F",
    short: str = "Sunny",
    detailed: str = "Sunny skies throughout the day.",
) -> dict[str, object]:
    return {
        "name": name,
        "temperature": temp,
        "temperatureUnit": unit,
        "shortForecast": short,
        "detailedForecast": detailed,
    }


def _hourly_period(
    start: str,
    temp: int,
    unit: str = "F",
    short: str = "Sunny",
    wind_speed: str = "10 mph",
    wind_dir: str = "SW",
) -> dict[str, object]:
    return {
        "startTime": start,
        "temperature": temp,
        "temperatureUnit": unit,
        "shortForecast": short,
        "windSpeed": wind_speed,
        "windDirection": wind_dir,
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


# ---------------------------------------------------------------------------
# TestGetHourlyForecast
# ---------------------------------------------------------------------------


class TestGetHourlyForecast:
    """get_hourly_forecast() returns hour-by-hour data for the next 24 hours."""

    async def test_returns_up_to_24_hours(self) -> None:
        """Caps output at 24 periods even when the API returns more."""
        hourly_url = "https://api.weather.gov/hourly/test"
        periods = [_hourly_period(f"2026-05-25T{h:02d}:00:00-05:00", 70 + h) for h in range(48)]
        responses = [
            _mock_response(_point_response("https://x", hourly_url)),
            _mock_response(_forecast_response(periods)),
        ]
        with _patch_client(responses):
            result = await get_hourly_forecast(latitude=38.89, longitude=-77.04)

        lines = result.strip().split("\n")
        assert len(lines) == 24

    async def test_includes_wind_info(self) -> None:
        """Each line contains wind speed and direction."""
        hourly_url = "https://api.weather.gov/hourly/test"
        periods = [
            _hourly_period("2026-05-25T14:00:00-05:00", 72, wind_speed="15 mph", wind_dir="NW")
        ]
        responses = [
            _mock_response(_point_response("https://x", hourly_url)),
            _mock_response(_forecast_response(periods)),
        ]
        with _patch_client(responses):
            result = await get_hourly_forecast(latitude=38.89, longitude=-77.04)

        assert "15 mph" in result
        assert "NW" in result

    async def test_timestamp_formatted_as_datetime(self) -> None:
        """ISO timestamp is trimmed to YYYY-MM-DD HH:MM format."""
        hourly_url = "https://api.weather.gov/hourly/test"
        periods = [_hourly_period("2026-05-25T09:00:00-05:00", 65)]
        responses = [
            _mock_response(_point_response("https://x", hourly_url)),
            _mock_response(_forecast_response(periods)),
        ]
        with _patch_client(responses):
            result = await get_hourly_forecast(latitude=38.89, longitude=-77.04)

        assert "2026-05-25 09:00" in result

    async def test_calls_forecast_hourly_url(self) -> None:
        """Uses the forecastHourly URL from the points response, not forecast."""
        hourly_url = "https://api.weather.gov/gridpoints/LWX/96,70/forecast/hourly"
        mock_client = AsyncMock()
        mock_client.get = AsyncMock(
            side_effect=[
                _mock_response(_point_response("https://forecast", hourly_url)),
                _mock_response(
                    _forecast_response([_hourly_period("2026-05-25T10:00:00-05:00", 70)])
                ),
            ]
        )
        cm = MagicMock()
        cm.__aenter__ = AsyncMock(return_value=mock_client)
        cm.__aexit__ = AsyncMock(return_value=None)

        with patch("openrattler.mcp.servers.weather.httpx.AsyncClient", return_value=cm):
            await get_hourly_forecast(latitude=38.89, longitude=-77.04)

        calls = mock_client.get.call_args_list
        assert calls[1].args[0] == hourly_url


# ---------------------------------------------------------------------------
# TestGetExtendedForecast
# ---------------------------------------------------------------------------


class TestGetExtendedForecast:
    """get_extended_forecast() returns all forecast periods (up to 14)."""

    async def test_returns_all_periods(self) -> None:
        """Returns all 14 periods without capping."""
        forecast_url = "https://api.weather.gov/forecast/ext"
        periods = [_period(f"Period {i}", 60 + i) for i in range(14)]
        responses = [
            _mock_response(_point_response(forecast_url)),
            _mock_response(_forecast_response(periods)),
        ]
        with _patch_client(responses):
            result = await get_extended_forecast(latitude=38.89, longitude=-77.04)

        lines = result.strip().split("\n")
        assert len(lines) == 14
        assert "Period 13" in result

    async def test_uses_detailed_forecast_field(self) -> None:
        """Each line includes the detailedForecast, not just shortForecast."""
        forecast_url = "https://api.weather.gov/forecast/ext"
        periods = [_period("Today", 75, detailed="Mostly sunny with a high near 75.")]
        responses = [
            _mock_response(_point_response(forecast_url)),
            _mock_response(_forecast_response(periods)),
        ]
        with _patch_client(responses):
            result = await get_extended_forecast(latitude=38.89, longitude=-77.04)

        assert "Mostly sunny with a high near 75." in result

    async def test_temperature_included(self) -> None:
        """Temperature and unit appear in each period line."""
        forecast_url = "https://api.weather.gov/forecast/ext"
        periods = [_period("Tonight", 42, "F")]
        responses = [
            _mock_response(_point_response(forecast_url)),
            _mock_response(_forecast_response(periods)),
        ]
        with _patch_client(responses):
            result = await get_extended_forecast(latitude=38.89, longitude=-77.04)

        assert "42°F" in result


# ---------------------------------------------------------------------------
# TestGetForecastDiscussion
# ---------------------------------------------------------------------------


class TestGetForecastDiscussion:
    """get_forecast_discussion() retrieves NWS Area Forecast Discussion text."""

    async def test_returns_discussion_text(self) -> None:
        """Returns productText from the most recent AFD."""
        forecast_url = "https://api.weather.gov/forecast/x"
        point_resp = _mock_response(_point_response(forecast_url, cwa="LWX"))
        products_resp = _mock_response({"@graph": [{"id": "afd-001"}]})
        discussion_resp = _mock_response({"productText": "Upper level ridge building..."})

        with _patch_client([point_resp, products_resp, discussion_resp]):
            result = await get_forecast_discussion(latitude=38.89, longitude=-77.04)

        assert "Upper level ridge building" in result

    async def test_no_discussion_available(self) -> None:
        """Returns a clear message when no AFD products exist for the office."""
        forecast_url = "https://api.weather.gov/forecast/x"
        point_resp = _mock_response(_point_response(forecast_url, cwa="LWX"))
        products_resp = _mock_response({"@graph": []})

        with _patch_client([point_resp, products_resp]):
            result = await get_forecast_discussion(latitude=38.89, longitude=-77.04)

        assert "No forecast discussion available" in result
        assert "LWX" in result

    async def test_uses_cwa_from_point_response(self) -> None:
        """Queries the AFD endpoint using the cwa code from the points response."""
        mock_client = AsyncMock()
        mock_client.get = AsyncMock(
            side_effect=[
                _mock_response(_point_response("https://f", cwa="BOU")),
                _mock_response({"@graph": [{"id": "afd-bou"}]}),
                _mock_response({"productText": "Rocky Mountain weather..."}),
            ]
        )
        cm = MagicMock()
        cm.__aenter__ = AsyncMock(return_value=mock_client)
        cm.__aexit__ = AsyncMock(return_value=None)

        with patch("openrattler.mcp.servers.weather.httpx.AsyncClient", return_value=cm):
            result = await get_forecast_discussion(latitude=40.0, longitude=-105.0)

        calls = mock_client.get.call_args_list
        assert "AFD/locations/BOU" in calls[1].args[0]
        assert "Rocky Mountain weather" in result

    async def test_missing_product_text_handled(self) -> None:
        """Returns fallback string when productText key is absent."""
        forecast_url = "https://api.weather.gov/forecast/x"
        point_resp = _mock_response(_point_response(forecast_url, cwa="OKX"))
        products_resp = _mock_response({"@graph": [{"id": "afd-okx"}]})
        discussion_resp = _mock_response({})  # No productText key

        with _patch_client([point_resp, products_resp, discussion_resp]):
            result = await get_forecast_discussion(latitude=40.71, longitude=-74.01)

        assert "unavailable" in result.lower()


# ---------------------------------------------------------------------------
# TestGetRadarStations
# ---------------------------------------------------------------------------


class TestGetRadarStations:
    """get_radar_stations() filters and ranks NEXRAD stations by distance."""

    def _radar_feature(
        self, station_id: str, name: str, lat: float, lon: float
    ) -> dict[str, object]:
        return {
            "geometry": {"coordinates": [lon, lat]},
            "properties": {"stationIdentifier": station_id, "name": name},
        }

    async def test_returns_stations_within_radius(self) -> None:
        """Only stations within radius_km appear in the result."""
        features = [
            self._radar_feature("KLWX", "Sterling VA", 38.975, -77.478),  # ~55 km from 38.89,-77.04
            self._radar_feature("KAKQ", "Norfolk VA", 36.984, -77.007),  # ~213 km — outside 200 km
        ]
        station_resp = _mock_response({"features": features})

        with _patch_client([station_resp]):
            result = await get_radar_stations(latitude=38.89, longitude=-77.04, radius_km=100.0)

        assert "KLWX" in result
        assert "KAKQ" not in result

    async def test_sorted_nearest_first(self) -> None:
        """Stations appear sorted by ascending distance."""
        features = [
            self._radar_feature("FAR", "Far Station", 39.9, -77.04),  # farther
            self._radar_feature("NEAR", "Near Station", 38.95, -77.04),  # closer
        ]
        station_resp = _mock_response({"features": features})

        with _patch_client([station_resp]):
            result = await get_radar_stations(latitude=38.89, longitude=-77.04, radius_km=200.0)

        lines = result.strip().split("\n")
        near_idx = next(i for i, l in enumerate(lines) if "NEAR" in l)
        far_idx = next(i for i, l in enumerate(lines) if "FAR" in l)
        assert near_idx < far_idx

    async def test_no_stations_in_radius(self) -> None:
        """Returns a clear message when no stations fall within the radius."""
        features = [
            self._radar_feature("DISTANT", "Distant Station", 50.0, -77.04),  # far away
        ]
        station_resp = _mock_response({"features": features})

        with _patch_client([station_resp]):
            result = await get_radar_stations(latitude=38.89, longitude=-77.04, radius_km=50.0)

        assert "No radar stations found" in result

    async def test_distance_shown_in_km(self) -> None:
        """Each station line includes a rounded distance in km."""
        features = [
            self._radar_feature("KLWX", "Sterling VA", 38.975, -77.478),
        ]
        station_resp = _mock_response({"features": features})

        with _patch_client([station_resp]):
            result = await get_radar_stations(latitude=38.89, longitude=-77.04, radius_km=200.0)

        # Should contain something like "(55 km)" or similar distance
        assert "km" in result

    async def test_skips_features_without_geometry(self) -> None:
        """Features missing geometry coordinates are silently skipped."""
        features = [
            {"geometry": {}, "properties": {"stationIdentifier": "NOGEO", "name": "No Geo"}},
            self._radar_feature("KLWX", "Sterling VA", 38.975, -77.478),
        ]
        station_resp = _mock_response({"features": features})

        with _patch_client([station_resp]):
            result = await get_radar_stations(latitude=38.89, longitude=-77.04, radius_km=200.0)

        assert "NOGEO" not in result
        assert "KLWX" in result


# ---------------------------------------------------------------------------
# TestHaversine (unit test for helper)
# ---------------------------------------------------------------------------


class TestHaversine:
    """_haversine() computes great-circle distance in km."""

    def test_same_point_is_zero(self) -> None:
        """Distance from a point to itself is 0."""
        assert _haversine(38.89, -77.04, 38.89, -77.04) == pytest.approx(0.0, abs=1e-6)

    def test_known_distance(self) -> None:
        """DC to NYC is approximately 333 km."""
        dist = _haversine(38.89, -77.04, 40.71, -74.01)
        assert 320 < dist < 350
