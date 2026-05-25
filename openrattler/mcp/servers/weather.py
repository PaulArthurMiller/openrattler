"""Bundled weather MCP server for OpenRattler.

Uses the National Weather Service (NWS) API — free, no API key required.
This server demonstrates the pattern for bundled MCP servers:
- Uses FastMCP from the mcp SDK
- Exposes tools matching its manifest declaration
- Runs as a subprocess via stdio transport
- Has no access to OpenRattler internals

Run directly: python -m openrattler.mcp.servers.weather
"""

from __future__ import annotations

import math

import httpx
from mcp.server.fastmcp import FastMCP

mcp = FastMCP("weather")

NWS_API_BASE = "https://api.weather.gov"
USER_AGENT = "openrattler-weather/1.0"


def _haversine(lat1: float, lon1: float, lat2: float, lon2: float) -> float:
    """Return great-circle distance in km between two lat/lon points."""
    R = 6371.0
    dlat = math.radians(lat2 - lat1)
    dlon = math.radians(lon2 - lon1)
    a = (
        math.sin(dlat / 2) ** 2
        + math.cos(math.radians(lat1)) * math.cos(math.radians(lat2)) * math.sin(dlon / 2) ** 2
    )
    return R * 2 * math.asin(math.sqrt(a))


@mcp.tool()
async def get_forecast(latitude: float, longitude: float) -> str:
    """Get weather forecast for a location by lat/long coordinates."""
    headers = {"User-Agent": USER_AGENT, "Accept": "application/geo+json"}
    async with httpx.AsyncClient() as client:
        # NWS requires a two-step lookup: point → forecast URL
        point_resp = await client.get(
            f"{NWS_API_BASE}/points/{latitude},{longitude}",
            headers=headers,
        )
        point_resp.raise_for_status()
        forecast_url = point_resp.json()["properties"]["forecast"]

        forecast_resp = await client.get(forecast_url, headers=headers)
        forecast_resp.raise_for_status()
        periods = forecast_resp.json()["properties"]["periods"]

        # Return first 3 periods as readable text
        lines = []
        for period in periods[:3]:
            lines.append(
                f"{period['name']}: {period['temperature']}°{period['temperatureUnit']}, "
                f"{period['shortForecast']}"
            )
        return "\n".join(lines)


@mcp.tool()
async def get_alerts(state: str) -> str:
    """Get active weather alerts for a US state (two-letter code)."""
    headers = {"User-Agent": USER_AGENT, "Accept": "application/geo+json"}
    async with httpx.AsyncClient() as client:
        resp = await client.get(
            f"{NWS_API_BASE}/alerts/active?area={state}",
            headers=headers,
        )
        resp.raise_for_status()
        features = resp.json().get("features", [])

        if not features:
            return f"No active alerts for {state}."

        lines = []
        for feature in features[:5]:  # Cap at 5
            props = feature["properties"]
            lines.append(f"- {props.get('event', 'Unknown')}: {props.get('headline', '')}")
        return "\n".join(lines)


@mcp.tool()
async def get_hourly_forecast(latitude: float, longitude: float) -> str:
    """Get hour-by-hour weather forecast for the next 24 hours."""
    headers = {"User-Agent": USER_AGENT, "Accept": "application/geo+json"}
    async with httpx.AsyncClient() as client:
        point_resp = await client.get(
            f"{NWS_API_BASE}/points/{latitude},{longitude}",
            headers=headers,
        )
        point_resp.raise_for_status()
        hourly_url = point_resp.json()["properties"]["forecastHourly"]

        hourly_resp = await client.get(hourly_url, headers=headers)
        hourly_resp.raise_for_status()
        periods = hourly_resp.json()["properties"]["periods"]

        lines = []
        for period in periods[:24]:
            # Trim ISO timestamp to "YYYY-MM-DD HH:MM"
            start = period["startTime"][:16].replace("T", " ")
            lines.append(
                f"{start}: {period['temperature']}°{period['temperatureUnit']}, "
                f"{period['shortForecast']}, "
                f"Wind: {period.get('windSpeed', 'N/A')} {period.get('windDirection', '')}".rstrip()
            )
        return "\n".join(lines)


@mcp.tool()
async def get_extended_forecast(latitude: float, longitude: float) -> str:
    """Get extended 7-day weather forecast with detailed descriptions."""
    headers = {"User-Agent": USER_AGENT, "Accept": "application/geo+json"}
    async with httpx.AsyncClient() as client:
        point_resp = await client.get(
            f"{NWS_API_BASE}/points/{latitude},{longitude}",
            headers=headers,
        )
        point_resp.raise_for_status()
        forecast_url = point_resp.json()["properties"]["forecast"]

        forecast_resp = await client.get(forecast_url, headers=headers)
        forecast_resp.raise_for_status()
        periods = forecast_resp.json()["properties"]["periods"]

        lines = []
        for period in periods:  # All periods — up to 14 covering 7 days
            lines.append(
                f"{period['name']}: {period['temperature']}°{period['temperatureUnit']} — "
                f"{period['detailedForecast']}"
            )
        return "\n".join(lines)


@mcp.tool()
async def get_forecast_discussion(latitude: float, longitude: float) -> str:
    """Get the official NWS meteorologist Area Forecast Discussion for a location."""
    headers = {"User-Agent": USER_AGENT, "Accept": "application/geo+json"}
    json_headers = {"User-Agent": USER_AGENT, "Accept": "application/json"}
    async with httpx.AsyncClient() as client:
        point_resp = await client.get(
            f"{NWS_API_BASE}/points/{latitude},{longitude}",
            headers=headers,
        )
        point_resp.raise_for_status()
        cwa = point_resp.json()["properties"]["cwa"]

        products_resp = await client.get(
            f"{NWS_API_BASE}/products/types/AFD/locations/{cwa}",
            headers=json_headers,
        )
        products_resp.raise_for_status()
        graph = products_resp.json().get("@graph", [])

        if not graph:
            return f"No forecast discussion available for {cwa}."

        product_id = graph[0]["id"]
        discussion_resp = await client.get(
            f"{NWS_API_BASE}/products/{product_id}",
            headers=json_headers,
        )
        discussion_resp.raise_for_status()
        return str(discussion_resp.json().get("productText", "Discussion text unavailable."))


@mcp.tool()
async def get_radar_stations(latitude: float, longitude: float, radius_km: float = 250.0) -> str:
    """Get nearby NEXRAD radar stations within radius_km (default 250 km)."""
    headers = {"User-Agent": USER_AGENT, "Accept": "application/geo+json"}
    async with httpx.AsyncClient() as client:
        resp = await client.get(f"{NWS_API_BASE}/radar/stations", headers=headers)
        resp.raise_for_status()
        features = resp.json().get("features", [])

    nearby: list[tuple[float, str, str]] = []
    for feature in features:
        coords = feature.get("geometry", {}).get("coordinates", [])
        if len(coords) >= 2:
            slon, slat = coords[0], coords[1]
            dist = _haversine(latitude, longitude, slat, slon)
            if dist <= radius_km:
                props = feature.get("properties", {})
                nearby.append((dist, props.get("stationIdentifier", ""), props.get("name", "")))

    if not nearby:
        return f"No radar stations found within {radius_km:.0f} km of ({latitude}, {longitude})."

    nearby.sort()
    lines = [f"Radar stations within {radius_km:.0f} km:"]
    for dist, sid, name in nearby:
        lines.append(f"  {sid} — {name} ({dist:.0f} km)")
    return "\n".join(lines)


if __name__ == "__main__":
    mcp.run(transport="stdio")
