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

import httpx
from mcp.server.fastmcp import FastMCP

mcp = FastMCP("weather")

NWS_API_BASE = "https://api.weather.gov"
USER_AGENT = "openrattler-weather/1.0"


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


if __name__ == "__main__":
    mcp.run(transport="stdio")
