"""
Serper API configuration and endpoint policy.

Security note: API key is read from the environment only. It is never
stored in this config object, never serialized, and never logged.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from typing import Any, FrozenSet

# ---------------------------------------------------------------------------
# Endpoint registry — all known Serper endpoints
# ---------------------------------------------------------------------------

# Every endpoint Serper supports. New endpoints must be added here before
# they can be enabled in config. Allowlists grow intentionally; no endpoint
# is available unless explicitly listed.
ALL_SERPER_ENDPOINTS: FrozenSet[str] = frozenset(
    {
        "search",  # Standard web search (organic results)
        "images",  # Google Images
        "news",  # Google News
        "videos",  # Google Videos
        "places",  # Google Maps / Places
        "maps",  # Google Maps directions
        "shopping",  # Google Shopping
        "scholar",  # Google Scholar
        "patents",  # Google Patents
        "autocomplete",  # Search autocomplete suggestions
        "lens",  # Google Lens — reverse image search (takes imageUrl, not q)
        # Confirmed available: POST https://google.serper.dev/lens
        # NOTE: Lens uses a different request shape than all other
        # endpoints. It accepts 'imageUrl' (a publicly accessible URL)
        # instead of 'q'. Use web_lens() not web_search() to call it.
        # Disabled by default; enable in config when needed.
    }
)

# Default set enabled for the ResearchAgent. Restrictive by design.
# Paul can expand this in config as use cases emerge.
# Note: 'lens' is intentionally excluded from the default set because it
# requires a different call path (web_lens tool, not web_search tool).
# Enable it explicitly once the image hosting workflow is in place.
DEFAULT_ENABLED_ENDPOINTS: FrozenSet[str] = frozenset(
    {
        "search",
        "news",
        "images",
    }
)


# ---------------------------------------------------------------------------
# Per-endpoint result field policies
# ---------------------------------------------------------------------------

# Fields returned by Serper for each endpoint. All fields are optional in
# the raw API — this registry documents what CAN appear so the sanitizer
# knows what to check and models know what to parse.
#
# Format: endpoint_name -> list of field paths that carry user-visible text
# (and therefore must be sanitized before reaching the LLM).
ENDPOINT_TEXT_FIELDS: dict[str, list[str]] = {
    "search": [
        "organic[].title",
        "organic[].snippet",
        "organic[].sitelinks[].title",
        "organic[].sitelinks[].snippet",
        "answerBox.answer",
        "answerBox.snippet",
        "answerBox.title",
        "knowledgeGraph.title",
        "knowledgeGraph.description",
        "knowledgeGraph.attributes.*",
        "peopleAlsoAsk[].question",
        "peopleAlsoAsk[].snippet",
        "peopleAlsoAsk[].title",
        "relatedSearches[].query",
        "topStories[].title",
        "topStories[].source",
    ],
    "images": [
        "images[].title",
        "images[].source",
        "images[].domain",
    ],
    "news": [
        "news[].title",
        "news[].snippet",
        "news[].source",
    ],
    "videos": [
        "videos[].title",
        "videos[].channel",
        "videos[].snippet",
    ],
    "places": [
        "places[].title",
        "places[].address",
        "places[].category",
        "places[].description",
        "places[].ratingCount",
    ],
    "maps": [
        "places[].title",
        "places[].address",
        "places[].category",
    ],
    "shopping": [
        "shopping[].title",
        "shopping[].source",
        "shopping[].delivery",
    ],
    "scholar": [
        "organic[].title",
        "organic[].snippet",
        "organic[].publicationInfo",
    ],
    "patents": [
        "organic[].title",
        "organic[].snippet",
        "organic[].assignee",
        "organic[].inventor",
    ],
    "autocomplete": [
        "suggestions[].value",
    ],
    "lens": [
        "visualMatches[].title",
        "visualMatches[].source",
        "knowledgeGraph.title",
        "knowledgeGraph.description",
        "knowledgeGraph.attributes.*",
        "relatedSearches[].query",
        "textInImage[].text",
    ],
}


# ---------------------------------------------------------------------------
# SerperConfig
# ---------------------------------------------------------------------------


@dataclass
class SerperConfig:
    """
    Runtime configuration for the Serper search client.

    Security note: api_key is intentionally absent from this dataclass.
    The client reads it directly from os.environ at call time so it is
    never stored in a serializable object, never included in repr(), and
    never accidentally logged as part of a config dump.
    """

    # Endpoints the ResearchAgent is permitted to call.
    # Must be a subset of ALL_SERPER_ENDPOINTS.
    enabled_endpoints: FrozenSet[str] = field(default_factory=lambda: DEFAULT_ENABLED_ENDPOINTS)

    # Maximum results to request per query (Serper param: num).
    # Range: 1–100. Serper default is 10.
    max_results: int = 10

    # HTTP request timeout in seconds. Enforced at the transport layer.
    request_timeout_seconds: float = 10.0

    # Maximum retry attempts on transient failures (5xx, network error).
    # Does NOT retry on 4xx (bad request, auth failure).
    max_retries: int = 2

    # Delay between retries in seconds.
    retry_delay_seconds: float = 1.0

    # Maximum size of a single Serper API response in bytes.
    # Responses exceeding this are rejected before parsing.
    max_response_bytes: int = 512_000  # 512 KB

    # Maximum number of text characters in any single field value
    # before the sanitizer flags it as anomalous.
    max_field_chars: int = 2_000

    # Credit warning threshold. If remaining credits drop to or below
    # this value, the client emits a structured warning in the result.
    # Set to 0 to disable warnings.
    credit_warning_threshold: int = 500

    # Country/region for search results (Serper param: gl).
    # ISO 3166-1 alpha-2 country code. None = Serper default (us).
    default_country: str | None = "us"

    # Language for search results (Serper param: hl).
    # BCP 47 language tag. None = Serper default (en).
    default_language: str | None = "en"

    # Safe search setting (Serper param: safe).
    # "active" | "off" | None (Serper default)
    safe_search: str | None = "active"

    def __post_init__(self) -> None:
        """Validate config on construction."""
        unknown = self.enabled_endpoints - ALL_SERPER_ENDPOINTS
        if unknown:
            raise ValueError(
                f"Unknown Serper endpoints in enabled_endpoints: {unknown}. "
                f"Known endpoints: {ALL_SERPER_ENDPOINTS}"
            )
        if not 1 <= self.max_results <= 100:
            raise ValueError(f"max_results must be between 1 and 100, got {self.max_results}")
        if self.request_timeout_seconds <= 0:
            raise ValueError("request_timeout_seconds must be positive")
        if self.max_retries < 0:
            raise ValueError("max_retries must be non-negative")
        if self.safe_search not in {"active", "off", None}:
            raise ValueError(
                f"safe_search must be 'active', 'off', or None, " f"got {self.safe_search!r}"
            )

    @classmethod
    def from_app_config(cls, raw: dict[str, Any]) -> "SerperConfig":
        """
        Construct from the 'search.serper' section of AppConfig.

        Enables endpoints listed in raw['enabled_endpoints'] if present,
        otherwise uses DEFAULT_ENABLED_ENDPOINTS.
        """
        enabled_raw: list[str] = raw.get("enabled_endpoints", list(DEFAULT_ENABLED_ENDPOINTS))
        return cls(
            enabled_endpoints=frozenset(enabled_raw),
            max_results=raw.get("max_results", 10),
            request_timeout_seconds=raw.get("request_timeout_seconds", 10.0),
            max_retries=raw.get("max_retries", 2),
            retry_delay_seconds=raw.get("retry_delay_seconds", 1.0),
            max_response_bytes=raw.get("max_response_bytes", 512_000),
            max_field_chars=raw.get("max_field_chars", 2_000),
            credit_warning_threshold=raw.get("credit_warning_threshold", 500),
            default_country=raw.get("default_country", "us"),
            default_language=raw.get("default_language", "en"),
            safe_search=raw.get("safe_search", "active"),
        )


def get_api_key() -> str:
    """
    Read the Serper API key from the environment.

    Security note: This function is the ONLY place the key is read.
    The returned string must not be stored in any serializable object,
    logged, or included in exception messages. Callers should treat it
    as ephemeral.

    Raises:
        RuntimeError: If SERPER_API_KEY is not set in the environment.
    """
    key = os.environ.get("SERPER_API_KEY", "")
    if not key:
        raise RuntimeError(
            "SERPER_API_KEY environment variable is not set. " "Set it before starting OpenRattler."
        )
    return key
