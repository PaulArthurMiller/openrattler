"""
Serper API HTTP client.

Responsibilities:
- Enforce endpoint allowlist (rejects disallowed endpoints before network call)
- Enforce timeouts and retry limits
- Enforce response size cap before parsing
- Parse credit headers
- Invoke SerperSanitizer (Window 1) before returning any data
- Never log the API key

This client does NOT construct Pydantic result models — that is the
caller's responsibility after receiving the sanitized raw dict.
"""

from __future__ import annotations

import asyncio
import json
import logging
import uuid
from typing import Any, Optional

import aiohttp

from openrattler.tools.search.serper_config import SerperConfig, get_api_key
from openrattler.tools.search.serper_models import SerperCredits
from openrattler.tools.search.serper_sanitizer import (
    SerperSanitizationError,
    sanitize_serper_response,
)

logger = logging.getLogger(__name__)

SERPER_BASE_URL = "https://google.serper.dev"

# Endpoints that use POST with a JSON body (all current Serper endpoints do)
POST_ENDPOINTS = {
    "search",
    "images",
    "news",
    "videos",
    "places",
    "maps",
    "shopping",
    "scholar",
    "patents",
    "lens",
}

# Autocomplete uses GET
GET_ENDPOINTS = {"autocomplete"}


class SerperClientError(Exception):
    """Base error for Serper client failures."""

    pass


class SerperEndpointNotAllowedError(SerperClientError):
    """Raised when the requested endpoint is not in the config allowlist."""

    pass


class SerperAuthError(SerperClientError):
    """Raised on 401/403 — key missing, invalid, or exhausted."""

    pass


class SerperRateLimitError(SerperClientError):
    """Raised on 429 — rate limit exceeded."""

    pass


class SerperResponseTooLargeError(SerperClientError):
    """Raised when response exceeds max_response_bytes."""

    pass


class SerperClient:
    """
    Async HTTP client for the Serper API.

    Security note: The API key is read from the environment at call time
    via get_api_key(). It is never stored as an instance attribute and
    never appears in logs or exception messages.

    Usage:
        client = SerperClient(config)
        raw, credits = await client.search(
            endpoint="search",
            query="python async patterns",
            trace_id="abc-123",
        )
    """

    def __init__(self, config: SerperConfig) -> None:
        self._config = config

    async def search(
        self,
        endpoint: str,
        query: str,
        trace_id: Optional[str] = None,
        *,
        # Optional per-call overrides (all respected by Serper)
        num: Optional[int] = None,
        gl: Optional[str] = None,  # Country code override
        hl: Optional[str] = None,  # Language override
        safe: Optional[str] = None,  # Safe search override
        location: Optional[str] = None,  # Location string (e.g. "Austin, Texas")
        tbs: Optional[str] = None,  # Time-based search filter
        autocorrect: Optional[bool] = None,
        page: Optional[int] = None,  # Results page number
        # audit_log_fn for sanitizer
        audit_log_fn: Any = None,
    ) -> tuple[dict[str, Any], SerperCredits]:
        """
        Execute a search request against the specified Serper endpoint.

        Enforces: endpoint allowlist, timeout, retries, response size cap,
        Window 1 sanitization.

        Args:
            endpoint: One of ALL_SERPER_ENDPOINTS. Must be in config's
                      enabled_endpoints or SerperEndpointNotAllowedError
                      is raised immediately (no network call made).
            query: The search query string.
            trace_id: Optional trace ID for audit correlation. Generated
                      if not provided.
            num: Override max_results from config for this call.
            gl: Country code override (ISO 3166-1 alpha-2).
            hl: Language override (BCP 47).
            safe: Safe search override ("active" | "off").
            location: Location string for localised results.
            tbs: Time-based search filter string.
            autocorrect: Whether to autocorrect the query.
            page: Page number for paginated results.
            audit_log_fn: Optional callable for audit event routing.

        Returns:
            Tuple of (sanitized raw JSON dict, SerperCredits).

        Raises:
            SerperEndpointNotAllowedError: Endpoint not in allowlist.
            SerperAuthError: API key invalid or missing.
            SerperRateLimitError: Rate limit exceeded.
            SerperResponseTooLargeError: Response exceeded size cap.
            SerperSanitizationError: Window 1 scan flagged content.
            SerperClientError: Any other Serper/network error.
        """
        if trace_id is None:
            trace_id = str(uuid.uuid4())

        # --- Enforce endpoint allowlist BEFORE network call ---
        if endpoint not in self._config.enabled_endpoints:
            raise SerperEndpointNotAllowedError(
                f"Endpoint '{endpoint}' is not in the enabled endpoints list. "
                f"Enabled: {sorted(self._config.enabled_endpoints)}"
            )

        # --- Build request payload ---
        payload: dict[str, Any] = {"q": query}
        payload["num"] = num if num is not None else self._config.max_results
        payload["gl"] = gl if gl is not None else self._config.default_country
        payload["hl"] = hl if hl is not None else self._config.default_language
        _safe = safe if safe is not None else self._config.safe_search
        if _safe is not None:
            payload["safe"] = _safe
        if location is not None:
            payload["location"] = location
        if tbs is not None:
            payload["tbs"] = tbs
        if autocorrect is not None:
            payload["autocorrect"] = autocorrect
        if page is not None:
            payload["page"] = page

        # Remove None values (Serper uses its own defaults for absent params)
        payload = {k: v for k, v in payload.items() if v is not None}

        url = f"{SERPER_BASE_URL}/{endpoint}"
        headers = {
            "X-API-KEY": get_api_key(),  # Read fresh at call time
            "Content-Type": "application/json",
        }

        last_error: Exception = SerperClientError("No attempts made")
        attempts = 0
        max_attempts = self._config.max_retries + 1  # retries + first attempt

        while attempts < max_attempts:
            attempts += 1
            try:
                raw_dict, credits = await self._execute_request(
                    url=url,
                    headers=headers,
                    payload=payload,
                    endpoint=endpoint,
                    trace_id=trace_id,
                    audit_log_fn=audit_log_fn,
                )
                return raw_dict, credits

            except (
                SerperAuthError,
                SerperEndpointNotAllowedError,
                SerperSanitizationError,
                SerperResponseTooLargeError,
            ):
                # Non-retryable: don't waste attempts
                raise

            except SerperRateLimitError:
                # Rate limits are not transient — don't retry
                raise

            except SerperClientError as exc:
                last_error = exc
                if attempts < max_attempts:
                    await asyncio.sleep(self._config.retry_delay_seconds)
                    logger.debug(
                        "serper_client: retrying after error (attempt %d/%d) " "trace_id=%s",
                        attempts,
                        max_attempts,
                        trace_id,
                    )

        raise last_error

    async def _execute_request(
        self,
        url: str,
        headers: dict[str, str],
        payload: dict[str, Any],
        endpoint: str,
        trace_id: str,
        audit_log_fn: Any,
    ) -> tuple[dict[str, Any], SerperCredits]:
        """Single HTTP request with timeout, size cap, and sanitization."""
        timeout = aiohttp.ClientTimeout(total=self._config.request_timeout_seconds)

        try:
            async with aiohttp.ClientSession(timeout=timeout) as session:
                if endpoint in POST_ENDPOINTS:
                    resp_ctx = session.post(url, json=payload, headers=headers)
                else:
                    # GET endpoints pass query as param
                    get_params = {**payload}
                    resp_ctx = session.get(url, params=get_params, headers=headers)

                async with resp_ctx as response:
                    # --- Auth / rate limit checks ---
                    if response.status in (401, 403):
                        raise SerperAuthError(
                            f"Serper auth failed (HTTP {response.status}). " "Check SERPER_API_KEY."
                        )
                    if response.status == 429:
                        raise SerperRateLimitError("Serper rate limit exceeded.")
                    if response.status >= 500:
                        raise SerperClientError(f"Serper server error (HTTP {response.status}).")
                    if response.status not in (200, 201):
                        raise SerperClientError(f"Unexpected Serper status: {response.status}")

                    # --- Response size cap (read raw bytes) ---
                    raw_bytes = await response.read()
                    if len(raw_bytes) > self._config.max_response_bytes:
                        raise SerperResponseTooLargeError(
                            f"Serper response size {len(raw_bytes)} bytes "
                            f"exceeds cap {self._config.max_response_bytes}."
                        )

                    # --- Parse credits from headers ---
                    credits = _parse_credits(response.headers)

                    # --- Check credit warning threshold ---
                    if (
                        credits.credits_remaining is not None
                        and self._config.credit_warning_threshold > 0
                        and credits.credits_remaining <= self._config.credit_warning_threshold
                    ):
                        logger.warning(
                            "serper_client: LOW CREDITS — %d remaining " "(threshold: %d)",
                            credits.credits_remaining,
                            self._config.credit_warning_threshold,
                        )

                    # --- Parse JSON ---
                    try:
                        raw_dict = json.loads(raw_bytes)
                    except json.JSONDecodeError as exc:
                        raise SerperClientError(f"Serper returned invalid JSON: {exc}") from exc

                    if not isinstance(raw_dict, dict):
                        raise SerperClientError("Serper response was not a JSON object.")

                    # --- Window 1: Sanitize before returning ---
                    sanitize_serper_response(
                        raw_json=raw_dict,
                        endpoint=endpoint,
                        trace_id=trace_id,
                        audit_log_fn=audit_log_fn,
                    )

                    return raw_dict, credits

        except asyncio.TimeoutError as exc:
            raise SerperClientError(
                f"Serper request timed out after " f"{self._config.request_timeout_seconds}s."
            ) from exc
        except aiohttp.ClientError as exc:
            raise SerperClientError(
                f"Serper network error: {type(exc).__name__}"
                # Note: exc message intentionally omitted — may contain URL
                # fragments or headers that could leak key material
            ) from exc


def _parse_credits(headers: Any) -> SerperCredits:
    """
    Parse credit information from Serper response headers.

    Header names observed in Serper responses:
      X-RateLimit-Limit       — total credits in pack
      X-RateLimit-Remaining   — credits remaining
      X-Credits-Used          — credits consumed by this request

    All fields are optional; parsing failures return None for that field.
    """

    def _safe_int(value: Optional[str]) -> Optional[int]:
        if value is None:
            return None
        try:
            return int(value)
        except (ValueError, TypeError):
            return None

    return SerperCredits(
        credits_used=_safe_int(headers.get("X-Credits-Used")),
        credits_remaining=_safe_int(headers.get("X-RateLimit-Remaining")),
        plan_limit=_safe_int(headers.get("X-RateLimit-Limit")),
    )
