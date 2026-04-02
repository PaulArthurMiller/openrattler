"""
Window 1 sanitizer for Serper search results.

Runs BEFORE Pydantic model construction and BEFORE LLM exposure.
All text fields in the raw Serper JSON response are scanned for
suspicious patterns before any further processing.

This is the pitch-catch checkpoint between the external Serper API
(untrusted) and the ResearchAgent's LLM context (trusted internal).

Security note: If any field fails, the entire response is rejected —
not trimmed. A partial result set that had one injection-bearing field
removed could still mislead the LLM about what was and wasn't found.
Rejection is logged with full details for audit.
"""

from __future__ import annotations

import logging
from typing import Any

from openrattler.security.sanitization import scan_for_suspicious_content
from openrattler.tools.search.serper_config import ENDPOINT_TEXT_FIELDS

logger = logging.getLogger(__name__)


class SerperSanitizationError(Exception):
    """Raised when Serper response fails sanitization."""

    pass


def _extract_text_values(data: Any, field_path: str) -> list[str]:
    """
    Extract all string values matching a field path pattern from a dict/list
    structure. Supports '[]' for list iteration and '.*' for dict value iteration.

    Returns a flat list of all string values found. Non-string leaves are ignored.
    """
    # Strip leading dot if present
    parts = field_path.lstrip(".").split(".", 1)
    key = parts[0]
    rest = parts[1] if len(parts) > 1 else ""

    values: list[str] = []

    if key.endswith("[]"):
        # List iteration
        list_key = key[:-2]
        target = data.get(list_key, []) if isinstance(data, dict) else []
        if isinstance(target, list):
            for item in target:
                if rest:
                    values.extend(_extract_text_values(item, rest))
                elif isinstance(item, str):
                    values.append(item)
    elif key == "*":
        # Dict value iteration
        if isinstance(data, dict):
            for v in data.values():
                if rest:
                    values.extend(_extract_text_values(v, rest))
                elif isinstance(v, str):
                    values.append(v)
    else:
        # Simple key lookup
        target = data.get(key) if isinstance(data, dict) else None
        if target is None:
            return values
        if rest:
            values.extend(_extract_text_values(target, rest))
        elif isinstance(target, str):
            values.append(target)

    return values


def sanitize_serper_response(
    raw_json: dict[str, Any],
    endpoint: str,
    trace_id: str,
    audit_log_fn: Any = None,  # Optional callable(event_dict) for audit logging
) -> dict[str, Any]:
    """
    Scan all text fields in a raw Serper API response for suspicious patterns.

    Must be called before constructing any Pydantic models or exposing
    results to the LLM. Returns the raw_json unchanged if clean (the
    caller proceeds to model construction). Raises SerperSanitizationError
    if any field is flagged.

    Args:
        raw_json: The parsed JSON dict from Serper's API response.
        endpoint: The Serper endpoint that produced this response
                  (used to select the appropriate field paths).
        trace_id: Trace ID for audit correlation.
        audit_log_fn: Optional callable that accepts an audit event dict.
                      If None, logging.warning is used.

    Returns:
        raw_json (unchanged) if all fields pass.

    Raises:
        SerperSanitizationError: If any text field contains suspicious content.

    Security note: Rejection reason is logged but never included in
    exception messages that propagate to the LLM or user output.
    The LLM receives only "search results unavailable" on failure.
    """
    field_paths = ENDPOINT_TEXT_FIELDS.get(endpoint, [])

    flagged_fields: list[dict[str, str]] = []

    for path in field_paths:
        texts = _extract_text_values(raw_json, path)
        for text in texts:
            # scan_for_suspicious_content returns list[tuple[pattern_name, matched_text]]
            # An empty list means clean; a non-empty list means flagged.
            matches = scan_for_suspicious_content(text)
            if matches:
                # Record the first matched pattern name; do NOT include the text value.
                flagged_fields.append(
                    {
                        "field_path": path,
                        "pattern": matches[0][0],
                    }
                )

    audit_event = {
        "event": "serper_sanitizer",
        "trace_id": trace_id,
        "endpoint": endpoint,
        "fields_checked": len(field_paths),
        "passed": len(flagged_fields) == 0,
        "flagged_count": len(flagged_fields),
        "flagged_fields": flagged_fields,
    }

    if audit_log_fn is not None:
        try:
            audit_log_fn(audit_event)
        except Exception:
            logger.warning(
                "serper_sanitizer: audit log call failed for trace_id=%s",
                trace_id,
            )
    else:
        if flagged_fields:
            logger.warning(
                "serper_sanitizer: FLAGGED trace_id=%s endpoint=%s fields=%s",
                trace_id,
                endpoint,
                flagged_fields,
            )
        else:
            logger.debug(
                "serper_sanitizer: CLEAN trace_id=%s endpoint=%s",
                trace_id,
                endpoint,
            )

    if flagged_fields:
        raise SerperSanitizationError(
            f"Serper response for endpoint '{endpoint}' failed sanitization "
            f"({len(flagged_fields)} field(s) flagged). "
            f"trace_id={trace_id}"
        )

    return raw_json
