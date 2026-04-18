"""CCOutputParser — parse Claude Code's --output-format json response.

CC's JSON output schema (from ``claude -p <task> --output-format json``):

    {
        "type": "result",
        "subtype": "success" | "error_during_execution" | ...,
        "result": "<text output from CC>",
        "session_id": "<uuid>",
        "cost_usd": 0.012,
        "num_turns": 3,
        "is_error": false
    }

All fields except ``result``/``is_error`` are optional — older or future CC
versions may add/remove fields.  ``CCOutputParser.parse`` is resilient to
missing fields; it only fails hard when the raw string is not valid JSON.
"""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass, field
from typing import Any, Optional

logger = logging.getLogger(__name__)


@dataclass
class CCParsedOutput:
    """Structured result from a CC subprocess run.

    Attributes:
        result:     The text output CC produced (may be empty on error).
        is_error:   True if CC reported an internal error.
        session_id: CC's session UUID, used as the correlation key in audit logs.
        cost_usd:   Estimated API cost for the session (may be None if CC omits it).
        num_turns:  Number of LLM turns CC used (may be None).
        error:      Parse-level or CC-level error message; None on clean success.
        raw:        The original JSON string (retained for debugging).
    """

    result: str = ""
    is_error: bool = False
    session_id: Optional[str] = None
    cost_usd: Optional[float] = None
    num_turns: Optional[int] = None
    error: Optional[str] = None
    raw: str = field(default="", repr=False)


class CCOutputParser:
    """Parse the JSON response emitted by ``claude --output-format json``.

    Usage::

        parser = CCOutputParser()
        parsed = parser.parse(raw_stdout)
        if parsed.error:
            handle_error(parsed.error)
        else:
            use_result(parsed.result)

    Security notes:
    - ``parse`` never executes any code from the CC output — it only
      deserialises JSON and reads known field names.
    - Unknown fields in the JSON payload are silently ignored.
    - A non-zero CC exit code does not cause ``parse`` to raise; the caller
      (CCSubprocessManager) sets ``is_error=True`` via the returned
      ``CCResult.returncode`` and surfaces the error through ``ToolResult``.
    """

    def parse(self, raw: str) -> CCParsedOutput:
        """Parse *raw* JSON string into a ``CCParsedOutput``.

        Args:
            raw: The raw stdout captured from the CC subprocess.

        Returns:
            A ``CCParsedOutput`` with fields populated from the JSON.  If the
            string is empty or not valid JSON, ``error`` is set and ``result``
            is empty.
        """
        if not raw or not raw.strip():
            return CCParsedOutput(
                error="CC produced no output",
                raw=raw,
            )

        try:
            data: dict[str, Any] = json.loads(raw)
        except json.JSONDecodeError as exc:
            logger.warning("CCOutputParser: JSON decode failed: %s", exc)
            return CCParsedOutput(
                error=f"CC output was not valid JSON: {exc}",
                raw=raw,
            )

        result: str = data.get("result", "")
        is_error: bool = bool(data.get("is_error", False))
        session_id: Optional[str] = data.get("session_id") or None
        num_turns: Optional[int] = data.get("num_turns") or None

        # cost_usd may be absent or null; coerce to float only when present.
        raw_cost = data.get("cost_usd")
        cost_usd: Optional[float] = float(raw_cost) if raw_cost is not None else None

        # Surface CC-level errors as the error field so callers need not inspect is_error.
        error: Optional[str] = None
        if is_error:
            error = result or "CC reported an error (no detail in output)"

        logger.debug(
            "CCOutputParser: parsed session_id=%s turns=%s cost=$%s is_error=%s",
            session_id,
            num_turns,
            cost_usd,
            is_error,
        )

        return CCParsedOutput(
            result=result,
            is_error=is_error,
            session_id=session_id,
            cost_usd=cost_usd,
            num_turns=num_turns,
            error=error,
            raw=raw,
        )
