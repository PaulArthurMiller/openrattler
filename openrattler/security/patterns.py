"""Suspicious-content pattern scanning.

This module provides a catalogue of regex patterns that flag potentially
hostile text — prompt injection, command injection, credential harvesting,
privilege escalation, and exfiltration attempts.

The scanner is intentionally broad: it is a first-pass filter, not a
definitive verdict.  Matches should be reviewed by the security agent or
escalated to the user for confirmation before taking action.

Pattern catalogue is derived from SECURITY.md §10 "Memory Security Review"
and extended to cover the full input-filtering threat surface (Layer 6).

SECURITY NOTES
--------------
- All patterns use ``re.IGNORECASE`` so capitalised variants are caught.
- Each pattern entry carries a *pattern_name* that identifies the threat
  category, making it easy to route matches to the appropriate handler.
- The same pattern name may appear multiple times in ``SUSPICIOUS_PATTERNS``
  for different regexes in the same category (e.g. two distinct exfiltration
  patterns both use the name ``"exfiltration"``).
- ``scan_for_suspicious_content`` returns one entry per regex *match*, not
  one entry per pattern.  A single input may produce multiple matches from
  the same or different patterns.
"""

from __future__ import annotations

import re

# ---------------------------------------------------------------------------
# Pattern definitions
# ---------------------------------------------------------------------------

#: Each entry is a ``(pattern_name, regex_string)`` pair.
#:
#: *pattern_name* identifies the threat category (e.g. ``"command_injection"``).
#: *regex_string* is the pattern to search for (case-insensitive).
#:
#: Categories:
#:   command_injection   — embedding shell/Python execution in text
#:   destructive_command — commands that destroy data or storage
#:   exfiltration        — tools/patterns used to send data out
#:   privilege_escalation — gaining elevated permissions
#:   instruction_override — classic prompt-injection openers
#:   credential_access   — probing for or referencing secrets
SUSPICIOUS_PATTERNS: list[tuple[str, str]] = [
    # ------------------------------------------------------------------
    # Command injection — attempts to embed execution in input/output
    # Require shell/function-call context to avoid false positives on
    # everyday words like "system" or "exec" in natural language.
    # ------------------------------------------------------------------
    # Function-call syntax: system(...), exec(...), eval(...)
    ("command_injection", r"\b(?:exec|system|eval)\s*\("),
    # os module execution calls (already context-specific via the dot)
    ("command_injection", r"os\.(?:system|popen|exec[lve]{0,2})"),
    # subprocess is specific enough; flag it regardless of context
    ("command_injection", r"\bsubprocess\b"),
    # Shell pipe/semicolon injection: ; system cmd, | exec cmd
    ("command_injection", r"[;|&]\s*(?:exec|system)\b"),
    # ------------------------------------------------------------------
    # Destructive commands — data/storage destruction
    # ------------------------------------------------------------------
    ("destructive_command", r"rm\s+-[rRfF]{1,2}|dd\s+if=|mkfs"),
    # ------------------------------------------------------------------
    # Exfiltration — tools commonly used to exfiltrate data
    # ------------------------------------------------------------------
    ("exfiltration", r"\b(?:curl|wget|nc|netcat)\b"),
    ("exfiltration", r"send\s+.*to\s+.*@|email\s+.*attachment"),
    # ------------------------------------------------------------------
    # Privilege escalation — gaining elevated permissions
    # ------------------------------------------------------------------
    ("privilege_escalation", r"\bsudo\b|chmod\s+777|chown\s+root"),
    # ------------------------------------------------------------------
    # Instruction override — classic prompt-injection openers
    # ------------------------------------------------------------------
    ("instruction_override", r"ignore\s+(?:previous|all)\s+instructions"),
    ("instruction_override", r"always\s+(?:execute|run|send)\b"),
    ("instruction_override", r"never\s+(?:ask|prompt|confirm)\b"),
    # ------------------------------------------------------------------
    # Credential access — probing for or referencing secrets
    # Require context qualifiers for common words (token, secret) to
    # avoid false positives on everyday language ("the secret to...",
    # "CSRF token").  Principle mirrors command_injection patterns above.
    # ------------------------------------------------------------------
    # api_key and password are specific enough without context
    ("credential_access", r"api[_-]?key|\bpassword\b"),
    # secret and token only flagged when combined with credential-context
    # qualifiers (api_secret, auth_token, bearer token, secret_key, etc.)
    # or when followed by an assignment operator (token=, secret:).
    # Separator [_\-\s]? allows underscore, hyphen, or a single space
    # so "auth_token", "auth-token", and "auth token" are all caught.
    ("credential_access", r"(?:api|app|client|auth|jwt)[_\-\s]?(?:secret|token)"),
    ("credential_access", r"(?:secret|access|bearer)[_\-\s]?(?:key|token)"),
    ("credential_access", r"\b(?:token|secret)\s*[:=]\s*\S"),
]


# ---------------------------------------------------------------------------
# Scanner
# ---------------------------------------------------------------------------


def scan_for_suspicious_content(text: str) -> list[tuple[str, str]]:
    """Scan *text* for suspicious patterns.

    Args:
        text: Arbitrary text to scan — e.g. a user message, LLM output,
              proposed memory change, or tool result.

    Returns:
        A list of ``(pattern_name, matched_text)`` tuples, one entry per
        regex match found.  The list is empty when no suspicious content
        is detected.

    Security notes:
    - Uses ``re.IGNORECASE`` so ``SUDO``, ``Sudo``, ``sudo`` are all caught.
    - The matched string (``match.group()``) is returned, not the surrounding
      context, to keep audit-log entries concise.
    - The same pattern name can appear multiple times if the regex matches
      at multiple positions in the text.
    """
    results: list[tuple[str, str]] = []
    for pattern_name, pattern in SUSPICIOUS_PATTERNS:
        for match in re.finditer(pattern, text, re.IGNORECASE):
            results.append((pattern_name, match.group()))
    return results
