"""Content sanitizer for Google Workspace API responses.

Every piece of externally-sourced content that will reach the agent context
passes through this module before it becomes part of a UniversalMessage.  The
sanitizer's job is to:

  1. Strip HTML markup to plain text (using stdlib ``html.parser``).
  2. Unescape HTML entities so the agent receives readable text.
  3. Truncate at the configured character limit.
  4. Scan for prompt-injection patterns via ``scan_for_suspicious_content``.
  5. Return a ``SanitizedContent`` object that carries both the clean text and
     any security flags found — callers decide whether to block or warn.
  6. Fire an audit event when suspicious content is detected.

The caller (tool handler) wraps the result with ``wrap_for_agent`` before
placing it in ``UniversalMessage.params["body"]``.

SECURITY NOTES
--------------
- Flagged content is *not* silently dropped.  Silently dropping a flagged
  email could itself be exploited to suppress legitimate messages.  Instead,
  the content is delivered with a ``[SECURITY WARNING]`` prefix so the agent
  can apply its own judgment.  The audit log records every flag.
- Sender / author metadata is never passed through this module.  It lives
  in separate ``params`` keys (``params.from``, ``params.subject``) to prevent
  injection via crafted From headers or document titles.
- The HTML stripper uses stdlib ``html.parser`` only — no third-party HTML
  library is added.
"""

from __future__ import annotations

import html
import html.parser
import logging
from dataclasses import dataclass, field
from typing import Any

from openrattler.config.loader import GoogleConfig
from openrattler.models.audit import AuditEvent
from openrattler.security.patterns import scan_for_suspicious_content
from openrattler.storage.audit import AuditLog

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# HTML stripper
# ---------------------------------------------------------------------------


_SKIP_TAGS: frozenset[str] = frozenset({"script", "style", "head"})


class _HTMLStripper(html.parser.HTMLParser):
    """Minimal HTMLParser subclass that collects text nodes only.

    Content inside ``<script>``, ``<style>``, and ``<head>`` tags is skipped
    entirely — it is never executable in plain text and only adds noise.
    """

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self._parts: list[str] = []
        self._skip_depth: int = 0

    def handle_starttag(self, tag: str, attrs: Any) -> None:  # noqa: D401
        if tag.lower() in _SKIP_TAGS:
            self._skip_depth += 1

    def handle_endtag(self, tag: str) -> None:  # noqa: D401
        if tag.lower() in _SKIP_TAGS and self._skip_depth > 0:
            self._skip_depth -= 1

    def handle_data(self, data: str) -> None:  # noqa: D401
        if self._skip_depth == 0:
            self._parts.append(data)

    def get_text(self) -> str:
        return "".join(self._parts)


def _strip_html(raw: str) -> str:
    """Return *raw* with all HTML tags removed and entities unescaped."""
    stripper = _HTMLStripper()
    stripper.feed(raw)
    # html.unescape handles any remaining named/numeric references that
    # convert_charrefs=True may have missed in malformed markup.
    return html.unescape(stripper.get_text())


# ---------------------------------------------------------------------------
# Result dataclass
# ---------------------------------------------------------------------------


@dataclass
class SanitizedContent:
    """The result of a single sanitization pass.

    Attributes:
        text:            Cleaned, plain-text content ready for the agent.
        was_truncated:   True when the original input exceeded the char limit.
        security_flags:  ``(category, matched_text)`` pairs from the scanner;
                         empty list when no suspicious content was detected.
        original_length: Character count of the input *before* truncation.
    """

    text: str
    was_truncated: bool
    security_flags: list[tuple[str, str]] = field(default_factory=list)
    original_length: int = 0


# ---------------------------------------------------------------------------
# Sanitizer
# ---------------------------------------------------------------------------


class GoogleContentSanitizer:
    """Security gate for Google Workspace API content.

    Args:
        config: ``GoogleConfig`` section — provides character limits.
        audit:  ``AuditLog`` — receives a ``security_content_flagged`` event
                whenever suspicious patterns are detected.
    """

    def __init__(self, config: GoogleConfig, audit: AuditLog) -> None:
        self._config = config
        self._audit = audit

    # ------------------------------------------------------------------
    # Public sanitization methods
    # ------------------------------------------------------------------

    async def sanitize_email_body(self, raw: str, mime_type: str) -> SanitizedContent:
        """Sanitize an email body string.

        HTML bodies are stripped to plain text before scanning.  The result
        is truncated at ``config.max_email_chars``.

        Args:
            raw:       Raw body text from the Gmail API.
            mime_type: MIME type of the body part (e.g. ``"text/html"``).

        Returns:
            ``SanitizedContent`` with plain text, truncation flag, and any
            security flags.
        """
        return await self._sanitize(
            raw=raw,
            mime_type=mime_type,
            char_limit=self._config.max_email_chars,
            source_label="email_body",
        )

    async def sanitize_file_content(self, raw: str, mime_type: str) -> SanitizedContent:
        """Sanitize Drive file content.

        Same pipeline as ``sanitize_email_body`` but uses ``max_file_chars``
        as the truncation limit.

        Args:
            raw:       Raw file text (exported or downloaded from Drive).
            mime_type: MIME type reported by Drive.

        Returns:
            ``SanitizedContent`` with plain text, truncation flag, and any
            security flags.
        """
        return await self._sanitize(
            raw=raw,
            mime_type=mime_type,
            char_limit=self._config.max_file_chars,
            source_label="file_content",
        )

    # ------------------------------------------------------------------
    # Agent wrapper
    # ------------------------------------------------------------------

    def wrap_for_agent(self, content: SanitizedContent, label: str) -> str:
        """Wrap sanitized content in a labelled block for agent consumption.

        Format (no security flags):
        ::

            [EMAIL CONTENT]
            ...sanitized text...
            [/EMAIL CONTENT]

        Format (with security flags):
        ::

            [SECURITY WARNING: suspicious content detected — categories: instruction_override, exfiltration]
            [EMAIL CONTENT]
            ...sanitized text...
            [/EMAIL CONTENT]
            [Content truncated at 10000 characters]

        The label is uppercased automatically.  Examples: ``"EMAIL CONTENT"``,
        ``"FILE CONTENT"``, ``"EVENT CONTENT"``.

        Args:
            content: Result from a ``sanitize_*`` call.
            label:   Content-type label used for the boundary markers.

        Returns:
            Formatted string ready to place in ``params["body"]``.
        """
        upper_label = label.upper()
        parts: list[str] = []

        if content.security_flags:
            categories = ", ".join(sorted({cat for cat, _ in content.security_flags}))
            parts.append(
                f"[SECURITY WARNING: suspicious content detected — categories: {categories}]"
            )

        parts.append(f"[{upper_label}]")
        parts.append(content.text)
        parts.append(f"[/{upper_label}]")

        if content.was_truncated:
            limit = (
                self._config.max_email_chars
                if "EMAIL" in upper_label
                else self._config.max_file_chars
            )
            parts.append(f"[Content truncated at {limit} characters]")

        return "\n".join(parts)

    # ------------------------------------------------------------------
    # Internal pipeline
    # ------------------------------------------------------------------

    async def _sanitize(
        self,
        raw: str,
        mime_type: str,
        char_limit: int,
        source_label: str,
    ) -> SanitizedContent:
        original_length = len(raw)

        # Step 1: Strip HTML if needed.
        if "html" in mime_type.lower():
            text = _strip_html(raw)
        else:
            text = raw

        # Step 2: Truncate.
        was_truncated = len(text) > char_limit
        if was_truncated:
            text = text[:char_limit]

        # Step 3: Scan for suspicious patterns.
        flags = scan_for_suspicious_content(text)

        # Step 4: Audit on flag.
        if flags:
            categories = sorted({cat for cat, _ in flags})
            logger.warning(
                "GoogleContentSanitizer: suspicious content detected in %s — categories: %s",
                source_label,
                categories,
            )
            await self._audit.log(
                AuditEvent(
                    event="security_content_flagged",
                    details={
                        "source": source_label,
                        "categories": categories,
                        "flag_count": len(flags),
                        "original_length": original_length,
                        "was_truncated": was_truncated,
                    },
                )
            )

        return SanitizedContent(
            text=text,
            was_truncated=was_truncated,
            security_flags=flags,
            original_length=original_length,
        )
