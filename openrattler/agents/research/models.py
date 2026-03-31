"""Pydantic v2 models for the research agent subsystem.

All data entering and leaving the ResearchAgent is typed and validated here.
These models are the input/output contract — validation at the boundary is the
first line of defence before the agent is spawned and after it returns.

SECURITY NOTES
--------------
- ``ResearchRequest.query`` is intentionally short (max 300 chars) to limit
  the prompt-injection surface area.
- ``CitationRecord.domain`` is always derived programmatically from the URL
  via a field validator — the source cannot assert its own domain.
- ``ResearchResult.summary`` is hard-capped at 2000 chars.  The cap is
  enforced by a field validator so it is impossible for a caller to bypass it
  by constructing the model directly.
- ``ResearchResult.warnings`` may only contain agent-generated strings — no
  external content may appear there.  Enforcement is by convention; callers
  must never propagate raw fetched text into this field.
"""

from __future__ import annotations

import re
from datetime import date, datetime, timezone
from enum import Enum
from typing import Optional
from urllib.parse import urlparse

from pydantic import BaseModel, Field, field_validator, model_validator

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_QUERY_MAX_LEN: int = 300
_FOCUS_TERM_MAX_LEN: int = 60
_FOCUS_TERMS_MAX_COUNT: int = 10
_MAX_RESULTS_MIN: int = 1
_MAX_RESULTS_MAX: int = 10
_EXCLUDE_DOMAINS_MAX_COUNT: int = 20
_TITLE_MAX_LEN: int = 300
_AUTHOR_MAX_LEN: int = 150
_SUMMARY_MAX_LEN: int = 2000
_WARNINGS_MAX_COUNT: int = 5
_WARNING_MAX_LEN: int = 200
_ERROR_MESSAGE_MAX_LEN: int = 200

# Simple domain validation: one or more labels separated by dots,
# each label is alphanumeric + hyphens (RFC 1035-ish).
_DOMAIN_RE: re.Pattern[str] = re.compile(
    r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$"
)


# ---------------------------------------------------------------------------
# Enums
# ---------------------------------------------------------------------------


class SourceType(str, Enum):
    """Category of information source to search."""

    GENERAL = "general"
    NEWS = "news"
    ACADEMIC = "academic"
    TECHNICAL = "technical"


class OutputFormat(str, Enum):
    """Format in which research results should be returned."""

    SUMMARY = "summary"
    CITATIONS_ONLY = "citations_only"
    SUMMARY_WITH_CITATIONS = "summary_with_citations"


# ---------------------------------------------------------------------------
# Request model
# ---------------------------------------------------------------------------


class ResearchRequest(BaseModel):
    """Structured request arriving via UniversalMessage params block.

    All string fields are length-capped.  The query field is the only
    natural language field and is intentionally short to limit the
    prompt-injection surface area.

    Security note: this model is the input contract.  Validation here is the
    first line of defence before the ResearchAgent is spawned.
    """

    query: str = Field(description="Natural language research query, max 300 chars")
    focus_terms: list[tuple[str, float]] = Field(
        default_factory=list,
        description="(term, weight) pairs; max 10 items; term max 60 chars; weight 0.0–1.0",
    )
    source_types: list[SourceType] = Field(
        default_factory=lambda: [SourceType.GENERAL],
        description="Which source categories to search",
    )
    date_range: Optional[tuple[date, date]] = Field(
        default=None,
        description="Inclusive (start, end) date range filter; None means no filter",
    )
    max_results: int = Field(
        default=5,
        ge=_MAX_RESULTS_MIN,
        le=_MAX_RESULTS_MAX,
        description="Maximum number of results to return, 1–10",
    )
    output_format: OutputFormat = Field(
        default=OutputFormat.SUMMARY_WITH_CITATIONS,
        description="How results should be packaged",
    )
    exclude_domains: list[str] = Field(
        default_factory=list,
        description="Domains to exclude from search; max 20 entries, each a valid domain string",
    )

    @field_validator("query")
    @classmethod
    def query_length(cls, v: str) -> str:
        """Reject queries longer than 300 chars."""
        if len(v) > _QUERY_MAX_LEN:
            raise ValueError(f"query must not exceed {_QUERY_MAX_LEN} characters (got {len(v)})")
        return v

    @field_validator("focus_terms")
    @classmethod
    def validate_focus_terms(cls, v: list[tuple[str, float]]) -> list[tuple[str, float]]:
        """Enforce count limit, per-term length, and weight range."""
        if len(v) > _FOCUS_TERMS_MAX_COUNT:
            raise ValueError(
                f"focus_terms must not exceed {_FOCUS_TERMS_MAX_COUNT} items (got {len(v)})"
            )
        for i, (term, weight) in enumerate(v):
            if len(term) > _FOCUS_TERM_MAX_LEN:
                raise ValueError(
                    f"focus_terms[{i}] term must not exceed {_FOCUS_TERM_MAX_LEN} chars "
                    f"(got {len(term)})"
                )
            if not (0.0 <= weight <= 1.0):
                raise ValueError(f"focus_terms[{i}] weight must be 0.0–1.0 (got {weight!r})")
        return v

    @field_validator("exclude_domains")
    @classmethod
    def validate_exclude_domains(cls, v: list[str]) -> list[str]:
        """Enforce count limit and per-domain string format."""
        if len(v) > _EXCLUDE_DOMAINS_MAX_COUNT:
            raise ValueError(
                f"exclude_domains must not exceed {_EXCLUDE_DOMAINS_MAX_COUNT} items (got {len(v)})"
            )
        for i, domain in enumerate(v):
            if not _DOMAIN_RE.match(domain):
                raise ValueError(f"exclude_domains[{i}] is not a valid domain string: {domain!r}")
        return v


# ---------------------------------------------------------------------------
# Citation record
# ---------------------------------------------------------------------------


class CitationRecord(BaseModel):
    """Structured citation metadata.  No raw content — typed fields only.

    Security note: ``domain`` is always extracted programmatically from the
    URL.  Never trust a domain name asserted by the source itself.
    """

    title: str = Field(description="Article or page title, max 300 chars")
    url: str = Field(description="HTTP/HTTPS URL to the source")
    domain: str = Field(description="Domain extracted from url; set automatically by validator")
    source_type: SourceType
    published_date: Optional[date] = None
    author: Optional[str] = Field(default=None, description="Author name, max 150 chars")
    retrieval_timestamp: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc),
        description="When this citation was retrieved",
    )

    @field_validator("title")
    @classmethod
    def title_length(cls, v: str) -> str:
        """Reject titles longer than 300 chars."""
        if len(v) > _TITLE_MAX_LEN:
            raise ValueError(f"title must not exceed {_TITLE_MAX_LEN} characters (got {len(v)})")
        return v

    @field_validator("url")
    @classmethod
    def url_must_be_http(cls, v: str) -> str:
        """Reject any URL that is not HTTP or HTTPS."""
        parsed = urlparse(v)
        if parsed.scheme not in ("http", "https"):
            raise ValueError(f"url must use http or https scheme (got {parsed.scheme!r} in {v!r})")
        if not parsed.netloc:
            raise ValueError(f"url has no host: {v!r}")
        return v

    @field_validator("domain", mode="before")
    @classmethod
    def extract_domain_from_url(cls, v: object, info: object) -> str:
        """Always derive domain from the url field; ignore whatever is passed in.

        Security note: the source cannot assert its own domain.  We parse
        the URL ourselves every time, regardless of what the caller supplies.

        Note: ``model_validator(mode="after")`` performs the authoritative
        derivation once all fields are guaranteed to be present and valid.
        This pre-validator returns a placeholder so Pydantic has a non-None
        value for the ``domain`` field during the initial validation pass.
        """
        # In Pydantic v2, info.data contains already-validated fields.
        # Use hasattr rather than isinstance to avoid Protocol runtime-check issues.
        url_value: str = ""
        if hasattr(info, "data"):
            url_value = info.data.get("url", "")

        if not url_value:
            # url not yet validated or validation failed — return placeholder;
            # model_validator will correct when url is valid and all fields present.
            return ""

        parsed = urlparse(url_value)
        return parsed.hostname or ""

    @model_validator(mode="after")
    def ensure_domain_from_url(self) -> "CitationRecord":
        """Final correction: ensure domain is always derived from url.

        Runs after all field validators so ``url`` is guaranteed to be valid.
        This is the authoritative derivation — overrides anything set earlier.
        """
        parsed = urlparse(self.url)
        object.__setattr__(self, "domain", parsed.hostname or "")
        return self

    @field_validator("author")
    @classmethod
    def author_length(cls, v: Optional[str]) -> Optional[str]:
        """Reject author strings longer than 150 chars."""
        if v is not None and len(v) > _AUTHOR_MAX_LEN:
            raise ValueError(f"author must not exceed {_AUTHOR_MAX_LEN} characters (got {len(v)})")
        return v


# ---------------------------------------------------------------------------
# Result model
# ---------------------------------------------------------------------------


class ResearchResult(BaseModel):
    """Sanitized output package returned to the calling agent via UniversalMessage.

    This is the ONLY data that exits the ResearchAgent context.

    Security note: summary is hard-capped at 2000 chars.  Citations are
    structured metadata, never raw content.  Warnings are agent-generated
    strings only — no external content may appear in the warnings field.
    """

    query_echo: str = Field(description="Echo of original query for caller verification")
    summary: str = Field(description="Research summary, max 2000 chars")
    citations: list[CitationRecord]
    source_types_searched: list[SourceType]
    result_count: int = Field(ge=0)
    search_timestamp: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc),
    )
    trace_id: str = Field(description="Propagated from the originating ResearchRequest UM")
    warnings: list[str] = Field(
        default_factory=list,
        description="Agent-generated warnings only; max 5 items; each max 200 chars",
    )

    @field_validator("summary")
    @classmethod
    def summary_length(cls, v: str) -> str:
        """Hard-cap summary at 2000 chars."""
        if len(v) > _SUMMARY_MAX_LEN:
            raise ValueError(
                f"summary must not exceed {_SUMMARY_MAX_LEN} characters (got {len(v)})"
            )
        return v

    @field_validator("warnings")
    @classmethod
    def validate_warnings(cls, v: list[str]) -> list[str]:
        """Enforce count limit and per-item length."""
        if len(v) > _WARNINGS_MAX_COUNT:
            raise ValueError(f"warnings must not exceed {_WARNINGS_MAX_COUNT} items (got {len(v)})")
        for i, w in enumerate(v):
            if len(w) > _WARNING_MAX_LEN:
                raise ValueError(
                    f"warnings[{i}] must not exceed {_WARNING_MAX_LEN} chars (got {len(w)})"
                )
        return v


# ---------------------------------------------------------------------------
# Error model
# ---------------------------------------------------------------------------


class ResearchError(BaseModel):
    """Structured error returned when research fails or is blocked.

    Returned as the params block of a UM ``type='error'`` message.

    Security note: ``message`` must never contain raw external content —
    only agent-generated or pipeline-generated descriptions.
    """

    error_code: str = Field(
        description=(
            "One of: NO_RESULTS | FETCH_BLOCKED | SANITIZATION_FAILED | TIMEOUT | INVALID_REQUEST"
        )
    )
    message: str = Field(description="Human-readable error description, max 200 chars")
    query_echo: str
    trace_id: str

    @field_validator("message")
    @classmethod
    def message_length(cls, v: str) -> str:
        """Reject error messages longer than 200 chars."""
        if len(v) > _ERROR_MESSAGE_MAX_LEN:
            raise ValueError(
                f"message must not exceed {_ERROR_MESSAGE_MAX_LEN} characters (got {len(v)})"
            )
        return v
