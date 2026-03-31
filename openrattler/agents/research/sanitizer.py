"""Output sanitization pipeline for the research agent.

Two mandatory stages run in sequence.  A failure at either stage returns a
``ResearchError`` — nothing partial exits the pipeline.

Stage 1 — Injection pattern filter
    Runs ``scan_for_suspicious_content`` (from ``openrattler.security.sanitization``)
    against the summary and each citation title/author.  Any match is a hard
    rejection.

Stage 2 — Schema enforcement
    Constructs ``ResearchResult`` via Pydantic.  Any validation failure —
    field length exceeded, invalid URL, citation count exceeds max_results,
    etc. — is a hard rejection.

Audit trail
    A structured ``AuditEvent`` is written on *every* invocation (pass or
    fail) before the method returns.  This is the primary debugging mechanism
    when no session transcript is retained.  It records enough context to
    reconstruct what the sanitizer saw and decided, without recording raw
    external content.

SECURITY NOTES
--------------
- ``sanitize`` never raises; all failure modes return ``ResearchError``.
- Raw fetched content must never reach this class — only the agent's
  synthesized summary and extracted citation metadata.
- Pattern import is from ``openrattler.security.sanitization``, not a
  local copy, so every pipeline shares the same pattern set.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from pydantic import ValidationError

from openrattler.agents.research.models import (
    CitationRecord,
    ResearchError,
    ResearchRequest,
    ResearchResult,
)
from openrattler.models.audit import AuditEvent
from openrattler.security.sanitization import scan_for_suspicious_content
from openrattler.storage.audit import AuditLog


class ResearchSanitizer:
    """Sanitizes ResearchAgent output before it exits to the calling agent.

    Primary injection defence for the research pipeline.  Raw fetched content
    must never reach this class — only the agent's synthesized summary and
    extracted citation metadata.

    Security note: returns ``ResearchError`` on all failure modes, never
    raises.  All decisions are written to the audit log with ``trace_id``
    linkage.

    Args:
        audit: ``AuditLog`` instance that receives a sanitization event for
               every call to ``sanitize``, whether the call passes or fails.
    """

    def __init__(self, audit: AuditLog) -> None:
        self._audit = audit

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    async def sanitize(
        self,
        raw_summary: str,
        raw_citations: list[dict[str, Any]],
        request: ResearchRequest,
        trace_id: str,
    ) -> ResearchResult | ResearchError:
        """Run the two-stage sanitization pipeline.

        Args:
            raw_summary:    Agent-synthesized summary text (not raw fetched content).
            raw_citations:  List of citation attribute dicts produced by the agent.
            request:        The originating ``ResearchRequest`` (provides max_results
                            and other context for Stage 2 validation).
            trace_id:       Trace ID from the originating UniversalMessage; propagated
                            to the audit log and result model.

        Returns:
            ``ResearchResult`` on success, ``ResearchError`` on any failure.

        Security notes:
        - Never raises; all exceptions are caught and returned as a
          ``ResearchError`` with ``error_code="SANITIZATION_FAILED"``.
        - Audit log is written *before* returning, on every code path.
        """
        try:
            return await self._run_pipeline(raw_summary, raw_citations, request, trace_id)
        except Exception as exc:  # pragma: no cover — safety net
            await self._audit.log(
                AuditEvent(
                    event="research_sanitization_fail",
                    trace_id=trace_id,
                    details={
                        "stage": "unknown",
                        "reason": f"Unexpected sanitizer error: {exc}",
                    },
                )
            )
            return ResearchError(
                error_code="SANITIZATION_FAILED",
                message="Internal sanitizer error",
                query_echo=request.query,
                trace_id=trace_id,
            )

    # ------------------------------------------------------------------
    # Private implementation
    # ------------------------------------------------------------------

    async def _run_pipeline(
        self,
        raw_summary: str,
        raw_citations: list[dict[str, Any]],
        request: ResearchRequest,
        trace_id: str,
    ) -> ResearchResult | ResearchError:
        """Core pipeline — separated from ``sanitize`` so the outer method can catch errors."""

        # ------------------------------------------------------------------
        # Stage 1: Injection pattern filter
        # ------------------------------------------------------------------
        stage1_result = self._stage1_injection_filter(raw_summary, raw_citations)
        if stage1_result is not None:
            # stage1_result is (reason, pattern_matched)
            reason, pattern_matched = stage1_result
            await self._audit.log(
                AuditEvent(
                    event="research_sanitization_fail",
                    trace_id=trace_id,
                    details={
                        "stage": 1,
                        "reason": reason,
                        "pattern_matched": pattern_matched,
                    },
                )
            )
            return ResearchError(
                error_code="SANITIZATION_FAILED",
                message="Output blocked by injection filter",
                query_echo=request.query,
                trace_id=trace_id,
            )

        # ------------------------------------------------------------------
        # Stage 2: Schema enforcement
        # ------------------------------------------------------------------
        stage2_result = self._stage2_schema_enforcement(
            raw_summary, raw_citations, request, trace_id
        )
        if isinstance(stage2_result, str):
            # stage2_result is an error reason string
            await self._audit.log(
                AuditEvent(
                    event="research_sanitization_fail",
                    trace_id=trace_id,
                    details={
                        "stage": 2,
                        "reason": stage2_result,
                    },
                )
            )
            return ResearchError(
                error_code="SANITIZATION_FAILED",
                message="Output failed schema validation",
                query_echo=request.query,
                trace_id=trace_id,
            )

        # ------------------------------------------------------------------
        # Both stages passed — audit and return result
        # ------------------------------------------------------------------
        result: ResearchResult = stage2_result
        await self._audit.log(
            AuditEvent(
                event="research_sanitization_pass",
                trace_id=trace_id,
                details={
                    "summary_length": len(result.summary),
                    "citation_count": len(result.citations),
                },
            )
        )
        return result

    def _stage1_injection_filter(
        self,
        summary: str,
        citations: list[dict[str, Any]],
    ) -> tuple[str, str] | None:
        """Scan summary and citation fields for injection patterns.

        Returns:
            ``(reason, pattern_matched)`` tuple on a match, ``None`` if clean.
        """
        # Scan the summary
        matches = scan_for_suspicious_content(summary)
        if matches:
            category, matched_text = matches[0]
            return (
                f"suspicious pattern [{category}] in summary",
                matched_text,
            )

        # Scan citation title and author fields
        for i, citation in enumerate(citations):
            for field_name in ("title", "author"):
                field_value = citation.get(field_name)
                if not field_value:
                    continue
                matches = scan_for_suspicious_content(str(field_value))
                if matches:
                    category, matched_text = matches[0]
                    return (
                        f"suspicious pattern [{category}] in citation[{i}].{field_name}",
                        matched_text,
                    )

        return None

    def _stage2_schema_enforcement(
        self,
        summary: str,
        raw_citations: list[dict[str, Any]],
        request: ResearchRequest,
        trace_id: str,
    ) -> ResearchResult | str:
        """Construct ResearchResult via Pydantic; return error reason string on failure.

        Returns:
            A validated ``ResearchResult`` on success, or a ``str`` error
            reason on any validation failure.
        """
        # Citation count guard (checked before Pydantic to produce a clear reason)
        if len(raw_citations) > request.max_results:
            return f"citation count {len(raw_citations)} exceeds max_results {request.max_results}"

        # Build CitationRecord objects
        citation_objects: list[CitationRecord] = []
        for i, raw in enumerate(raw_citations):
            try:
                citation_objects.append(CitationRecord(**raw))
            except (ValidationError, Exception) as exc:
                return f"citation[{i}] failed validation: {exc}"

        # Build the full ResearchResult
        try:
            result = ResearchResult(
                query_echo=request.query,
                summary=summary,
                citations=citation_objects,
                source_types_searched=request.source_types,
                result_count=len(citation_objects),
                search_timestamp=datetime.now(timezone.utc),
                trace_id=trace_id,
            )
        except (ValidationError, Exception) as exc:
            return f"ResearchResult validation failed: {exc}"

        return result
