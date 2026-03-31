"""Tests for openrattler.agents.research.models."""

from __future__ import annotations

from datetime import date, datetime, timezone

import pytest
from pydantic import ValidationError

from openrattler.agents.research.models import (
    CitationRecord,
    OutputFormat,
    ResearchError,
    ResearchRequest,
    ResearchResult,
    SourceType,
)

# ---------------------------------------------------------------------------
# ResearchRequest validation
# ---------------------------------------------------------------------------


class TestResearchRequest:
    """ResearchRequest field validation."""

    def test_valid_minimal_request(self) -> None:
        req = ResearchRequest(query="What is Python?")
        print(f"[TestResearchRequest] valid minimal: query={req.query!r}")
        assert req.query == "What is Python?"
        assert req.max_results == 5
        assert req.source_types == [SourceType.GENERAL]
        assert req.output_format == OutputFormat.SUMMARY_WITH_CITATIONS

    def test_rejects_query_over_300_chars(self) -> None:
        long_query = "a" * 301
        print(f"[TestResearchRequest] reject query > 300 chars (len={len(long_query)})")
        with pytest.raises(ValidationError) as exc_info:
            ResearchRequest(query=long_query)
        assert "300" in str(exc_info.value)

    def test_accepts_query_exactly_300_chars(self) -> None:
        query = "b" * 300
        req = ResearchRequest(query=query)
        print(f"[TestResearchRequest] accept query exactly 300 chars")
        assert len(req.query) == 300

    def test_rejects_focus_terms_over_10_items(self) -> None:
        terms = [(f"term{i}", 0.5) for i in range(11)]
        print(f"[TestResearchRequest] reject focus_terms with {len(terms)} items")
        with pytest.raises(ValidationError) as exc_info:
            ResearchRequest(query="test", focus_terms=terms)
        assert "10" in str(exc_info.value)

    def test_accepts_focus_terms_exactly_10_items(self) -> None:
        terms = [(f"term{i}", 0.5) for i in range(10)]
        req = ResearchRequest(query="test", focus_terms=terms)
        print(f"[TestResearchRequest] accept focus_terms exactly 10 items")
        assert len(req.focus_terms) == 10

    def test_rejects_weight_outside_range(self) -> None:
        print("[TestResearchRequest] reject weight > 1.0")
        with pytest.raises(ValidationError) as exc_info:
            ResearchRequest(query="test", focus_terms=[("term", 1.1)])
        assert "1.0" in str(exc_info.value) or "weight" in str(exc_info.value).lower()

    def test_rejects_negative_weight(self) -> None:
        print("[TestResearchRequest] reject weight < 0.0")
        with pytest.raises(ValidationError) as exc_info:
            ResearchRequest(query="test", focus_terms=[("term", -0.1)])
        assert "0.0" in str(exc_info.value) or "weight" in str(exc_info.value).lower()

    def test_rejects_focus_term_over_60_chars(self) -> None:
        long_term = "t" * 61
        print(f"[TestResearchRequest] reject focus term > 60 chars (len={len(long_term)})")
        with pytest.raises(ValidationError) as exc_info:
            ResearchRequest(query="test", focus_terms=[(long_term, 0.5)])
        assert "60" in str(exc_info.value)

    def test_rejects_invalid_domain_in_exclude_domains(self) -> None:
        print("[TestResearchRequest] reject invalid domain in exclude_domains")
        with pytest.raises(ValidationError) as exc_info:
            ResearchRequest(query="test", exclude_domains=["not-a-domain"])
        assert "domain" in str(exc_info.value).lower()

    def test_rejects_exclude_domains_with_scheme(self) -> None:
        print("[TestResearchRequest] reject domain with scheme prefix")
        with pytest.raises(ValidationError) as exc_info:
            ResearchRequest(query="test", exclude_domains=["https://example.com"])
        assert "domain" in str(exc_info.value).lower()

    def test_accepts_valid_exclude_domains(self) -> None:
        req = ResearchRequest(
            query="test",
            exclude_domains=["example.com", "sub.example.org"],
        )
        print("[TestResearchRequest] accept valid exclude_domains")
        assert len(req.exclude_domains) == 2

    def test_rejects_exclude_domains_over_20_items(self) -> None:
        domains = [f"example{i}.com" for i in range(21)]
        print(f"[TestResearchRequest] reject exclude_domains with {len(domains)} items")
        with pytest.raises(ValidationError) as exc_info:
            ResearchRequest(query="test", exclude_domains=domains)
        assert "20" in str(exc_info.value)

    def test_rejects_max_results_outside_1_to_10(self) -> None:
        print("[TestResearchRequest] reject max_results=0")
        with pytest.raises(ValidationError):
            ResearchRequest(query="test", max_results=0)
        print("[TestResearchRequest] reject max_results=11")
        with pytest.raises(ValidationError):
            ResearchRequest(query="test", max_results=11)


# ---------------------------------------------------------------------------
# CitationRecord validation
# ---------------------------------------------------------------------------


class TestCitationRecord:
    """CitationRecord field validation."""

    def _make_citation(self, **overrides: object) -> CitationRecord:
        defaults: dict[str, object] = {
            "title": "Test Article",
            "url": "https://example.com/article",
            "domain": "ignored",  # always overwritten by validator
            "source_type": SourceType.GENERAL,
            "retrieval_timestamp": datetime.now(timezone.utc),
        }
        defaults.update(overrides)
        return CitationRecord(**defaults)  # type: ignore[arg-type]

    def test_rejects_non_http_url(self) -> None:
        print("[TestCitationRecord] reject ftp:// URL")
        with pytest.raises(ValidationError) as exc_info:
            self._make_citation(url="ftp://example.com/file")
        assert "http" in str(exc_info.value).lower() or "scheme" in str(exc_info.value).lower()

    def test_rejects_file_url(self) -> None:
        print("[TestCitationRecord] reject file:// URL")
        with pytest.raises(ValidationError):
            self._make_citation(url="file:///etc/passwd")

    def test_domain_derived_from_url_ignores_passed_value(self) -> None:
        # Whatever we pass as domain should be overwritten
        citation = self._make_citation(
            url="https://real-domain.com/page",
            domain="fake-domain.com",
        )
        print(
            f"[TestCitationRecord] domain derived from URL: "
            f"passed='fake-domain.com', got={citation.domain!r}"
        )
        assert citation.domain == "real-domain.com"

    def test_domain_extracted_correctly_from_url(self) -> None:
        citation = self._make_citation(url="https://news.example.org/story/123")
        print(f"[TestCitationRecord] domain extracted: {citation.domain!r}")
        assert citation.domain == "news.example.org"

    def test_domain_extracted_from_http_url(self) -> None:
        citation = self._make_citation(url="http://blog.test.io/post")
        print(f"[TestCitationRecord] http URL domain: {citation.domain!r}")
        assert citation.domain == "blog.test.io"

    def test_rejects_title_over_300_chars(self) -> None:
        long_title = "T" * 301
        print(f"[TestCitationRecord] reject title > 300 chars (len={len(long_title)})")
        with pytest.raises(ValidationError) as exc_info:
            self._make_citation(title=long_title)
        assert "300" in str(exc_info.value)

    def test_accepts_title_exactly_300_chars(self) -> None:
        title = "T" * 300
        citation = self._make_citation(title=title)
        print("[TestCitationRecord] accept title exactly 300 chars")
        assert len(citation.title) == 300

    def test_rejects_author_over_150_chars(self) -> None:
        long_author = "A" * 151
        print(f"[TestCitationRecord] reject author > 150 chars (len={len(long_author)})")
        with pytest.raises(ValidationError) as exc_info:
            self._make_citation(author=long_author)
        assert "150" in str(exc_info.value)

    def test_accepts_none_author(self) -> None:
        citation = self._make_citation(author=None)
        print("[TestCitationRecord] accept None author")
        assert citation.author is None

    def test_valid_citation_record(self) -> None:
        citation = self._make_citation(
            title="Research Paper",
            url="https://arxiv.org/abs/1234.5678",
            author="Jane Doe",
            source_type=SourceType.ACADEMIC,
            published_date=date(2024, 1, 15),
        )
        print(f"[TestCitationRecord] valid citation: domain={citation.domain!r}")
        assert citation.domain == "arxiv.org"
        assert citation.author == "Jane Doe"


# ---------------------------------------------------------------------------
# ResearchResult validation
# ---------------------------------------------------------------------------


class TestResearchResult:
    """ResearchResult field validation."""

    def _make_result(self, **overrides: object) -> ResearchResult:
        defaults: dict[str, object] = {
            "query_echo": "test query",
            "summary": "A short summary.",
            "citations": [],
            "source_types_searched": [SourceType.GENERAL],
            "result_count": 0,
            "search_timestamp": datetime.now(timezone.utc),
            "trace_id": "trace-abc-123",
        }
        defaults.update(overrides)
        return ResearchResult(**defaults)  # type: ignore[arg-type]

    def test_rejects_summary_over_2000_chars(self) -> None:
        long_summary = "s" * 2001
        print(f"[TestResearchResult] reject summary > 2000 chars (len={len(long_summary)})")
        with pytest.raises(ValidationError) as exc_info:
            self._make_result(summary=long_summary)
        assert "2000" in str(exc_info.value)

    def test_accepts_summary_exactly_2000_chars(self) -> None:
        summary = "s" * 2000
        result = self._make_result(summary=summary)
        print("[TestResearchResult] accept summary exactly 2000 chars")
        assert len(result.summary) == 2000

    def test_rejects_warnings_item_over_200_chars(self) -> None:
        long_warning = "w" * 201
        print(f"[TestResearchResult] reject warning > 200 chars (len={len(long_warning)})")
        with pytest.raises(ValidationError) as exc_info:
            self._make_result(warnings=[long_warning])
        assert "200" in str(exc_info.value)

    def test_rejects_over_5_warnings(self) -> None:
        warnings = ["warn"] * 6
        print(f"[TestResearchResult] reject {len(warnings)} warnings")
        with pytest.raises(ValidationError) as exc_info:
            self._make_result(warnings=warnings)
        assert "5" in str(exc_info.value)

    def test_accepts_exactly_5_warnings(self) -> None:
        warnings = ["warn"] * 5
        result = self._make_result(warnings=warnings)
        print("[TestResearchResult] accept exactly 5 warnings")
        assert len(result.warnings) == 5

    def test_valid_result_with_no_warnings(self) -> None:
        result = self._make_result()
        print(f"[TestResearchResult] valid result: trace_id={result.trace_id!r}")
        assert result.trace_id == "trace-abc-123"
        assert result.warnings == []


# ---------------------------------------------------------------------------
# ResearchError validation
# ---------------------------------------------------------------------------


class TestResearchError:
    """ResearchError field validation."""

    def test_rejects_message_over_200_chars(self) -> None:
        long_msg = "e" * 201
        print(f"[TestResearchError] reject message > 200 chars (len={len(long_msg)})")
        with pytest.raises(ValidationError) as exc_info:
            ResearchError(
                error_code="SANITIZATION_FAILED",
                message=long_msg,
                query_echo="test",
                trace_id="trace-xyz",
            )
        assert "200" in str(exc_info.value)

    def test_accepts_message_exactly_200_chars(self) -> None:
        msg = "e" * 200
        error = ResearchError(
            error_code="NO_RESULTS",
            message=msg,
            query_echo="test",
            trace_id="trace-xyz",
        )
        print("[TestResearchError] accept message exactly 200 chars")
        assert len(error.message) == 200

    def test_valid_error_model(self) -> None:
        error = ResearchError(
            error_code="TIMEOUT",
            message="Request timed out",
            query_echo="test query",
            trace_id="trace-001",
        )
        print(f"[TestResearchError] valid error: code={error.error_code!r}")
        assert error.error_code == "TIMEOUT"
        assert error.trace_id == "trace-001"
