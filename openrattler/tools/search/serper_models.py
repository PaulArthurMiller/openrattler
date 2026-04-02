"""
Pydantic models for Serper API responses.

All models represent UNTRUSTED external data. They are constructed only
after the sanitizer has scanned the raw JSON. They must not be passed
to the LLM directly — the ResearchAgent maps them to CitationRecord /
ResearchResult objects which are the sanitized internal representation.

Security note: 'domain' fields are always derived from 'link' (the URL)
by the system. No domain field from the Serper payload is trusted — an
attacker-controlled page can put anything in its metadata.
"""

from __future__ import annotations

from typing import Any, Optional
from urllib.parse import urlparse

from pydantic import BaseModel, Field, model_validator

# ---------------------------------------------------------------------------
# Shared primitive models
# ---------------------------------------------------------------------------


class SerperSearchParameters(BaseModel):
    """Echo of the query parameters Serper received."""

    q: Optional[str] = None
    gl: Optional[str] = None  # Country code
    hl: Optional[str] = None  # Language code
    num: Optional[int] = None  # Results requested
    type: Optional[str] = None  # Endpoint type
    engine: Optional[str] = None


class SerperSitelink(BaseModel):
    """A sitelink beneath an organic result."""

    title: Optional[str] = Field(None, max_length=300)
    link: Optional[str] = None
    snippet: Optional[str] = Field(None, max_length=500)


class SerperOrganicResult(BaseModel):
    """A single organic search result."""

    title: Optional[str] = Field(None, max_length=500)
    link: Optional[str] = None
    snippet: Optional[str] = Field(None, max_length=1000)
    date: Optional[str] = None
    position: Optional[int] = None
    rating: Optional[float] = None
    ratingCount: Optional[int] = None
    priceRange: Optional[str] = Field(None, max_length=100)
    sitelinks: list[SerperSitelink] = Field(default_factory=list)
    attributes: Optional[dict[str, str]] = None
    publicationInfo: Optional[str] = Field(None, max_length=300)
    citedBy: Optional[int] = None
    year: Optional[int] = None
    patentId: Optional[str] = Field(None, max_length=100)
    assignee: Optional[str] = Field(None, max_length=300)
    inventor: Optional[str] = Field(None, max_length=300)
    thumbnail: Optional[str] = None

    # System-derived — never accepted from payload
    domain: Optional[str] = None

    @model_validator(mode="after")
    def derive_domain(self) -> "SerperOrganicResult":
        """Derive domain from link; never trust a domain from the payload."""
        if self.link:
            try:
                self.domain = urlparse(self.link).netloc.lower()
            except Exception:
                self.domain = None
        return self


class SerperAnswerBox(BaseModel):
    """Featured answer box (direct answer to query)."""

    answer: Optional[str] = Field(None, max_length=2000)
    snippet: Optional[str] = Field(None, max_length=2000)
    snippetHighlighted: Optional[list[str]] = None
    title: Optional[str] = Field(None, max_length=500)
    link: Optional[str] = None
    date: Optional[str] = None


class SerperKnowledgeGraph(BaseModel):
    """Knowledge graph panel."""

    title: Optional[str] = Field(None, max_length=300)
    type: Optional[str] = Field(None, max_length=200)
    website: Optional[str] = None
    imageUrl: Optional[str] = None
    description: Optional[str] = Field(None, max_length=2000)
    descriptionSource: Optional[str] = Field(None, max_length=200)
    descriptionLink: Optional[str] = None
    attributes: Optional[dict[str, str]] = None


class SerperPeopleAlsoAsk(BaseModel):
    """A 'People Also Ask' question-answer pair."""

    question: Optional[str] = Field(None, max_length=500)
    snippet: Optional[str] = Field(None, max_length=1000)
    title: Optional[str] = Field(None, max_length=500)
    link: Optional[str] = None


class SerperRelatedSearch(BaseModel):
    """A related search suggestion."""

    query: Optional[str] = Field(None, max_length=300)


class SerperTopStory(BaseModel):
    """A top story in a news-style result block."""

    title: Optional[str] = Field(None, max_length=500)
    link: Optional[str] = None
    source: Optional[str] = Field(None, max_length=200)
    date: Optional[str] = None
    imageUrl: Optional[str] = None


# ---------------------------------------------------------------------------
# Endpoint-specific result item models
# ---------------------------------------------------------------------------


class SerperImageResult(BaseModel):
    """A single image result."""

    title: Optional[str] = Field(None, max_length=500)
    imageUrl: Optional[str] = None
    imageWidth: Optional[int] = None
    imageHeight: Optional[int] = None
    thumbnailUrl: Optional[str] = None
    thumbnailWidth: Optional[int] = None
    thumbnailHeight: Optional[int] = None
    source: Optional[str] = Field(None, max_length=300)
    link: Optional[str] = None
    googleUrl: Optional[str] = None
    position: Optional[int] = None

    # System-derived
    domain: Optional[str] = None

    @model_validator(mode="after")
    def derive_domain(self) -> "SerperImageResult":
        if self.link:
            try:
                self.domain = urlparse(self.link).netloc.lower()
            except Exception:
                self.domain = None
        return self


class SerperNewsResult(BaseModel):
    """A single news result."""

    title: Optional[str] = Field(None, max_length=500)
    link: Optional[str] = None
    snippet: Optional[str] = Field(None, max_length=1000)
    date: Optional[str] = None
    source: Optional[str] = Field(None, max_length=200)
    imageUrl: Optional[str] = None
    position: Optional[int] = None

    # System-derived
    domain: Optional[str] = None

    @model_validator(mode="after")
    def derive_domain(self) -> "SerperNewsResult":
        if self.link:
            try:
                self.domain = urlparse(self.link).netloc.lower()
            except Exception:
                self.domain = None
        return self


class SerperVideoResult(BaseModel):
    """A single video result."""

    title: Optional[str] = Field(None, max_length=500)
    link: Optional[str] = None
    snippet: Optional[str] = Field(None, max_length=500)
    date: Optional[str] = None
    channel: Optional[str] = Field(None, max_length=200)
    duration: Optional[str] = None
    imageUrl: Optional[str] = None
    position: Optional[int] = None


class SerperPlaceResult(BaseModel):
    """A single place / maps result."""

    position: Optional[int] = None
    title: Optional[str] = Field(None, max_length=300)
    address: Optional[str] = Field(None, max_length=500)
    latitude: Optional[float] = None
    longitude: Optional[float] = None
    rating: Optional[float] = None
    ratingCount: Optional[int] = None
    category: Optional[str] = Field(None, max_length=200)
    phoneNumber: Optional[str] = Field(None, max_length=50)
    website: Optional[str] = None
    cid: Optional[str] = None
    description: Optional[str] = Field(None, max_length=1000)
    openingHours: Optional[list[str]] = None
    thumbnailUrl: Optional[str] = None
    priceLevel: Optional[str] = None


class SerperShoppingResult(BaseModel):
    """A single shopping result."""

    title: Optional[str] = Field(None, max_length=500)
    source: Optional[str] = Field(None, max_length=200)
    link: Optional[str] = None
    price: Optional[str] = Field(None, max_length=100)
    imageUrl: Optional[str] = None
    delivery: Optional[str] = Field(None, max_length=200)
    rating: Optional[float] = None
    ratingCount: Optional[int] = None
    position: Optional[int] = None

    # System-derived
    domain: Optional[str] = None

    @model_validator(mode="after")
    def derive_domain(self) -> "SerperShoppingResult":
        if self.link:
            try:
                self.domain = urlparse(self.link).netloc.lower()
            except Exception:
                self.domain = None
        return self


class SerperAutocompleteResult(BaseModel):
    """A single autocomplete suggestion."""

    value: Optional[str] = Field(None, max_length=300)


class SerperLensVisualMatch(BaseModel):
    """A single visual match result from Google Lens."""

    position: Optional[int] = None
    title: Optional[str] = Field(None, max_length=500)
    link: Optional[str] = None
    source: Optional[str] = Field(None, max_length=200)
    thumbnail: Optional[str] = None
    thumbnailWidth: Optional[int] = None
    thumbnailHeight: Optional[int] = None
    image: Optional[str] = None
    imageWidth: Optional[int] = None
    imageHeight: Optional[int] = None
    rating: Optional[float] = None
    reviews: Optional[int] = None
    price: Optional[dict[str, Any]] = None  # value, currency, extracted_value
    inStock: Optional[bool] = None
    condition: Optional[str] = Field(None, max_length=100)

    # System-derived
    domain: Optional[str] = None

    @model_validator(mode="after")
    def derive_domain(self) -> "SerperLensVisualMatch":
        if self.link:
            try:
                self.domain = urlparse(self.link).netloc.lower()
            except Exception:
                self.domain = None
        return self


class SerperLensTextFragment(BaseModel):
    """A fragment of text detected in the submitted image (OCR)."""

    text: Optional[str] = Field(None, max_length=1000)


# ---------------------------------------------------------------------------
# Credit tracking model
# ---------------------------------------------------------------------------


class SerperCredits(BaseModel):
    """
    Credit usage information parsed from Serper response headers.

    This data is the foundation for the heartbeat credit-warning feature.
    All fields are Optional because header parsing can fail gracefully.
    """

    credits_used: Optional[int] = None  # Credits consumed by this request
    credits_remaining: Optional[int] = None  # Credits remaining in account
    plan_limit: Optional[int] = None  # Total credits in current pack


# ---------------------------------------------------------------------------
# Top-level response model — one per endpoint
# ---------------------------------------------------------------------------


class SerperResponse(BaseModel):
    """
    Unified response wrapper for all Serper endpoints.

    Only the fields relevant to the called endpoint will be populated.
    All other fields will be None or empty lists.

    Security note: This model is only constructed AFTER the raw JSON has
    been scanned by the SerperSanitizer. It must never be constructed
    from raw API output directly.
    """

    # Echo of request parameters
    searchParameters: Optional[SerperSearchParameters] = None

    # Web search fields
    answerBox: Optional[SerperAnswerBox] = None
    knowledgeGraph: Optional[SerperKnowledgeGraph] = None
    organic: list[SerperOrganicResult] = Field(default_factory=list)
    peopleAlsoAsk: list[SerperPeopleAlsoAsk] = Field(default_factory=list)
    relatedSearches: list[SerperRelatedSearch] = Field(default_factory=list)
    topStories: list[SerperTopStory] = Field(default_factory=list)

    # Endpoint-specific result lists
    images: list[SerperImageResult] = Field(default_factory=list)
    news: list[SerperNewsResult] = Field(default_factory=list)
    videos: list[SerperVideoResult] = Field(default_factory=list)
    places: list[SerperPlaceResult] = Field(default_factory=list)
    shopping: list[SerperShoppingResult] = Field(default_factory=list)
    # Scholar and patents reuse 'organic' field with typed entries
    # (Serper returns them under 'organic' key for these endpoints)
    suggestions: list[SerperAutocompleteResult] = Field(default_factory=list)

    # Lens-specific fields
    visualMatches: list[SerperLensVisualMatch] = Field(default_factory=list)
    textInImage: list[SerperLensTextFragment] = Field(default_factory=list)
    # imageUrl echoed back by Serper for Lens requests — set by client, not payload
    submittedImageUrl: Optional[str] = None

    # Credit tracking — populated from response headers, not body
    credits: Optional[SerperCredits] = None

    # Endpoint that produced this response (set by client, not payload)
    endpoint: Optional[str] = None
