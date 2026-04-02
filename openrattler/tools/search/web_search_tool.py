"""
web_search and web_lens tool implementations backed by the Serper API.

These are the functions the ResearchAgent's pipeline calls to search the web.
They are responsible for:
  1. Validating tool call parameters (Pydantic)
  2. Invoking SerperClient (which enforces endpoint allowlist + sanitization)
  3. Mapping sanitized SerperResponse models to the internal citation format
  4. Returning a structured result the pipeline can reason about

The ResearchAgent NEVER sees raw Serper output. By the time data reaches
here from SerperClient, it has passed the Window 1 sanitizer. The structured
dict returned by these functions then enters the ResearchAgent's context,
where it will be processed before passing to the output sanitizer (Window 2).

Security note: Any SerperClientError, SerperSanitizationError, or other
exception from the client layer is caught and returned as a structured
error dict. Exceptions never propagate to the ResearchAgent raw.
"""

from __future__ import annotations

import logging
import uuid
from typing import Any, Optional
from urllib.parse import urlparse

from pydantic import BaseModel, Field, field_validator

from openrattler.tools.search.serper_client import (
    SerperClient,
    SerperClientError,
    SerperEndpointNotAllowedError,
)
from openrattler.tools.search.serper_config import SerperConfig, ALL_SERPER_ENDPOINTS
from openrattler.tools.search.serper_models import SerperResponse
from openrattler.tools.search.serper_sanitizer import SerperSanitizationError

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Tool parameter model (what the ResearchAgent pipeline sends to web_search)
# ---------------------------------------------------------------------------


class WebSearchParams(BaseModel):
    """
    Parameters for the web_search tool call.

    These are the fields the pipeline can supply. Validation is strict —
    the pipeline cannot specify an endpoint not in the known set, and it
    cannot request more results than the per-call cap allows.
    """

    query: str = Field(..., min_length=1, max_length=500)
    endpoint: str = Field(
        default="search",
        description=(
            "Serper endpoint to use. One of: search, images, news, videos, "
            "places, maps, shopping, scholar, patents, autocomplete."
        ),
    )
    num: Optional[int] = Field(
        default=None,
        ge=1,
        le=20,
        description="Number of results to request. Capped by server config.",
    )
    gl: Optional[str] = Field(
        default=None,
        max_length=2,
        description="Country code for results (ISO 3166-1 alpha-2, e.g. 'us').",
    )
    hl: Optional[str] = Field(
        default=None,
        max_length=10,
        description="Language for results (BCP 47, e.g. 'en').",
    )
    location: Optional[str] = Field(
        default=None,
        max_length=200,
        description="Location string for localised results (e.g. 'Austin, Texas').",
    )
    tbs: Optional[str] = Field(
        default=None,
        max_length=100,
        description=(
            "Time-based search filter. Examples: 'qdr:h' (past hour), "
            "'qdr:d' (past day), 'qdr:w' (past week), 'qdr:m' (past month)."
        ),
    )
    page: Optional[int] = Field(
        default=None,
        ge=1,
        le=10,
        description="Results page number (1-based).",
    )
    autocorrect: Optional[bool] = Field(
        default=None,
        description="Whether Serper should autocorrect the query.",
    )

    @field_validator("endpoint")
    @classmethod
    def endpoint_must_be_known(cls, v: str) -> str:
        if v not in ALL_SERPER_ENDPOINTS:
            raise ValueError(
                f"Unknown endpoint '{v}'. " f"Valid endpoints: {sorted(ALL_SERPER_ENDPOINTS)}"
            )
        return v


# ---------------------------------------------------------------------------
# Result structure returned to the pipeline
# ---------------------------------------------------------------------------


def _map_response_to_tool_result(
    response: SerperResponse,
    endpoint: str,
    credits_remaining: Optional[int],
) -> dict[str, Any]:
    """
    Map a sanitized SerperResponse to a structured dict the pipeline can consume.

    Only includes fields relevant to the endpoint. Domain is always
    system-derived (from URL), never from the payload.
    """
    result: dict[str, Any] = {
        "endpoint": endpoint,
        "credits_remaining": credits_remaining,
        "results": [],
        "answer_box": None,
        "knowledge_graph": None,
        "people_also_ask": [],
        "related_searches": [],
    }

    # Answer box (web search)
    if response.answerBox:
        ab = response.answerBox
        result["answer_box"] = {
            "title": ab.title,
            "answer": ab.answer,
            "snippet": ab.snippet,
            "link": ab.link,
        }

    # Knowledge graph (web search)
    if response.knowledgeGraph:
        kg = response.knowledgeGraph
        result["knowledge_graph"] = {
            "title": kg.title,
            "type": kg.type,
            "description": kg.description,
            "website": kg.website,
            "attributes": kg.attributes,
        }

    # People Also Ask
    result["people_also_ask"] = [
        {"question": p.question, "snippet": p.snippet, "link": p.link}
        for p in response.peopleAlsoAsk
    ]

    # Related searches
    result["related_searches"] = [r.query for r in response.relatedSearches]

    # Endpoint-specific results
    if endpoint == "search":
        result["results"] = [
            {
                "position": r.position,
                "title": r.title,
                "url": r.link,
                "domain": r.domain,  # system-derived
                "snippet": r.snippet,
                "date": r.date,
                "sitelinks": [{"title": s.title, "url": s.link} for s in r.sitelinks],
            }
            for r in response.organic
        ]

    elif endpoint == "images":
        result["results"] = [
            {
                "position": r.position,
                "title": r.title,
                "url": r.link,
                "domain": r.domain,  # system-derived
                "image_url": r.imageUrl,
                "width": r.imageWidth,
                "height": r.imageHeight,
                "source": r.source,
            }
            for r in response.images
        ]

    elif endpoint == "news":
        result["results"] = [
            {
                "position": r.position,
                "title": r.title,
                "url": r.link,
                "domain": r.domain,  # system-derived
                "snippet": r.snippet,
                "source": r.source,
                "date": r.date,
            }
            for r in response.news
        ]

    elif endpoint == "videos":
        result["results"] = [
            {
                "position": r.position,
                "title": r.title,
                "url": r.link,
                "snippet": r.snippet,
                "channel": r.channel,
                "duration": r.duration,
                "date": r.date,
            }
            for r in response.videos
        ]

    elif endpoint in ("places", "maps"):
        result["results"] = [
            {
                "position": r.position,
                "title": r.title,
                "address": r.address,
                "latitude": r.latitude,
                "longitude": r.longitude,
                "rating": r.rating,
                "rating_count": r.ratingCount,
                "category": r.category,
                "phone": r.phoneNumber,
                "website": r.website,
                "price_level": r.priceLevel,
                "opening_hours": r.openingHours,
            }
            for r in response.places
        ]

    elif endpoint == "shopping":
        result["results"] = [
            {
                "position": r.position,
                "title": r.title,
                "url": r.link,
                "domain": r.domain,  # system-derived
                "source": r.source,
                "price": r.price,
                "delivery": r.delivery,
                "rating": r.rating,
            }
            for r in response.shopping
        ]

    elif endpoint == "scholar":
        result["results"] = [
            {
                "position": r.position,
                "title": r.title,
                "url": r.link,
                "domain": r.domain,  # system-derived
                "snippet": r.snippet,
                "publication_info": r.publicationInfo,
                "cited_by": r.citedBy,
                "year": r.year,
            }
            for r in response.organic  # Scholar reuses 'organic' key
        ]

    elif endpoint == "patents":
        result["results"] = [
            {
                "position": r.position,
                "title": r.title,
                "url": r.link,
                "snippet": r.snippet,
                "patent_id": r.patentId,
                "assignee": r.assignee,
                "inventor": r.inventor,
                "date": r.date,
            }
            for r in response.organic  # Patents also reuse 'organic' key
        ]

    elif endpoint == "autocomplete":
        result["results"] = [s.value for s in response.suggestions]

    elif endpoint == "lens":
        result["results"] = [
            {
                "position": r.position,
                "title": r.title,
                "url": r.link,
                "domain": r.domain,  # system-derived
                "source": r.source,
                "thumbnail": r.thumbnail,
                "image": r.image,
                "rating": r.rating,
                "reviews": r.reviews,
                "price": r.price,
                "in_stock": r.inStock,
                "condition": r.condition,
            }
            for r in response.visualMatches
        ]
        result["text_in_image"] = [f.text for f in response.textInImage if f.text]
        result["submitted_image_url"] = response.submittedImageUrl

    return result


# ---------------------------------------------------------------------------
# web_search entry point
# ---------------------------------------------------------------------------


async def web_search(
    params: dict[str, Any],
    config: SerperConfig,
    trace_id: Optional[str] = None,
    audit_log_fn: Any = None,
) -> dict[str, Any]:
    """
    Execute a web search via Serper and return structured results.

    This function is called by ResearchAgent._web_search() to perform
    real web searches. It handles the full lifecycle: param validation,
    HTTP request, Window 1 sanitization, and result mapping.

    Args:
        params: Dict of search parameters (query, endpoint, num, etc.).
        config: SerperConfig (from AppConfig.search.serper or default).
        trace_id: Optional trace ID for audit correlation.
        audit_log_fn: Optional audit log callable.

    Returns:
        A structured dict with 'status', 'results', and metadata.
        Never raises — all errors are returned as structured error dicts.

    Security note: The pipeline never sees raw Serper output. All data in the
    returned dict has passed Window 1 sanitization.
    """
    if trace_id is None:
        trace_id = str(uuid.uuid4())

    # --- Validate tool call params ---
    try:
        validated = WebSearchParams.model_validate(params)
    except Exception as exc:
        logger.warning(
            "web_search: invalid params trace_id=%s error=%s",
            trace_id,
            type(exc).__name__,
        )
        return {
            "status": "error",
            "error": "invalid_params",
            "message": "Search parameters failed validation.",
            "trace_id": trace_id,
        }

    # --- Execute via client ---
    client = SerperClient(config)
    try:
        raw_dict, credits = await client.search(
            endpoint=validated.endpoint,
            query=validated.query,
            trace_id=trace_id,
            num=validated.num,
            gl=validated.gl,
            hl=validated.hl,
            location=validated.location,
            tbs=validated.tbs,
            page=validated.page,
            autocorrect=validated.autocorrect,
            audit_log_fn=audit_log_fn,
        )
    except SerperEndpointNotAllowedError:
        return {
            "status": "error",
            "error": "endpoint_not_allowed",
            "message": (
                f"The '{validated.endpoint}' endpoint is not enabled in "
                "the current configuration."
            ),
            "trace_id": trace_id,
        }
    except SerperSanitizationError:
        return {
            "status": "error",
            "error": "sanitization_failed",
            "message": "Search results were flagged by security scan and discarded.",
            "trace_id": trace_id,
        }
    except SerperClientError as exc:
        logger.warning(
            "web_search: client error trace_id=%s type=%s",
            trace_id,
            type(exc).__name__,
        )
        return {
            "status": "error",
            "error": "search_failed",
            "message": "Search request failed. Please try again.",
            "trace_id": trace_id,
        }

    # --- Construct Pydantic model from sanitized raw dict ---
    # Strip the body 'credits' key (an int — credits consumed) before model
    # construction. Our SerperResponse.credits field holds a SerperCredits
    # object parsed from response headers, set separately below.
    try:
        response = SerperResponse.model_validate({k: v for k, v in raw_dict.items() if k != "credits"})
        response.endpoint = validated.endpoint
        response.credits = credits
    except Exception as exc:
        logger.error(
            "web_search: model construction failed after sanitization trace_id=%s type=%s msg=%s",
            trace_id,
            type(exc).__name__,
            exc,
        )
        return {
            "status": "error",
            "error": "response_parse_failed",
            "message": "Search results could not be parsed.",
            "trace_id": trace_id,
        }

    # --- Map to tool result ---
    tool_result = _map_response_to_tool_result(
        response=response,
        endpoint=validated.endpoint,
        credits_remaining=credits.credits_remaining,
    )
    tool_result["status"] = "ok"
    tool_result["trace_id"] = trace_id
    tool_result["query"] = validated.query

    return tool_result


# ---------------------------------------------------------------------------
# WebLensParams and web_lens entry point
# ---------------------------------------------------------------------------


class WebLensParams(BaseModel):
    """
    Parameters for the web_lens tool call (Google Lens / reverse image search).

    Lens takes an image URL rather than a text query. The image must be
    publicly accessible — Serper fetches it server-side. Local files must
    be uploaded to a hosting service first (future build piece).

    Security note: imageUrl is validated to be HTTP/HTTPS only. The system
    never accepts data: URIs or file:// paths.
    """

    imageUrl: str = Field(
        ...,
        description=(
            "Publicly accessible URL of the image to search with Google Lens. "
            "Must be HTTP or HTTPS. The image must be reachable by Serper's servers."
        ),
    )
    gl: Optional[str] = Field(
        default=None,
        max_length=2,
        description="Country code for results (ISO 3166-1 alpha-2, e.g. 'us').",
    )
    hl: Optional[str] = Field(
        default=None,
        max_length=10,
        description="Language for results (BCP 47, e.g. 'en').",
    )

    @field_validator("imageUrl")
    @classmethod
    def url_must_be_http_or_https(cls, v: str) -> str:
        parsed = urlparse(v)
        if parsed.scheme not in ("http", "https"):
            raise ValueError(
                "imageUrl must use http or https scheme. " f"Got scheme: '{parsed.scheme}'"
            )
        if not parsed.netloc:
            raise ValueError("imageUrl must include a hostname.")
        return v


async def web_lens(
    params: dict[str, Any],
    config: SerperConfig,
    trace_id: Optional[str] = None,
    audit_log_fn: Any = None,
) -> dict[str, Any]:
    """
    Execute a Google Lens reverse image search via Serper.

    This is a separate function from web_search because Lens has a
    fundamentally different request shape: it takes an image URL instead
    of a text query.

    Security notes:
    - imageUrl is validated to HTTP/HTTPS before any network call.
    - The 'lens' endpoint must be in config.enabled_endpoints or the call
      is rejected before any network activity.
    - All Lens results pass Window 1 sanitization before reaching the pipeline.
    - The submitted imageUrl is echoed in the result for audit traceability
      but is never re-fetched or processed by this function.

    Args:
        params: Raw dict from the tool call arguments.
        config: SerperConfig (from AppConfig.search.serper).
        trace_id: Optional trace ID for audit correlation.
        audit_log_fn: Optional audit log callable.

    Returns:
        A structured dict with 'status', 'results', and metadata.
        Never raises — all errors are returned as structured error dicts.
    """
    if trace_id is None:
        trace_id = str(uuid.uuid4())

    # --- Validate params ---
    try:
        validated = WebLensParams.model_validate(params)
    except Exception as exc:
        logger.warning(
            "web_lens: invalid params trace_id=%s error=%s",
            trace_id,
            type(exc).__name__,
        )
        return {
            "status": "error",
            "error": "invalid_params",
            "message": "Lens parameters failed validation.",
            "trace_id": trace_id,
        }

    # --- Build Lens-specific payload (imageUrl instead of q) ---
    payload: dict[str, Any] = {"imageUrl": validated.imageUrl}
    if validated.gl is not None:
        payload["gl"] = validated.gl
    if validated.hl is not None:
        payload["hl"] = validated.hl

    # Lens endpoint uses the same client but a fixed endpoint name
    # and a custom payload — we call the client's _execute_request directly
    # via a thin wrapper that respects the allowlist.
    client = SerperClient(config)
    try:
        # Enforce allowlist — 'lens' must be in enabled_endpoints
        if "lens" not in config.enabled_endpoints:
            raise SerperEndpointNotAllowedError(
                "The 'lens' endpoint is not in the enabled endpoints list."
            )

        from openrattler.tools.search.serper_config import get_api_key

        url = f"https://google.serper.dev/lens"
        headers = {
            "X-API-KEY": get_api_key(),
            "Content-Type": "application/json",
        }
        raw_dict, credits = await client._execute_request(
            url=url,
            headers=headers,
            payload=payload,
            endpoint="lens",
            trace_id=trace_id,
            audit_log_fn=audit_log_fn,
        )
    except SerperEndpointNotAllowedError:
        return {
            "status": "error",
            "error": "endpoint_not_allowed",
            "message": "The 'lens' endpoint is not enabled in the current configuration.",
            "trace_id": trace_id,
        }
    except SerperSanitizationError:
        return {
            "status": "error",
            "error": "sanitization_failed",
            "message": "Lens results were flagged by security scan and discarded.",
            "trace_id": trace_id,
        }
    except SerperClientError as exc:
        logger.warning(
            "web_lens: client error trace_id=%s type=%s",
            trace_id,
            type(exc).__name__,
        )
        return {
            "status": "error",
            "error": "lens_failed",
            "message": "Lens request failed. Please try again.",
            "trace_id": trace_id,
        }

    # --- Construct model from sanitized dict ---
    # Strip body 'credits' key (int) — same collision as web_search above.
    try:
        response = SerperResponse.model_validate({k: v for k, v in raw_dict.items() if k != "credits"})
        response.endpoint = "lens"
        response.credits = credits
        response.submittedImageUrl = validated.imageUrl  # set by system, not payload
    except Exception as exc:
        logger.error(
            "web_lens: model construction failed trace_id=%s type=%s msg=%s",
            trace_id,
            type(exc).__name__,
            exc,
        )
        return {
            "status": "error",
            "error": "response_parse_failed",
            "message": "Lens results could not be parsed.",
            "trace_id": trace_id,
        }

    # --- Map to tool result ---
    tool_result = _map_response_to_tool_result(
        response=response,
        endpoint="lens",
        credits_remaining=credits.credits_remaining,
    )
    tool_result["status"] = "ok"
    tool_result["trace_id"] = trace_id
    tool_result["image_url"] = validated.imageUrl

    return tool_result
