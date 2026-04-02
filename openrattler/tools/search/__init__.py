"""Serper-backed search tools for OpenRattler."""

from openrattler.tools.search.serper_config import (
    SerperConfig,
    ALL_SERPER_ENDPOINTS,
    DEFAULT_ENABLED_ENDPOINTS,
    get_api_key,
)
from openrattler.tools.search.serper_models import (
    SerperResponse,
    SerperCredits,
    SerperLensVisualMatch,
    SerperLensTextFragment,
)
from openrattler.tools.search.serper_client import SerperClient, SerperClientError
from openrattler.tools.search.serper_sanitizer import (
    SerperSanitizationError,
    sanitize_serper_response,
)
from openrattler.tools.search.web_search_tool import (
    web_search,
    WebSearchParams,
    web_lens,
    WebLensParams,
)

__all__ = [
    "SerperConfig",
    "ALL_SERPER_ENDPOINTS",
    "DEFAULT_ENABLED_ENDPOINTS",
    "get_api_key",
    "SerperResponse",
    "SerperCredits",
    "SerperLensVisualMatch",
    "SerperLensTextFragment",
    "SerperClient",
    "SerperClientError",
    "SerperSanitizationError",
    "sanitize_serper_response",
    "web_search",
    "WebSearchParams",
    "web_lens",
    "WebLensParams",
]
