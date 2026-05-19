"""SummarizerAgent — standalone text summarization subagent.

Zero dependencies on session tools or TranscriptStore; designed to be
wired in as a helper by session_read_self and session_lookup (Build 42.3).
"""

from openrattler.agents.summarizer.agent import SummarizerAgent
from openrattler.agents.summarizer.config import SummarizerAgentConfig
from openrattler.agents.summarizer.models import (
    SummarizerError,
    SummarizerRequest,
    SummarizerResult,
)

__all__ = [
    "SummarizerAgent",
    "SummarizerAgentConfig",
    "SummarizerRequest",
    "SummarizerResult",
    "SummarizerError",
]
