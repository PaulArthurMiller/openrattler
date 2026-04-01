"""Research agent subpackage.

Public exports for the research subsystem.  Import these from here rather
than from the individual sub-modules so internal refactoring never breaks
external callers.
"""

from openrattler.agents.research.agent import ResearchAgent
from openrattler.agents.research.config import APPROVED_RESEARCH_MODELS, ResearchAgentConfig
from openrattler.agents.research.models import (
    CitationRecord,
    OutputFormat,
    ResearchError,
    ResearchRequest,
    ResearchResult,
    SourceType,
)
from openrattler.agents.research.sanitizer import ResearchSanitizer

__all__ = [
    "APPROVED_RESEARCH_MODELS",
    "CitationRecord",
    "OutputFormat",
    "ResearchAgent",
    "ResearchAgentConfig",
    "ResearchError",
    "ResearchRequest",
    "ResearchResult",
    "ResearchSanitizer",
    "SourceType",
]
