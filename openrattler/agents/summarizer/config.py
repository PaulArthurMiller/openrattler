"""Configuration for SummarizerAgent.

SECURITY NOTES
--------------
- ``skill_prompt_path`` must point to an existing file at instantiation;
  missing file raises ``FileNotFoundError`` — silent degradation is not acceptable.
- ``named_skills_dir`` is optional; if set, the agent looks for ``SKILL_{name}.md``
  files there.  Unknown skill names fall back to the default prompt gracefully.
- ``max_input_chars`` limits the text that reaches the LLM, capping the
  injection surface area.
- ``max_output_chars`` caps the summary before it enters caller context.
"""

from __future__ import annotations

from pathlib import Path
from typing import Optional

from pydantic import BaseModel, Field

# ---------------------------------------------------------------------------
# Approved model allowlist
# ---------------------------------------------------------------------------

#: Models approved for SummarizerAgent use.  Adding a new model requires a
#: code change — no config override bypasses this check.
APPROVED_SUMMARIZER_MODELS: frozenset[str] = frozenset(
    {
        "claude-haiku-4-5-20251001",
        "claude-haiku-4-5",
        "claude-sonnet-4-6",
        "anthropic/claude-haiku-4-5-20251001",
        "anthropic/claude-haiku-4-5",
        "anthropic/claude-sonnet-4-6",
    }
)

# ---------------------------------------------------------------------------
# SummarizerAgentConfig
# ---------------------------------------------------------------------------

_DEFAULT_SKILL_PATH = Path(__file__).parent / "prompts" / "SKILL.md"


class SummarizerAgentConfig(BaseModel):
    """Pydantic config for a SummarizerAgent instance.

    Attributes:
        model:             LLM model for summarization.  Cheap model by default;
                           override for higher-quality summaries.
        skill_prompt_path: Path to the default SKILL.md.  Must exist at
                           instantiation; missing file raises FileNotFoundError.
        named_skills_dir:  Optional directory containing ``SKILL_{name}.md``
                           files.  When set, the agent resolves named skills
                           from this directory before falling back to the default.
        max_input_chars:   Maximum characters of text forwarded to the LLM.
                           Content beyond this limit is silently truncated;
                           ``was_truncated=True`` is set in the result.
        max_output_chars:  Maximum characters in the returned summary.  The
                           LLM output is sliced to this length before returning.

    Security notes:
    - ``max_input_chars`` is the primary injection-surface cap.  Do not raise
      without documented justification.
    - ``max_output_chars`` prevents unbounded output from reaching caller context.
    """

    model: str = Field(
        default="claude-haiku-4-5-20251001",
        description="LLM model for summarization",
    )
    skill_prompt_path: Path = Field(
        default_factory=lambda: _DEFAULT_SKILL_PATH,
        description="Path to the default SKILL.md; must exist at instantiation",
    )
    named_skills_dir: Optional[Path] = Field(
        default=None,
        description="Directory of SKILL_*.md named skills; None disables named-skill lookup",
    )
    max_input_chars: int = Field(
        default=100_000,
        description="Truncation limit for text before LLM call",
    )
    max_output_chars: int = Field(
        default=4_000,
        description="Maximum summary length returned to caller",
    )

    model_config = {"arbitrary_types_allowed": True}
