"""Pydantic v2 models for the SummarizerAgent subsystem.

All data entering and leaving the SummarizerAgent is typed and validated here.

SECURITY NOTES
--------------
- ``SummarizerRequest.text`` is the untrusted surface; ``max_input_chars``
  in the config caps how much of it reaches the LLM.
- ``SummarizerResult.summary`` carries LLM output after security scanning;
  callers should treat it as untrusted and apply their own display-layer
  escaping if rendering in a web context.
- ``SummarizerError`` must never contain raw external content — only
  agent-generated descriptions.
"""

from __future__ import annotations

from typing import Optional

from pydantic import BaseModel, Field


class SummarizerRequest(BaseModel):
    """Structured request parsed from UniversalMessage params.

    Args:
        text:    The text to summarize.  Truncated at ``max_input_chars``
                 before reaching the LLM.
        skill:   Optional named skill.  When set and a matching
                 ``SKILL_{skill}.md`` exists in ``named_skills_dir``, that
                 prompt is used instead of the default.
        context: Optional extra context appended to the user turn of the
                 LLM prompt (e.g. session metadata, caller intent).
    """

    text: str = Field(description="Text to summarize")
    skill: Optional[str] = Field(
        default=None,
        description="Named skill selector; resolves SKILL_{skill}.md when available",
    )
    context: Optional[str] = Field(
        default=None,
        description="Extra context appended to the LLM user turn",
    )


class SummarizerResult(BaseModel):
    """Successful summarization result returned via UniversalMessage.

    Args:
        summary:         The generated summary, capped at ``max_output_chars``.
        original_length: Character count of the original text before truncation.
        skill_used:      Name of the skill prompt file actually used (path stem).
        was_truncated:   True if the input was truncated before the LLM call.
    """

    summary: str = Field(description="Generated summary text")
    original_length: int = Field(description="Character count of original text")
    skill_used: str = Field(description="Skill prompt stem used for this request")
    was_truncated: bool = Field(description="True if input was truncated before LLM call")


class SummarizerError(BaseModel):
    """Structured error returned when summarization fails or is blocked.

    Returned as the params block of a UM ``type='error'`` message.

    Security note: ``message`` must never contain raw external content —
    only agent-generated or pipeline-generated descriptions.
    """

    error_code: str = Field(description="One of: INVALID_REQUEST | OUTPUT_FLAGGED | INTERNAL_ERROR")
    message: str = Field(description="Human-readable error description")
    trace_id: str = Field(description="Trace ID from the originating UM")
