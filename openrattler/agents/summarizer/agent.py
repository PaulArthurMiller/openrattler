"""SummarizerAgent — standalone text summarization subagent.

Accepts a UniversalMessage whose params contain a SummarizerRequest, calls
the LLM with a skill-selected system prompt, scans the output for suspicious
content, and returns a response UniversalMessage with a SummarizerResult.

KEY CONSTRAINTS
---------------
- No tool loop: LLM is called with ``tools=None`` — text in, text out.
- No TranscriptStore dependency: ephemeral by design.
- Provider is optional: when None, a stub summary (first ~1000 chars of
  input) is returned so callers do not crash in test or no-LLM environments.
- Output is always scanned before the response UM is constructed.

SECURITY NOTES
--------------
- ``scan_for_suspicious_content`` runs on every LLM output before it leaves
  this agent.  Flagged output → error UM; audit event is always written.
- ``max_input_chars`` caps the text forwarded to the LLM, limiting the
  injection surface area.
- Named skills are loaded from the file system only; the skill name is used
  to construct a filename — it is not evaluated or executed.
- The agent never raises; all errors → error-type UM so callers never see
  a Python exception from a summarization failure.
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import TYPE_CHECKING, Optional

from pydantic import ValidationError

from openrattler.agents.providers.base import LLMProvider
from openrattler.agents.summarizer.config import SummarizerAgentConfig
from openrattler.agents.summarizer.models import (
    SummarizerError,
    SummarizerRequest,
    SummarizerResult,
)
from openrattler.models.audit import AuditEvent
from openrattler.models.messages import UniversalMessage, create_message
from openrattler.security.patterns import scan_for_suspicious_content
from openrattler.storage.audit import AuditLog

if TYPE_CHECKING:
    from openrattler.storage.usage import UsageStore

logger = logging.getLogger(__name__)


class SummarizerAgent:
    """Standalone summarization subagent.

    Args:
        config:   ``SummarizerAgentConfig``.  ``skill_prompt_path`` must exist;
                  missing file raises ``FileNotFoundError`` at construction time.
        audit:    ``AuditLog`` for security events (output-flagged, etc.).
        provider: Optional ``LLMProvider``.  When ``None``, a stub fallback is
                  used so the agent remains functional in test environments.

    Raises:
        FileNotFoundError: If ``config.skill_prompt_path`` does not exist.
                           Silent degradation is not acceptable.
    """

    def __init__(
        self,
        config: SummarizerAgentConfig,
        audit: AuditLog,
        provider: Optional[LLMProvider] = None,
        usage_store: Optional["UsageStore"] = None,
        parent_session_key: Optional[str] = None,
    ) -> None:
        skill_path = config.skill_prompt_path
        if not skill_path.exists():
            raise FileNotFoundError(
                f"SummarizerAgent requires a skill prompt at {skill_path!r}; file not found. "
                "A SummarizerAgent without its skill prompt must not run silently degraded."
            )
        self._default_skill_prompt: str = skill_path.read_text(encoding="utf-8")
        self._default_skill_name: str = skill_path.stem
        self._config = config
        self._audit = audit
        self._provider = provider
        self._usage_store = usage_store
        self._parent_session_key = parent_session_key
        # Per-turn token accumulators — reset at the start of each run() call.
        self._turn_prompt_tokens: int = 0
        self._turn_completion_tokens: int = 0
        self._turn_cost_usd: float = 0.0
        self._turn_model: str = ""
        self._turn_llm_calls: int = 0

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    async def run(
        self,
        um: UniversalMessage,
        trace_id: str,
        from_agent: str = "agent:summarizer:sub",
        to_agent: str = "agent:main:main",
        session_key: str = "agent:summarizer:ephemeral",
    ) -> UniversalMessage:
        """Summarize the text in *um.params* and return a UniversalMessage.

        Args:
            um:          Incoming UM; params must be parseable as SummarizerRequest.
            trace_id:    Trace ID propagated to the response and audit events.
            from_agent:  Sender identity for the response UM.
            to_agent:    Recipient identity for the response UM.
            session_key: Session key for the response UM.

        Returns:
            ``UniversalMessage`` with ``type='response'`` and ``SummarizerResult``
            params on success, or ``type='error'`` with ``SummarizerError`` params
            on any failure.

        Security notes:
        - Never raises; all errors returned as error-typed UMs.
        - Output scanning always runs before the response UM is built.
        """
        # Reset per-turn token accumulators for this run.
        self._turn_prompt_tokens = 0
        self._turn_completion_tokens = 0
        self._turn_cost_usd = 0.0
        self._turn_model = ""
        self._turn_llm_calls = 0
        summarizer_session_key = f"agent:summarizer:{(trace_id or 'no-trace')[:12]}"

        try:
            result_um = await self._run(um, trace_id, from_agent, to_agent, session_key)
        except Exception as exc:
            logger.exception("SummarizerAgent unexpected error: %s", exc)
            error = SummarizerError(
                error_code="INTERNAL_ERROR",
                message="Unexpected error in SummarizerAgent",
                trace_id=trace_id,
            )
            result_um = self._build_error_um(error, from_agent, to_agent, session_key, trace_id)

        # Record token usage — runs even when the pipeline encountered an error.
        if self._usage_store is not None and self._turn_llm_calls > 0:
            try:
                await self._usage_store.record_turn(
                    {
                        "session_key": summarizer_session_key,
                        "agent_type": "summarizer",
                        "channel": "summarizer",
                        "parent_session_key": self._parent_session_key,
                        "trace_id": trace_id,
                        "model": self._turn_model,
                        "prompt_tokens": self._turn_prompt_tokens,
                        "completion_tokens": self._turn_completion_tokens,
                        "total_tokens": self._turn_prompt_tokens + self._turn_completion_tokens,
                        "estimated_cost_usd": self._turn_cost_usd,
                        "llm_calls": self._turn_llm_calls,
                        "tool_calls": [],
                        "tool_loops": 0,
                    }
                )
            except Exception as usage_exc:
                logger.warning("SummarizerAgent: failed to record usage: %s", usage_exc)

        return result_um

    # ------------------------------------------------------------------
    # Internal pipeline
    # ------------------------------------------------------------------

    async def _run(
        self,
        um: UniversalMessage,
        trace_id: str,
        from_agent: str,
        to_agent: str,
        session_key: str,
    ) -> UniversalMessage:
        # Step 1: Parse request
        try:
            request = SummarizerRequest.model_validate(um.params)
        except (ValidationError, Exception) as exc:
            logger.warning("SummarizerAgent: invalid params: %s", exc)
            error = SummarizerError(
                error_code="INVALID_REQUEST",
                message=f"Invalid SummarizerRequest params: {exc}",
                trace_id=trace_id,
            )
            return self._build_error_um(error, from_agent, to_agent, session_key, trace_id)

        # Step 2: Select skill prompt
        skill_prompt, skill_name = self._select_skill(request.skill)

        # Step 3: Truncate input
        original_length = len(request.text)
        text = request.text
        was_truncated = False
        if original_length > self._config.max_input_chars:
            text = text[: self._config.max_input_chars]
            was_truncated = True
            logger.debug(
                "SummarizerAgent: truncated input from %d to %d chars",
                original_length,
                self._config.max_input_chars,
            )

        # Step 4: Build messages and call LLM (or stub)
        output = await self._summarize(skill_prompt, text, request.context)

        # Step 5: Cap output length
        output = output[: self._config.max_output_chars]

        # Step 6: Security scan on output
        flags = scan_for_suspicious_content(output)
        if flags:
            categories = ", ".join(sorted({cat for cat, _ in flags}))
            logger.warning(
                "SummarizerAgent: output flagged by security scan: categories=%r trace_id=%s",
                categories,
                trace_id,
            )
            await self._audit.log(
                AuditEvent(
                    event="summarizer_output_flagged",
                    session_key=session_key,
                    details={"trace_id": trace_id, "categories": categories},
                )
            )
            error = SummarizerError(
                error_code="OUTPUT_FLAGGED",
                message=f"Summary blocked by security scan (categories: {categories})",
                trace_id=trace_id,
            )
            return self._build_error_um(error, from_agent, to_agent, session_key, trace_id)

        # Step 7: Build response UM
        result = SummarizerResult(
            summary=output,
            original_length=original_length,
            skill_used=skill_name,
            was_truncated=was_truncated,
        )
        return self._build_response_um(result, from_agent, to_agent, session_key, trace_id)

    # ------------------------------------------------------------------
    # Skill selection
    # ------------------------------------------------------------------

    def _select_skill(self, skill: Optional[str]) -> tuple[str, str]:
        """Return (prompt_text, skill_name) for the requested skill.

        If *skill* is set and a matching ``SKILL_{skill}.md`` exists in
        ``named_skills_dir``, that file is used.  Otherwise falls back to
        the default skill loaded at init.
        """
        if skill and self._config.named_skills_dir:
            candidate = self._config.named_skills_dir / f"SKILL_{skill}.md"
            if candidate.exists():
                try:
                    prompt = candidate.read_text(encoding="utf-8")
                    logger.debug("SummarizerAgent: using named skill %r from %s", skill, candidate)
                    return prompt, candidate.stem
                except OSError as exc:
                    logger.warning(
                        "SummarizerAgent: failed to read named skill %r: %s; falling back",
                        skill,
                        exc,
                    )
        return self._default_skill_prompt, self._default_skill_name

    # ------------------------------------------------------------------
    # LLM call with stub fallback
    # ------------------------------------------------------------------

    async def _summarize(
        self,
        skill_prompt: str,
        text: str,
        context: Optional[str],
    ) -> str:
        """Call the LLM with the skill prompt and return the summary text.

        Falls back to a stub (first 1000 chars of text) when no provider is
        available or the provider call fails.

        Security notes:
        - ``tools=None`` — no tool loop possible during summarization.
        - Output is capped by the caller at ``max_output_chars`` after this
          method returns.
        """
        if self._provider is None:
            return self._stub_summary(text)

        user_content = text
        if context:
            user_content = f"{text}\n\n---\nContext: {context}"

        messages = [
            {"role": "system", "content": skill_prompt},
            {"role": "user", "content": user_content},
        ]
        model = self._config.model.removeprefix("anthropic/")

        try:
            response = await self._provider.complete(
                messages=messages,
                tools=None,
                model=model,
                max_tokens=1024,
            )
            self._turn_prompt_tokens += response.usage.prompt_tokens
            self._turn_completion_tokens += response.usage.completion_tokens
            self._turn_cost_usd += response.usage.estimated_cost_usd
            self._turn_model = response.model
            self._turn_llm_calls += 1
            logger.info(
                "SummarizerAgent: LLM produced %d chars",
                len(response.content),
            )
            return response.content
        except Exception as exc:
            logger.warning("SummarizerAgent: LLM call failed (%s); falling back to stub", exc)
            return self._stub_summary(text)

    @staticmethod
    def _stub_summary(text: str) -> str:
        """Stub fallback used when no provider is available or the LLM call fails."""
        return text[:1000]

    # ------------------------------------------------------------------
    # UM construction helpers
    # ------------------------------------------------------------------

    def _build_response_um(
        self,
        result: SummarizerResult,
        from_agent: str,
        to_agent: str,
        session_key: str,
        trace_id: str,
    ) -> UniversalMessage:
        return create_message(
            from_agent=from_agent,
            to_agent=to_agent,
            session_key=session_key,
            type="response",
            operation="summarize",
            trust_level="main",
            params=result.model_dump(mode="json"),
            trace_id=trace_id,
        )

    def _build_error_um(
        self,
        error: SummarizerError,
        from_agent: str,
        to_agent: str,
        session_key: str,
        trace_id: str,
    ) -> UniversalMessage:
        return create_message(
            from_agent=from_agent,
            to_agent=to_agent,
            session_key=session_key,
            type="error",
            operation="summarize",
            trust_level="main",
            params=error.model_dump(mode="json"),
            trace_id=trace_id,
        )
