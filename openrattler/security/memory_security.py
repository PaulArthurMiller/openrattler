"""Memory Security Agent — reviews persistent memory changes before they persist.

This is Layer 10 of OpenRattler's defence-in-depth security architecture.
Before any memory write is committed, the MemorySecurityAgent scans the
proposed diff for suspicious content and checks session-level write
restrictions.

REVIEW PIPELINE (review_memory_change)
---------------------------------------
1. Serialize the diff to a text representation.
2. Run scan_for_suspicious_content against it, filter by the configured
   category blocklist.
3. Check whether a non-main session is attempting to modify the
   ``instructions`` key (a common prompt-poisoning vector).
4. Emit a SecurityResult (suspicious flag + reason + confidence).
5. Audit-log the review outcome.

SECURITY NOTES
--------------
- The agent never raises — every code path returns a SecurityResult.
  Callers decide whether to block or allow based on the result.
- LLM-based subtle-attack detection is intentionally stubbed (TODO).
  Pattern matching alone provides the first, and often sufficient, layer.
- Audit events are always written, even for clean changes, so reviewers
  can see that security review occurred.
- ``suspicious_patterns`` is a list of *category names* drawn from the
  SUSPICIOUS_PATTERNS catalogue.  Callers choose which categories block
  writes; this makes the agent's sensitivity tunable per context/profile.
"""

from __future__ import annotations

import json
from typing import Any, Optional

from pydantic import BaseModel

from openrattler.models.audit import AuditEvent
from openrattler.security.patterns import scan_for_suspicious_content
from openrattler.storage.audit import AuditLog

# ---------------------------------------------------------------------------
# Result model
# ---------------------------------------------------------------------------

_MAIN_SESSION_KEY = "agent:main:main"


class SecurityResult(BaseModel):
    """Outcome of a memory-security review.

    Attributes:
        suspicious: True when the proposed change should be blocked.
        reason:     Human-readable explanation when suspicious is True.
        confidence: 0–100 confidence score.  100 = definite threat detected
                    via pattern match; 80 = policy violation (non-main session
                    writing instructions); 0 = clean.
    """

    suspicious: bool
    reason: Optional[str] = None
    confidence: int  # 0–100


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _diff_to_text(diff: dict[str, Any]) -> str:
    """Flatten a memory diff to a single string for pattern scanning.

    We JSON-serialise the added, modified, and removed sections so that
    both keys and values are included in the scan surface.
    """
    parts: list[str] = []
    for section in ("added", "modified", "removed"):
        data = diff.get(section, {})
        if data:
            parts.append(json.dumps(data, ensure_ascii=False))
    return " ".join(parts)


def _modifies_instructions(diff: dict[str, Any]) -> bool:
    """Return True if the diff adds or modifies the ``instructions`` key."""
    return "instructions" in diff.get("added", {}) or "instructions" in diff.get("modified", {})


def _is_main_session(session_key: str) -> bool:
    """Return True only for the personal main session."""
    return session_key == _MAIN_SESSION_KEY


# ---------------------------------------------------------------------------
# MemorySecurityAgent
# ---------------------------------------------------------------------------


class MemorySecurityAgent:
    """Security gatekeeper for persistent memory changes.

    Args:
        suspicious_patterns: List of category names from SUSPICIOUS_PATTERNS
            that should block a memory write.  For example:
            ``["command_injection", "instruction_override", "exfiltration"]``.
            An empty list disables pattern-based blocking (only session-level
            policy checks will apply).
        audit_log: Audit log instance that receives a review event for every
            call to review_memory_change, whether the change is clean or not.

    Security notes:
    - The ``CreatorSecurityValidator`` pattern is intentionally followed:
      the security validator is a concrete dependency, not a replaceable
      interface, so it cannot be monkey-patched out in production.
    - review_memory_change never raises; callers always receive a
      SecurityResult and can act on it without try/except.
    """

    def __init__(self, suspicious_patterns: list[str], audit_log: AuditLog) -> None:
        # Category names that cause a write to be blocked when matched.
        self._pattern_categories: frozenset[str] = frozenset(suspicious_patterns)
        self._audit = audit_log

    # ------------------------------------------------------------------
    # Public async API
    # ------------------------------------------------------------------

    async def review_memory_change(
        self,
        agent_id: str,
        diff: dict[str, Any],
        session_key: str,
    ) -> SecurityResult:
        """Review a proposed memory diff and return a SecurityResult.

        Args:
            agent_id:    The agent whose memory would be modified.
            diff:        Diff dict from MemoryStore.compute_diff — keys
                         ``added``, ``removed``, ``modified``.
            session_key: Session that is requesting the write.

        Returns:
            SecurityResult with suspicious=True if the change should be
            blocked, False if it can proceed.

        Security notes:
        - The method never raises; all exceptions are caught and returned
          as a suspicious result with confidence=100.
        - TODO: integrate an LLM-based subtle-attack detector here as an
          additional step between pattern matching and the final result.
          The pattern layer alone catches the most common injection vectors.
        """
        try:
            return await self._do_review(agent_id, diff, session_key)
        except Exception as exc:  # pragma: no cover — safety net
            # Unexpected errors default to blocking the write (fail-secure).
            result = SecurityResult(
                suspicious=True,
                reason=f"Internal review error: {exc}",
                confidence=100,
            )
            await self._audit.log(
                AuditEvent(
                    event="memory_security_review",
                    session_key=session_key,
                    agent_id=agent_id,
                    details={"error": str(exc), "blocked": True},
                )
            )
            return result

    # ------------------------------------------------------------------
    # Private implementation
    # ------------------------------------------------------------------

    async def _do_review(
        self,
        agent_id: str,
        diff: dict[str, Any],
        session_key: str,
    ) -> SecurityResult:
        """Core review logic — separated so the outer method can catch errors."""
        reasons: list[str] = []

        # ------------------------------------------------------------------
        # Step 1: Pattern matching
        # ------------------------------------------------------------------
        text = _diff_to_text(diff)
        if text and self._pattern_categories:
            matches = scan_for_suspicious_content(text)
            flagged = [
                (category, matched)
                for category, matched in matches
                if category in self._pattern_categories
            ]
            if flagged:
                for category, matched in flagged:
                    reasons.append(f"suspicious pattern [{category}]: {matched!r}")

        # ------------------------------------------------------------------
        # Step 2: Non-main session attempting to modify instructions
        # ------------------------------------------------------------------
        if not _is_main_session(session_key) and _modifies_instructions(diff):
            reasons.append(f"non-main session {session_key!r} attempted to modify 'instructions'")

        # ------------------------------------------------------------------
        # Step 3: Build result and audit
        # ------------------------------------------------------------------
        suspicious = bool(reasons)
        reason = "; ".join(reasons) if reasons else None
        # Confidence: 100 on definite pattern hit, 80 on policy-only violation, 0 for clean.
        if reasons:
            has_pattern_hit = any(r.startswith("suspicious pattern") for r in reasons)
            confidence = 100 if has_pattern_hit else 80
        else:
            confidence = 0

        result = SecurityResult(suspicious=suspicious, reason=reason, confidence=confidence)

        await self._audit.log(
            AuditEvent(
                event="memory_security_review",
                session_key=session_key,
                agent_id=agent_id,
                details={
                    "suspicious": suspicious,
                    "confidence": confidence,
                    "reason": reason,
                    "blocked": suspicious,
                },
            )
        )

        return result
