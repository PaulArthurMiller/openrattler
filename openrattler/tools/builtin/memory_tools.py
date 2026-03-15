"""Narrative memory tools — update_memory_narrative and update_user_profile.

These tools give the agent write access to its two runtime identity files:

- ``MEMORY.md``   — free-form working memory narrative (append or replace)
- ``USER.md``     — structured user profile (always a full replace)

Both files live in the workspace identity directory
(``~/.openrattler/identity/``).  All writes are:

1. Validated against token limits (approximated as ``len(text) // 4``).
2. Reviewed by ``MemorySecurityAgent`` before touching disk.
3. Written atomically via temp-file + rename.

TOKEN LIMITS
------------
- ``narrative_max_write_tokens`` caps the size of a single write to MEMORY.md.
- ``narrative_max_tokens`` caps the total size of MEMORY.md.
- ``user_profile_max_tokens`` caps the total size of USER.md.

Limits come from ``MemoryConfig`` (default: 300 write / 2000 file / 500 user).
The tool response always reports current token usage so the agent knows when
to prune.  Near-80% capacity triggers an explicit pruning suggestion.

SECURITY NOTES
--------------
- The ``MemorySecurityAgent`` is never bypassed — every write goes through the
  security review gate regardless of mode or caller.
- Writes are atomic (temp file + ``Path.replace()``) so a crash mid-write
  never leaves a corrupt file.
- ``agent_id`` and ``session_key`` passed to the security review are fixed at
  construction time; they cannot be influenced by the LLM's tool arguments.
"""

from __future__ import annotations

import asyncio
import logging
from pathlib import Path
from typing import TYPE_CHECKING

from openrattler.models.agents import TrustLevel
from openrattler.models.tools import ToolDefinition

if TYPE_CHECKING:
    from openrattler.config.loader import MemoryConfig
    from openrattler.security.memory_security import MemorySecurityAgent
    from openrattler.storage.audit import AuditLog
    from openrattler.tools.registry import ToolRegistry

logger = logging.getLogger(__name__)

#: Session key used in security review audit events from these tools.
_TOOLS_SESSION_KEY = "agent:main:main"

#: Threshold (fraction of max) at which a pruning suggestion is added to the response.
_PRUNE_WARNING_THRESHOLD = 0.80


# ---------------------------------------------------------------------------
# Token approximation helper
# ---------------------------------------------------------------------------


def _approx_tokens(text: str) -> int:
    """Approximate token count using the chars-÷-4 heuristic."""
    return max(1, len(text) // 4)


# ---------------------------------------------------------------------------
# Atomic write helper (synchronous, called via asyncio.to_thread)
# ---------------------------------------------------------------------------


def _atomic_write(path: Path, content: str) -> None:
    """Write *content* to *path* atomically via a temp-file + replace.

    Security notes:
    - ``Path.replace()`` is atomic on POSIX and succeeds on Windows even when
      the target already exists, preventing torn writes.
    - The temp file is cleaned up on any exception to avoid stale .tmp files.
    """
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + ".tmp")
    try:
        tmp.write_text(content, encoding="utf-8")
        tmp.replace(path)
    except Exception:
        try:
            tmp.unlink(missing_ok=True)
        except OSError:
            pass
        raise


# ---------------------------------------------------------------------------
# NarrativeMemoryTools
# ---------------------------------------------------------------------------


class NarrativeMemoryTools:
    """Container for narrative memory tools registered with the tool registry.

    Args:
        identity_dir:   Path to the runtime identity directory
                        (``~/.openrattler/identity/``).
        memory_config:  Token limits for MEMORY.md and USER.md.
        security_agent: Gatekeeper that reviews all writes before they persist.
        audit:          Audit log (passed through to the security agent which
                        logs its own review events).

    Security notes:
    - ``security_agent`` is captured at construction time and cannot be
      replaced or bypassed by the LLM's tool arguments.
    - Both tools are registered explicitly (not via ``@tool``) because they
      require a bound ``identity_dir`` and ``security_agent`` instance.
    """

    def __init__(
        self,
        identity_dir: Path,
        memory_config: "MemoryConfig",
        security_agent: "MemorySecurityAgent",
        audit: "AuditLog",
    ) -> None:
        self._identity_dir = identity_dir
        self._config = memory_config
        self._security_agent = security_agent
        self._audit = audit

    # ------------------------------------------------------------------
    # Registration
    # ------------------------------------------------------------------

    def register_all(self, registry: "ToolRegistry") -> None:
        """Register both narrative memory tools into *registry*."""
        registry.register(
            ToolDefinition(
                name="update_memory_narrative",
                description=(
                    "Update the working memory narrative (MEMORY.md). "
                    "Use 'append' to add new content, 'replace' to rewrite the entire file "
                    "(use replace to prune when approaching the token limit)."
                ),
                parameters={
                    "type": "object",
                    "properties": {
                        "mode": {
                            "type": "string",
                            "enum": ["append", "replace"],
                            "description": (
                                "'append' adds content to the end of MEMORY.md. "
                                "'replace' rewrites the entire file — use this to prune "
                                "and condense when approaching the token limit."
                            ),
                        },
                        "content": {
                            "type": "string",
                            "description": (
                                "The Markdown text to write. For append, this is the new "
                                "section to add. For replace, this is the complete new "
                                "contents of MEMORY.md."
                            ),
                        },
                    },
                    "required": ["mode", "content"],
                },
                trust_level_required=TrustLevel.main,
                requires_approval=False,
                security_notes=(
                    "All writes pass through MemorySecurityAgent pattern scan before "
                    "touching disk. Atomic write (temp + rename). Token limits enforced "
                    "before security review."
                ),
            ),
            self._update_memory_narrative,
        )
        registry.register(
            ToolDefinition(
                name="update_user_profile",
                description=(
                    "Replace the user profile (USER.md) with updated content. "
                    "Always rewrites the entire file — include all current profile "
                    "information, not just the new additions."
                ),
                parameters={
                    "type": "object",
                    "properties": {
                        "content": {
                            "type": "string",
                            "description": (
                                "The complete new contents of USER.md in Markdown. "
                                "Include all profile information: name, timezone, "
                                "communication preferences, interests, standing rules."
                            ),
                        },
                    },
                    "required": ["content"],
                },
                trust_level_required=TrustLevel.main,
                requires_approval=False,
                security_notes=(
                    "All writes pass through MemorySecurityAgent pattern scan. "
                    "Atomic write (temp + rename). Token limit enforced before review."
                ),
            ),
            self._update_user_profile,
        )

    # ------------------------------------------------------------------
    # Tool handlers
    # ------------------------------------------------------------------

    async def _update_memory_narrative(self, mode: str, content: str) -> str:
        """Handler for update_memory_narrative.

        Validates token limits, runs security review, writes atomically.

        Args:
            mode:    "append" or "replace".
            content: The text to append or the full replacement content.

        Returns:
            A status string reporting token usage and any warnings.
        """
        if mode not in ("append", "replace"):
            return f"Error: mode must be 'append' or 'replace', got {mode!r}."

        max_write = self._config.narrative_max_write_tokens
        max_file = self._config.narrative_max_tokens
        write_tokens = _approx_tokens(content)

        if write_tokens > max_write:
            return (
                f"Error: content is approximately {write_tokens} tokens, "
                f"exceeding the per-write limit of {max_write}. "
                f"Please shorten your entry and try again."
            )

        memory_path = self._identity_dir / "MEMORY.md"
        current_content = ""
        if memory_path.exists():
            try:
                current_content = memory_path.read_text(encoding="utf-8")
            except OSError as exc:
                return f"Error: could not read MEMORY.md: {exc}"

        if mode == "append":
            new_content = (current_content.rstrip() + "\n\n" + content.strip()).strip()
        else:
            new_content = content.strip()

        total_tokens = _approx_tokens(new_content)
        if total_tokens > max_file:
            return (
                f"Error: this write would bring MEMORY.md to approximately "
                f"{total_tokens} tokens, exceeding the file limit of {max_file}. "
                f"Use replace mode to condense and prune the file first."
            )

        # Security review
        diff = self._build_diff(current_content, new_content, mode)
        security_result = await self._security_agent.review_memory_change(
            agent_id="main",
            diff=diff,
            session_key=_TOOLS_SESSION_KEY,
        )
        if security_result.suspicious:
            return f"Error: write blocked by security review. " f"Reason: {security_result.reason}"

        # Atomic write
        try:
            await asyncio.to_thread(_atomic_write, memory_path, new_content)
        except OSError as exc:
            return f"Error: failed to write MEMORY.md: {exc}"

        # Build status response
        return self._status_message("MEMORY.md", total_tokens, max_file)

    async def _update_user_profile(self, content: str) -> str:
        """Handler for update_user_profile.

        Always replaces USER.md entirely.  Validates token limit, runs
        security review, writes atomically.

        Args:
            content: The complete new contents of USER.md.

        Returns:
            A status string reporting token usage and any warnings.
        """
        max_tokens = self._config.user_profile_max_tokens
        write_tokens = _approx_tokens(content)

        if write_tokens > max_tokens:
            return (
                f"Error: content is approximately {write_tokens} tokens, "
                f"exceeding the USER.md limit of {max_tokens}. "
                f"Please shorten the profile and try again."
            )

        user_path = self._identity_dir / "USER.md"
        current_content = ""
        if user_path.exists():
            try:
                current_content = user_path.read_text(encoding="utf-8")
            except OSError:
                pass

        new_content = content.strip()

        # Security review
        diff = self._build_diff(current_content, new_content, "replace")
        security_result = await self._security_agent.review_memory_change(
            agent_id="main",
            diff=diff,
            session_key=_TOOLS_SESSION_KEY,
        )
        if security_result.suspicious:
            return f"Error: write blocked by security review. " f"Reason: {security_result.reason}"

        # Atomic write
        try:
            await asyncio.to_thread(_atomic_write, user_path, new_content)
        except OSError as exc:
            return f"Error: failed to write USER.md: {exc}"

        total_tokens = _approx_tokens(new_content)
        return self._status_message("USER.md", total_tokens, max_tokens)

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _build_diff(current: str, new: str, mode: str) -> dict[str, object]:
        """Build a diff dict compatible with MemorySecurityAgent.review_memory_change.

        For append mode, the new content is represented as an addition.
        For replace mode, it is represented as a modification.
        """
        if mode == "append":
            return {
                "added": {"narrative_append": new[len(current) :].strip()},
                "modified": {},
                "removed": {},
            }
        # replace
        if current:
            return {
                "added": {},
                "modified": {"narrative_content": {"old": current[:200], "new": new[:200]}},
                "removed": {},
            }
        return {
            "added": {"narrative_content": new},
            "modified": {},
            "removed": {},
        }

    @staticmethod
    def _status_message(filename: str, used_tokens: int, max_tokens: int) -> str:
        """Build a status string reporting token usage with optional pruning hint."""
        msg = f"Written. {filename} is now approximately {used_tokens}/{max_tokens} tokens."
        if used_tokens >= int(max_tokens * _PRUNE_WARNING_THRESHOLD):
            msg += (
                f" File is nearing its limit — use replace mode to condense "
                f"before the next write."
            )
        return msg
