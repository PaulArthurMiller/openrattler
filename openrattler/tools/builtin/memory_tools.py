"""Narrative memory tools — update_memory_narrative, update_user_profile,
update_identity, update_heartbeat, memory_read, and memory_write.

These tools give the agent write access to its runtime identity files and
structured memory store:

- ``MEMORY.md``    — free-form working memory narrative (append or replace)
- ``USER.md``      — structured user profile (always a full replace)
- ``IDENTITY.md``  — operational identity: name, creature, vibe (always a full replace)
- ``HEARTBEAT.md`` — autonomous monitoring routine (always a full replace; elevated
                     approval path — diff display + mandatory rationale required)
- ``memory.json``  — structured key-value fact store (read/write via MemoryStore)

All file writes are:

1. Validated against token limits (approximated as ``len(text) // 4``).
2. Reviewed by ``MemorySecurityAgent`` before touching disk.
3. Written atomically via temp-file + rename.

TOKEN LIMITS
------------
- ``narrative_max_write_tokens`` caps the size of a single write to MEMORY.md.
- ``narrative_max_tokens`` caps the total size of MEMORY.md.
- ``user_profile_max_tokens`` caps the total size of USER.md.
- ``identity_max_tokens`` caps the total size of IDENTITY.md.

Limits come from ``MemoryConfig`` (defaults: 300 write / 2000 file / 500 user / 500 identity).
The tool response always reports current token usage so the agent knows when
to prune.  Near-80% capacity triggers an explicit pruning suggestion.

HEARTBEAT.MD ELEVATED APPROVAL PATH
-------------------------------------
``update_heartbeat`` enforces stricter rules than other identity tools because
HEARTBEAT.md governs autonomous behaviour — modifying it is more consequential
than updating USER.md.

1. ``rationale`` is a required argument.  If absent or empty the tool returns
   an error *before* reaching ``MemorySecurityAgent`` — the agent cannot make
   undocumented autonomous routine changes.
2. Approval metadata includes ``change_type="autonomous_routine_update"`` and a
   unified diff of old vs new content so reviewers see exactly what changes.
3. ``MemorySecurityAgent`` checks specifically for scope creep: capability
   additions or weakened constraints.

TOKEN LIMITS
------------
- ``narrative_max_write_tokens`` caps the size of a single write to MEMORY.md.
- ``narrative_max_tokens`` caps the total size of MEMORY.md.
- ``user_profile_max_tokens`` caps the total size of USER.md.
- ``identity_max_tokens`` caps the total size of IDENTITY.md.

Limits come from ``MemoryConfig`` (defaults: 300 write / 2000 file / 500 user / 500 identity).
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
- When a write is blocked, the optional ``on_security_alert`` callback fires
  independently of the tool response so the alert reaches the user even if
  the agent does not surface it in conversation.
"""

from __future__ import annotations

import asyncio
import difflib
import json
import logging
from collections.abc import Awaitable, Callable
from pathlib import Path
from typing import TYPE_CHECKING, Optional

from openrattler.models.agents import TrustLevel
from openrattler.models.tools import ToolDefinition

if TYPE_CHECKING:
    from openrattler.config.loader import MemoryConfig
    from openrattler.security.memory_security import MemorySecurityAgent
    from openrattler.storage.audit import AuditLog
    from openrattler.storage.memory import MemoryStore
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
        identity_dir:       Path to the runtime identity directory
                            (``~/.openrattler/identity/``).
        memory_config:      Token limits for MEMORY.md, USER.md, and IDENTITY.md.
        security_agent:     Gatekeeper that reviews all writes before they persist.
        audit:              Audit log (passed through to the security agent which
                            logs its own review events).
        memory_store:       Optional MemoryStore for memory_read / memory_write tools.
                            When ``None``, those tools are not registered.
        on_security_alert:  Optional async callback invoked when a write is blocked
                            by the security agent.  Receives ``(filename, reason)``
                            so the caller can surface the event out-of-band from the
                            agent's tool response.

    Security notes:
    - ``security_agent`` is captured at construction time and cannot be
      replaced or bypassed by the LLM's tool arguments.
    - All tools are registered explicitly (not via ``@tool``) because they
      require a bound ``identity_dir`` and ``security_agent`` instance.
    - ``on_security_alert`` fires independently of the tool response; even if
      an agent suppresses the error message in conversation, the alert still
      reaches the registered handler.
    """

    def __init__(
        self,
        identity_dir: Path,
        memory_config: "MemoryConfig",
        security_agent: "MemorySecurityAgent",
        audit: "AuditLog",
        memory_store: Optional["MemoryStore"] = None,
        on_security_alert: Optional[Callable[[str, str], Awaitable[None]]] = None,
    ) -> None:
        self._identity_dir = identity_dir
        self._config = memory_config
        self._security_agent = security_agent
        self._audit = audit
        self._memory_store = memory_store
        self._on_security_alert = on_security_alert

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
        registry.register(
            ToolDefinition(
                name="update_identity",
                description=(
                    "Replace the agent's operational identity file (IDENTITY.md) with "
                    "updated content. Use this after the bootstrap conversation to record "
                    "the agent's name, creature, vibe, and emoji. Always rewrites the "
                    "entire file — include all identity information, not just changes."
                ),
                parameters={
                    "type": "object",
                    "properties": {
                        "content": {
                            "type": "string",
                            "description": (
                                "The complete new contents of IDENTITY.md in Markdown. "
                                "Include name, creature, vibe, emoji, and any other "
                                "identity details established during the bootstrap conversation."
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
            self._update_identity,
        )
        registry.register(
            ToolDefinition(
                name="update_heartbeat",
                description=(
                    "Replace the agent's autonomous monitoring routine (HEARTBEAT.md) with "
                    "updated content. Requires an explicit rationale tied to observed evidence. "
                    "Always rewrites the entire file — include all monitoring instructions."
                    "\n\n⚠️ This changes your agent's autonomous monitoring routine and "
                    "requires a mandatory rationale argument."
                ),
                parameters={
                    "type": "object",
                    "properties": {
                        "content": {
                            "type": "string",
                            "description": (
                                "The complete new contents of HEARTBEAT.md in Markdown. "
                                "Include all monitoring tasks, urgency criteria, and "
                                "reporting instructions."
                            ),
                        },
                        "rationale": {
                            "type": "string",
                            "description": (
                                "Required. A clear explanation of why this change is needed, "
                                "tied to specific observed evidence (e.g. 'user engagement "
                                "patterns show X', 'repeated false positives on topic Y'). "
                                "The update will be rejected if this is absent or empty."
                            ),
                        },
                    },
                    "required": ["content", "rationale"],
                },
                trust_level_required=TrustLevel.main,
                requires_approval=False,
                security_notes=(
                    "Elevated approval path: rationale is required and validated before "
                    "MemorySecurityAgent review. Approval metadata includes unified diff "
                    "and change_type='autonomous_routine_update' to signal elevated review. "
                    "Atomic write (temp + rename). Token limit enforced before review."
                ),
            ),
            self._update_heartbeat,
        )
        if self._memory_store is not None:
            registry.register(
                ToolDefinition(
                    name="memory_read",
                    description=(
                        "Read from the structured memory store (memory.json). "
                        "Omit 'key' to read the entire store. Provide a top-level "
                        "'key' to read a single field (e.g. 'facts', 'preferences')."
                    ),
                    parameters={
                        "type": "object",
                        "properties": {
                            "key": {
                                "type": "string",
                                "description": (
                                    "Optional top-level key to read. "
                                    "If omitted, the entire memory store is returned."
                                ),
                            },
                        },
                        "required": [],
                    },
                    trust_level_required=TrustLevel.main,
                    requires_approval=False,
                    security_notes=(
                        "Read-only. No security review needed — returns stored data only."
                    ),
                ),
                self._memory_read,
            )
            registry.register(
                ToolDefinition(
                    name="memory_write",
                    description=(
                        "Write structured facts to the memory store (memory.json). "
                        "Provide a JSON object of top-level key-value pairs to set. "
                        "Existing keys not mentioned are preserved. "
                        'Example: \'{"facts": {"name": "Paul"}, "bootstrap_complete": true}\''
                    ),
                    parameters={
                        "type": "object",
                        "properties": {
                            "changes_json": {
                                "type": "string",
                                "description": (
                                    "A JSON-encoded object of top-level key-value changes "
                                    "to apply to the memory store. Must be a valid JSON object. "
                                    "The 'history' key is reserved and will be ignored."
                                ),
                            },
                        },
                        "required": ["changes_json"],
                    },
                    trust_level_required=TrustLevel.main,
                    requires_approval=False,
                    security_notes=(
                        "All writes pass through MemorySecurityAgent pattern scan before "
                        "touching disk. The 'history' key cannot be overwritten by callers."
                    ),
                ),
                self._memory_write,
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
            if self._on_security_alert is not None:
                await self._on_security_alert("MEMORY.md", security_result.reason or "")
            return f"Error: write blocked by security review. Reason: {security_result.reason}"

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
            if self._on_security_alert is not None:
                await self._on_security_alert("USER.md", security_result.reason or "")
            return f"Error: write blocked by security review. Reason: {security_result.reason}"

        # Atomic write
        try:
            await asyncio.to_thread(_atomic_write, user_path, new_content)
        except OSError as exc:
            return f"Error: failed to write USER.md: {exc}"

        total_tokens = _approx_tokens(new_content)
        return self._status_message("USER.md", total_tokens, max_tokens)

    async def _update_identity(self, content: str) -> str:
        """Handler for update_identity.

        Always replaces IDENTITY.md entirely.  Validates token limit, runs
        security review, writes atomically.

        Args:
            content: The complete new contents of IDENTITY.md.

        Returns:
            A status string reporting token usage and any warnings.
        """
        max_tokens = self._config.identity_max_tokens
        write_tokens = _approx_tokens(content)

        if write_tokens > max_tokens:
            return (
                f"Error: content is approximately {write_tokens} tokens, "
                f"exceeding the IDENTITY.md limit of {max_tokens}. "
                f"Please shorten the identity and try again."
            )

        identity_path = self._identity_dir / "IDENTITY.md"
        current_content = ""
        if identity_path.exists():
            try:
                current_content = identity_path.read_text(encoding="utf-8")
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
            if self._on_security_alert is not None:
                await self._on_security_alert("IDENTITY.md", security_result.reason or "")
            return f"Error: write blocked by security review. Reason: {security_result.reason}"

        # Atomic write
        try:
            await asyncio.to_thread(_atomic_write, identity_path, new_content)
        except OSError as exc:
            return f"Error: failed to write IDENTITY.md: {exc}"

        total_tokens = _approx_tokens(new_content)
        return self._status_message("IDENTITY.md", total_tokens, max_tokens)

    async def _update_heartbeat(self, content: str, rationale: str = "") -> str:
        """Handler for update_heartbeat.

        Elevated approval path for HEARTBEAT.md:
        - Rejects the write before MemorySecurityAgent if rationale is absent/empty.
        - Passes ``change_type="autonomous_routine_update"`` and a unified diff in
          the security review metadata so the reviewer sees exactly what changes.

        Args:
            content:   The complete new contents of HEARTBEAT.md.
            rationale: Required explanation tied to observed evidence.

        Returns:
            A status string, an error message, or a rejection notice.
        """
        # Reject before security review if rationale is absent or empty.
        if not rationale or not rationale.strip():
            return (
                "Error: HEARTBEAT.md updates require an explicit rationale tied to "
                "observed evidence."
            )

        max_tokens = self._config.identity_max_tokens
        write_tokens = _approx_tokens(content)

        if write_tokens > max_tokens:
            return (
                f"Error: content is approximately {write_tokens} tokens, "
                f"exceeding the HEARTBEAT.md limit of {max_tokens}. "
                f"Please shorten and try again."
            )

        heartbeat_path = self._identity_dir / "HEARTBEAT.md"
        current_content = ""
        if heartbeat_path.exists():
            try:
                current_content = heartbeat_path.read_text(encoding="utf-8")
            except OSError:
                pass

        new_content = content.strip()
        unified_diff = self._build_unified_diff(current_content, new_content, "HEARTBEAT.md")

        # Security review with elevated metadata for HEARTBEAT.md.
        diff = {
            "file": "HEARTBEAT.md",
            "change_type": "autonomous_routine_update",
            "rationale": rationale.strip(),
            "diff": unified_diff,
            "added": {},
            "modified": {
                "heartbeat_content": {"old": current_content[:200], "new": new_content[:200]}
            },
            "removed": {},
        }
        security_result = await self._security_agent.review_memory_change(
            agent_id="main",
            diff=diff,
            session_key=_TOOLS_SESSION_KEY,
        )
        if security_result.suspicious:
            if self._on_security_alert is not None:
                await self._on_security_alert("HEARTBEAT.md", security_result.reason or "")
            return f"Error: write blocked by security review. Reason: {security_result.reason}"

        # Atomic write
        try:
            await asyncio.to_thread(_atomic_write, heartbeat_path, new_content)
        except OSError as exc:
            return f"Error: failed to write HEARTBEAT.md: {exc}"

        total_tokens = _approx_tokens(new_content)
        return self._status_message("HEARTBEAT.md", total_tokens, max_tokens)

    async def _memory_read(self, key: str = "") -> str:
        """Handler for memory_read.

        Reads from the structured memory store.  Returns the entire store when
        *key* is absent or empty, or a single top-level field when *key* is provided.

        Args:
            key: Optional top-level key to read.  Empty string returns the whole store.

        Returns:
            JSON string of the requested data, or an error message.
        """
        if self._memory_store is None:
            return "Error: memory store is not available."
        try:
            data = await self._memory_store.load("main")
        except Exception as exc:
            return f"Error: could not read memory store: {exc}"

        if key:
            if key not in data:
                return f"Key '{key}' not found in memory store."
            return json.dumps(data[key], indent=2, default=str)
        return json.dumps(data, indent=2, default=str)

    async def _memory_write(self, changes_json: str) -> str:
        """Handler for memory_write.

        Parses *changes_json* as a JSON object and applies the changes to the
        structured memory store via ``MemoryStore.apply_changes_with_review``.
        The security agent reviews the diff before any write touches disk.

        Args:
            changes_json: JSON-encoded object of top-level key-value changes.

        Returns:
            A status string, or an error message.
        """
        if self._memory_store is None:
            return "Error: memory store is not available."

        try:
            changes = json.loads(changes_json)
        except json.JSONDecodeError as exc:
            return f"Error: changes_json is not valid JSON: {exc}"

        if not isinstance(changes, dict):
            return "Error: changes_json must be a JSON object (dict), not a list or scalar."

        ok, reason = await self._memory_store.apply_changes_with_review(
            agent_id="main",
            changes=changes,
            session_key=_TOOLS_SESSION_KEY,
            security_agent=self._security_agent,
        )
        if not ok:
            if self._on_security_alert is not None:
                await self._on_security_alert("memory.json", reason or "")
            return f"Error: write blocked by security review. Reason: {reason}"

        keys_written = [k for k in changes if k != "history"]
        return f"Written. Updated keys: {', '.join(keys_written) or '(none)'}."

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
    def _build_unified_diff(current: str, new: str, filename: str) -> str:
        """Generate a unified diff string between *current* and *new* content.

        Used in HEARTBEAT.md approval metadata so reviewers see exactly what changes.
        Returns a non-empty string even when both inputs are empty (first-time write).
        """
        current_lines = current.splitlines(keepends=True)
        new_lines = new.splitlines(keepends=True)
        diff_lines = list(
            difflib.unified_diff(
                current_lines,
                new_lines,
                fromfile=f"a/{filename}",
                tofile=f"b/{filename}",
            )
        )
        if diff_lines:
            return "".join(diff_lines)
        if not current and new:
            return f"--- /dev/null\n+++ b/{filename}\n@@ -0,0 +1 @@\n+{new[:100]}\n"
        return f"(no diff — content identical)"

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
