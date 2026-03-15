"""IdentityLoader — assembles the agent system prompt from identity files.

PROMPT ASSEMBLY ORDER
---------------------
1. SOUL.md        — core values, personality, ethical frame
2. IDENTITY.md    — role, capabilities, per-session operational guidance
3. USER.md        — personal context about the user (runtime, may be empty)
   OR BOOTSTRAP.md — first-run setup wizard (injected when USER.md is empty)
4. Generated context section — permitted tools, current datetime
5. MEMORY.md      — narrative working memory (runtime, may be absent)

The ``load_heartbeat_section()`` method returns HEARTBEAT.md content for
injection by the ProcessorScheduler during scheduled turns.

FILE RESOLUTION
---------------
For each template file (SOUL, IDENTITY, BOOTSTRAP, HEARTBEAT), the loader
checks ``identity_dir`` first.  If a user-customised copy exists there it is
used; otherwise the file is read from the package's ``templates/`` directory.

USER.md and MEMORY.md are runtime-only — they have no package template and
are always read from ``identity_dir`` (returning an empty string if absent).

SECURITY NOTES
--------------
- File loading is synchronous (small files, loaded once per session init).
  All I/O is wrapped in ``asyncio.to_thread`` to stay non-blocking.
- The generated context section lists only tools the agent is permitted to
  use (via ``ToolRegistry.list_tools_for_agent``), so an agent never learns
  about tools outside its permission boundary.
- USER.md and MEMORY.md are never committed to source control.  This is
  enforced by keeping them in ``~/.openrattler/identity/`` (outside the repo).
"""

from __future__ import annotations

import asyncio
import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from openrattler.models.agents import AgentConfig
    from openrattler.tools.registry import ToolRegistry

logger = logging.getLogger(__name__)

#: Directory containing the bundled template files.
_TEMPLATES_DIR: Path = Path(__file__).parent / "templates"

#: Template files that are shipped with the package.
TEMPLATE_FILES: tuple[str, ...] = ("SOUL.md", "IDENTITY.md", "BOOTSTRAP.md", "HEARTBEAT.md")

#: Runtime files that live only in the workspace identity dir (no package template).
RUNTIME_FILES: tuple[str, ...] = ("USER.md", "MEMORY.md")


# ---------------------------------------------------------------------------
# IdentityLoader
# ---------------------------------------------------------------------------


class IdentityLoader:
    """Assembles the agent system prompt from identity and memory files.

    Args:
        identity_dir:  Runtime identity directory (e.g. ``~/.openrattler/identity``).
                       Template files are copied here on first run by ``build_application``.
        agent_config:  Configuration of the agent being initialised.  Used to
                       filter the tool list to only permitted tools.
        tool_registry: Registry of all available tools.  ``list_tools_for_agent``
                       is called to build the context section.

    Security notes:
    - The generated context section uses ``tool_registry.list_tools_for_agent``
      so each agent only sees tools within its own permission boundary.
    - Template fallback reads from the package directory; user-customised files
      in ``identity_dir`` take precedence but are never required.
    """

    def __init__(
        self,
        identity_dir: Path,
        agent_config: "AgentConfig",
        tool_registry: "ToolRegistry",
    ) -> None:
        self._identity_dir = identity_dir
        self._agent_config = agent_config
        self._tool_registry = tool_registry

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    async def load_system_prompt(self) -> str:
        """Assemble and return the full system prompt for session initialisation.

        Sections included (in order):
        1. SOUL.md
        2. IDENTITY.md
        3. USER.md (or BOOTSTRAP.md if USER.md is empty)
        4. Generated context section (tools + datetime)
        5. MEMORY.md (if non-empty)

        Returns:
            The assembled system prompt string.
        """
        return await asyncio.to_thread(self._assemble_system_prompt)

    async def load_heartbeat_section(self) -> str:
        """Return the HEARTBEAT.md content for injection during scheduled turns.

        Returns an empty string if the file cannot be loaded.
        """
        return await asyncio.to_thread(self._load_heartbeat)

    # ------------------------------------------------------------------
    # Internal assembly (runs in thread via asyncio.to_thread)
    # ------------------------------------------------------------------

    def _assemble_system_prompt(self) -> str:
        """Synchronous assembly — called inside asyncio.to_thread."""
        parts: list[str] = []

        soul = self._load_template_file("SOUL.md")
        if soul:
            parts.append(soul)

        identity = self._load_template_file("IDENTITY.md")
        if identity:
            parts.append(identity)

        # USER.md or BOOTSTRAP.md
        if self._is_bootstrap_needed():
            bootstrap = self._load_template_file("BOOTSTRAP.md")
            if bootstrap:
                parts.append(bootstrap)
        else:
            user = self._load_runtime_file("USER.md")
            if user:
                parts.append(user)

        # Generated context section
        context = self._generate_context_section()
        if context:
            parts.append(context)

        # Narrative working memory
        memory = self._load_runtime_file("MEMORY.md")
        if memory:
            parts.append(f"## Working Memory\n\n{memory}")

        return "\n\n".join(parts)

    def _load_heartbeat(self) -> str:
        """Synchronous HEARTBEAT.md load — called inside asyncio.to_thread."""
        return self._load_template_file("HEARTBEAT.md")

    # ------------------------------------------------------------------
    # File helpers
    # ------------------------------------------------------------------

    def _load_template_file(self, filename: str) -> str:
        """Load a template file, preferring identity_dir over the package template.

        Returns an empty string if neither location has the file.
        """
        # User-customised copy takes precedence.
        user_copy = self._identity_dir / filename
        if user_copy.exists():
            try:
                return user_copy.read_text(encoding="utf-8").strip()
            except OSError as exc:
                logger.warning("IdentityLoader: failed to read %s: %s", user_copy, exc)

        # Fall back to the bundled package template.
        bundled = _TEMPLATES_DIR / filename
        if bundled.exists():
            try:
                return bundled.read_text(encoding="utf-8").strip()
            except OSError as exc:
                logger.warning("IdentityLoader: failed to read bundled %s: %s", bundled, exc)

        logger.warning("IdentityLoader: %s not found in identity_dir or templates", filename)
        return ""

    def _load_runtime_file(self, filename: str) -> str:
        """Load a runtime-only file from identity_dir.

        Returns an empty string if the file does not exist or is empty.
        """
        path = self._identity_dir / filename
        if not path.exists():
            return ""
        try:
            return path.read_text(encoding="utf-8").strip()
        except OSError as exc:
            logger.warning("IdentityLoader: failed to read %s: %s", path, exc)
            return ""

    # ------------------------------------------------------------------
    # Bootstrap detection
    # ------------------------------------------------------------------

    def _is_bootstrap_needed(self) -> bool:
        """Return True if USER.md is absent or empty."""
        path = self._identity_dir / "USER.md"
        if not path.exists():
            return True
        try:
            return not path.read_text(encoding="utf-8").strip()
        except OSError:
            return True

    # ------------------------------------------------------------------
    # Context section generation
    # ------------------------------------------------------------------

    def _generate_context_section(self) -> str:
        """Generate the '## Available Context' section for this specific agent.

        Includes:
        - Current UTC date and time
        - List of tools this agent is permitted to use (filtered by permission)

        Security notes:
        - Only tools permitted for this agent are listed; agents with lower
          trust levels will not see tools outside their permission boundary.
        """
        lines: list[str] = ["## Available Context", ""]

        # Current date/time
        now = datetime.now(timezone.utc)
        lines.append(f"**Current date/time (UTC):** {now.strftime('%Y-%m-%d %H:%M')} UTC")
        lines.append("")

        # Permitted tools
        permitted = self._tool_registry.list_tools_for_agent(self._agent_config)
        if permitted:
            lines.append("**Tools available to you:**")
            lines.append("")
            for td in permitted:
                lines.append(f"- `{td.name}` — {td.description}")
        else:
            lines.append("**Tools available to you:** none")

        return "\n".join(lines)
