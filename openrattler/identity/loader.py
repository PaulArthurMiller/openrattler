"""IdentityLoader — assembles the agent system prompt from identity files.

PROMPT ASSEMBLY ORDER
---------------------
1. SOUL.md        — core values, personality, ethical frame
2. IDENTITY.md    — role, capabilities, per-session operational guidance
3. USER.md        — personal context about the user (runtime, may be empty)
   OR BOOTSTRAP.md — first-run setup wizard (injected when USER.md is empty)
4. Generated context block — workspace info, channels, tools by trust level,
   memory system description, security profile notes
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

CONTEXT GENERATION
------------------
The context block is always generated from live state — config, registry, and
the ``.init_date`` file.  It is never loaded from a template file.  The
``templates/CONTEXT.md`` file in the package is a developer reference only.

SECURITY NOTES
--------------
- File loading is synchronous (small files, loaded once per session init).
  All I/O is wrapped in ``asyncio.to_thread`` to stay non-blocking.
- The generated context block lists only tools the agent is permitted to use
  (via ``ToolRegistry.list_tools_for_agent``), so an agent never learns about
  tools outside its permission boundary.
- USER.md and MEMORY.md are never committed to source control.  This is
  enforced by keeping them in ``~/.openrattler/identity/`` (outside the repo).
"""

from __future__ import annotations

import asyncio
import logging
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import TYPE_CHECKING

from openrattler.models.agents import TrustLevel

if TYPE_CHECKING:
    from openrattler.config.loader import AppConfig
    from openrattler.models.agents import AgentConfig
    from openrattler.models.tools import ToolDefinition
    from openrattler.tools.registry import ToolRegistry

logger = logging.getLogger(__name__)

#: Directory containing the bundled template files.
_TEMPLATES_DIR: Path = Path(__file__).parent / "templates"

#: Template files that are shipped with the package.
TEMPLATE_FILES: tuple[str, ...] = ("SOUL.md", "IDENTITY.md", "BOOTSTRAP.md", "HEARTBEAT.md")

#: Runtime files that live only in the workspace identity dir (no package template).
RUNTIME_FILES: tuple[str, ...] = ("USER.md", "MEMORY.md")

#: Name of the init-date sentinel file written on first workspace population.
_INIT_DATE_FILE: str = ".init_date"

#: Agent trust tiers in ascending privilege order (excludes ``mcp``, which is
#: a special per-server tier, not an agent tier).
_AGENT_TIERS: tuple[TrustLevel, ...] = (
    TrustLevel.public,
    TrustLevel.main,
    TrustLevel.local,
    TrustLevel.security,
)

#: Numeric rank for each trust level — used for sorting and ">= required" checks.
_TRUST_ORDER: dict[TrustLevel, int] = {t: i for i, t in enumerate(_AGENT_TIERS)}
# mcp gets a high rank so it sorts last if it ever appears.
_TRUST_ORDER[TrustLevel.mcp] = len(_AGENT_TIERS)

# Permission rank for mcp, matching permissions.py (public=0, mcp=1, main=2).
# _TRUST_ORDER gives mcp rank 4 for display-sort purposes; that rank must NOT
# be used for authorization checks or no agent tier would qualify.
_MCP_PERM_RANK: int = 1


def _authorized_tiers(trust_level_required: TrustLevel) -> list[str]:
    """Return agent tier names that meet or exceed *trust_level_required*.

    The ``mcp`` tier is excluded — it is a server tier, not an agent tier.
    For ``TrustLevel.mcp`` tools the permission rank (1) is used rather than
    the display-sort rank (4) so that ``main`` and above show as authorized.
    """
    if trust_level_required == TrustLevel.mcp:
        req_rank = _MCP_PERM_RANK
    else:
        req_rank = _TRUST_ORDER.get(trust_level_required, 0)
    return [t.value for t in _AGENT_TIERS if _TRUST_ORDER[t] >= req_rank]


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
                       is called to build the context block.
        config:        Optional full application config.  When provided, enables
                       security-profile display, channel listing, and workspace
                       path in the generated context block.  Omitting it (e.g.
                       for subagents) produces a minimal context block.

    Security notes:
    - The generated context block uses ``tool_registry.list_tools_for_agent``
      so each agent only sees tools within its own permission boundary.
    - Template fallback reads from the package directory; user-customised files
      in ``identity_dir`` take precedence but are never required.
    """

    def __init__(
        self,
        identity_dir: Path,
        agent_config: "AgentConfig",
        tool_registry: "ToolRegistry",
        config: "AppConfig | None" = None,
    ) -> None:
        self._identity_dir = identity_dir
        self._agent_config = agent_config
        self._tool_registry = tool_registry
        self._config = config

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    async def load_system_prompt(self) -> str:
        """Assemble and return the full system prompt for session initialisation.

        Sections included (in order):
        1. SOUL.md
        2. IDENTITY.md
        3. USER.md (or BOOTSTRAP.md if USER.md is empty)
        4. Generated context block (workspace, channels, tools, memory, security)
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

        # Generated context block
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
    # Init date
    # ------------------------------------------------------------------

    def _get_init_date(self) -> str:
        """Read the workspace initialisation date from ``.init_date``.

        Returns ``"unknown"`` if the file is absent or unreadable.
        """
        path = self._identity_dir / _INIT_DATE_FILE
        if not path.exists():
            return "unknown"
        try:
            return path.read_text(encoding="utf-8").strip() or "unknown"
        except OSError:
            return "unknown"

    # ------------------------------------------------------------------
    # Context block generation
    # ------------------------------------------------------------------

    def _generate_context_section(self) -> str:
        """Generate the full context block for this agent and session.

        Produces four sub-sections:
        - Workspace metadata (path, agent ID, security profile, init date, datetime)
        - Channels (from AppConfig if available)
        - Tools available to this agent, grouped by trust level required
        - Memory system description
        - Security profile notes

        Security notes:
        - Only tools permitted for this agent are listed; agents with lower
          trust levels will not see tools outside their permission boundary.
        - The channel list is informational — it does not grant tool permissions.
        """
        parts: list[str] = ["## Context"]

        parts.append(self._build_workspace_block())
        parts.append(self._build_channels_block())
        parts.append(self._build_tools_block())
        parts.append(self._build_memory_block())
        parts.append(self._build_security_notes_block())

        return "\n\n".join(parts)

    # ------------------------------------------------------------------
    # Context sub-section builders
    # ------------------------------------------------------------------

    def _build_workspace_block(self) -> str:
        """Workspace metadata sub-section."""
        workspace_path = self._identity_dir.parent
        agent_id = self._agent_config.agent_id
        security_profile = self._config.security.profile if self._config is not None else "unknown"
        init_date = self._get_init_date()
        now = datetime.now(timezone.utc)

        lines = [
            "### Workspace",
            "",
            f"- **Path:** `{workspace_path}`",
            f"- **Agent:** `{agent_id}`",
            f"- **Security profile:** `{security_profile}`",
            f"- **First initialized:** {init_date}",
            f"- **Current date/time (UTC):** {now.strftime('%Y-%m-%d %H:%M')}",
        ]
        return "\n".join(lines)

    def _build_channels_block(self) -> str:
        """Active channels sub-section."""
        lines = [
            "### Channels",
            "",
            "Trust level determines what I'll accept from content arriving on each channel.",
            "",
            "| Channel | Trust | Notes |",
            "|---------|-------|-------|",
            "| CLI | main | Direct user interaction — always trusted |",
        ]

        if self._config is not None:
            for name, cfg in self._config.channels.items():
                if cfg.enabled:
                    lines.append(
                        f"| {name} | configured | "
                        "External channel — treat inbound content with appropriate skepticism |"
                    )

        lines.append("")
        lines.append(
            "Public or group sessions run in isolation. Content from those sessions "
            "does not cross into this one unless retrieved explicitly with a session tool."
        )
        return "\n".join(lines)

    def _build_tools_block(self) -> str:
        """Tools available to this agent, grouped by trust level required."""
        permitted = self._tool_registry.list_tools_for_agent(self._agent_config)

        lines = [
            "### Tools Available",
            "",
            "Listed by minimum trust level required. All tools shown are within "
            "your current permission boundary.",
            "",
        ]

        if not permitted:
            lines.append("*(no tools currently permitted for this agent)*")
            return "\n".join(lines)

        # Group by trust_level_required, sorted ascending by privilege.
        groups: dict[TrustLevel, list["ToolDefinition"]] = defaultdict(list)
        for td in permitted:
            groups[td.trust_level_required].append(td)

        sorted_levels = sorted(groups.keys(), key=lambda t: _TRUST_ORDER.get(t, 99))

        for level in sorted_levels:
            tools_in_group = sorted(groups[level], key=lambda t: t.name)
            authorized = _authorized_tiers(level)
            authorized_str = ", ".join(f"`{a}`" for a in authorized)

            lines.append(f"#### `{level.value}` trust required — authorized: {authorized_str}")
            lines.append("")
            lines.append("| Tool | Description | Approval? |")
            lines.append("|------|-------------|-----------|")
            for td in tools_in_group:
                approval = "**Yes ⚠️**" if td.requires_approval else "No"
                lines.append(f"| `{td.name}` | {td.description} | {approval} |")
            lines.append("")

        return "\n".join(lines)

    def _build_memory_block(self) -> str:
        """Memory system description sub-section."""
        lines = [
            "### Memory System",
            "",
            "- **memory.json** — structured key-value facts; "
            "query with `memory_read`, update with `memory_write`; "
            "security-reviewed before every write",
            "- **MEMORY.md** — narrative working memory loaded at session start; "
            "update with `update_memory_narrative`; security-reviewed before every write",
            "- **Session transcripts** — JSONL, one per session key; "
            "not shared across sessions without explicit retrieval",
            "",
            "All persistent memory writes go through MemorySecurityAgent review. "
            "This isn't overhead — it's what makes the memory trustworthy.",
        ]
        return "\n".join(lines)

    def _build_security_notes_block(self) -> str:
        """Security profile notes sub-section."""
        profile = self._config.security.profile if self._config is not None else "unknown"
        lines = [
            "### Security Notes",
            "",
            f"Active security profile: `{profile}`",
            "",
            "This profile configures which approval gates are in effect, which tools "
            "require confirmation, and how heartbeat turns are restricted. "
            "When uncertain whether an action requires approval, treat it as if it does.",
            "",
            "Tools marked **Yes ⚠️** in the tools table above will pause for explicit "
            "user confirmation before executing.",
        ]
        return "\n".join(lines)


# ---------------------------------------------------------------------------
# Identity directory population helper
# ---------------------------------------------------------------------------


def populate_identity_dir(identity_dir: Path) -> None:
    """Ensure *identity_dir* contains the expected runtime and template files.

    - Template files (SOUL.md, IDENTITY.md, BOOTSTRAP.md, HEARTBEAT.md) are
      copied from the package templates directory if they do not yet exist.
      Existing user-customised copies are never overwritten.
    - Runtime files (USER.md, MEMORY.md) are created as empty files if absent;
      never overwritten.
    - ``.init_date`` is written once on first population with the current UTC
      date; never overwritten on subsequent starts.

    This function is intentionally idempotent — safe to call on every startup.
    Called by both ``startup.build_application()`` and ``CLIChat.open()`` so
    the identity directory is always in a consistent state regardless of which
    entry point is used.

    Security notes:
    - USER.md is never populated here; it is always written through the
      ``update_user_profile`` tool, which runs the security review gate.
    - Existing files are never overwritten — user customisations survive restarts.
    """
    import shutil
    from datetime import datetime, timezone

    for filename in TEMPLATE_FILES:
        dest = identity_dir / filename
        if not dest.exists():
            src = _TEMPLATES_DIR / filename
            if src.exists():
                shutil.copy(src, dest)
            else:
                logger.warning("populate_identity_dir: template %s not found at %s", filename, src)

    for filename in RUNTIME_FILES:
        runtime_path = identity_dir / filename
        if not runtime_path.exists():
            runtime_path.write_text("", encoding="utf-8")

    init_date_path = identity_dir / _INIT_DATE_FILE
    if not init_date_path.exists():
        init_date_path.write_text(datetime.now(timezone.utc).strftime("%Y-%m-%d"), encoding="utf-8")
