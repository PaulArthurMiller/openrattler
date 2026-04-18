"""Claude Code tool definitions for OpenRattler.

Defines the six cc_* ToolDefinition instances that expose Claude Code (CC)
capabilities to the agent runtime.  Tool definitions are pure data — no
subprocess, no I/O.  The executor wiring lives in startup.py (piece 40.5).

Action levels follow the same 1–5 scale as all other built-in tools:

    cc_read_analyze     5 — read-only CC session; no file writes
    cc_write_task       3 — CC writes/modifies files within workspace
    cc_run_with_shell   2 — CC task that includes Bash execution
    cc_git_commit       3 — CC commits staged changes to a corvus/* branch
    cc_git_push_branch  2 — CC pushes a corvus/* branch to remote
    cc_promote_request  1 — Request to merge; always requires human approval

Dead stops (in DEAD_STOP_ACTIONS — no config can override):

    cc_bypass_permissions — defined as a sentinel; dead-stop fires before
                            any handler runs if an agent constructs this call
    cc_push_main          — same; CC may never push directly to main

Registration is conditional on CCConfig.enabled.  startup.py gates the
import and passes cc_enabled=True to register_cc_tools() when enabled.
"""

from __future__ import annotations

from typing import Any

from openrattler.models.agents import TrustLevel
from openrattler.models.tools import ToolDefinition
from openrattler.tools.registry import ToolRegistry

# ---------------------------------------------------------------------------
# Parameter schemas
# ---------------------------------------------------------------------------

_TASK_PROJECT_PARAMS: dict[str, Any] = {
    "type": "object",
    "properties": {
        "task": {
            "type": "string",
            "description": "Natural-language description of what CC should do.",
        },
        "project_name": {
            "type": "string",
            "description": (
                "Short slug for the project directory.  A prefix is prepended "
                "automatically (e.g. 'auth-fix' → 'or-auth-fix')."
            ),
        },
    },
    "required": ["task", "project_name"],
}

_COMMIT_PARAMS: dict[str, Any] = {
    "type": "object",
    "properties": {
        "project_name": {
            "type": "string",
            "description": "Name of the existing project to commit in.",
        },
        "message": {
            "type": "string",
            "description": "Commit message; must follow conventional-commits style.",
        },
    },
    "required": ["project_name", "message"],
}

_PUSH_PARAMS: dict[str, Any] = {
    "type": "object",
    "properties": {
        "project_name": {
            "type": "string",
            "description": "Name of the project whose branch should be pushed.",
        },
        "branch": {
            "type": "string",
            "description": "Branch to push.  Must be prefixed with 'corvus/' or the configured project prefix.",
        },
    },
    "required": ["project_name", "branch"],
}

_PROMOTE_PARAMS: dict[str, Any] = {
    "type": "object",
    "properties": {
        "project_name": {
            "type": "string",
            "description": "Name of the project containing the branch to promote.",
        },
        "branch": {
            "type": "string",
            "description": "Branch to merge (must be a corvus/* branch).",
        },
        "target": {
            "type": "string",
            "description": "Target branch for the merge request.  Default: 'main'.",
        },
    },
    "required": ["project_name", "branch"],
}

_BYPASS_PARAMS: dict[str, Any] = {
    "type": "object",
    "properties": {},
    "required": [],
}

# ---------------------------------------------------------------------------
# Tool definitions
# ---------------------------------------------------------------------------

CC_READ_ANALYZE = ToolDefinition(
    name="cc_read_analyze",
    description=(
        "Spawn Claude Code in read-only mode to analyse a codebase, answer questions, "
        "or produce a review.  CC may only use Read, Glob, Grep, and LS tools — no "
        "file writes or shell commands.  Results are returned as a structured summary."
    ),
    parameters=_TASK_PROJECT_PARAMS,
    action_level=5,
    trust_level_required=TrustLevel.main,
    security_notes=(
        "Read-only — CC cannot write files or run shell commands in this mode.  "
        "Path is fenced to the workspace project directory via --add-dir."
    ),
)

CC_WRITE_TASK = ToolDefinition(
    name="cc_write_task",
    description=(
        "Spawn Claude Code to complete a development task that involves writing or "
        "modifying files within the assistant workspace.  CC runs non-interactively "
        "with a plan-review approval step before execution begins."
    ),
    parameters=_TASK_PROJECT_PARAMS,
    action_level=3,
    trust_level_required=TrustLevel.main,
    security_notes=(
        "CC may write files only within the workspace project directory (enforced by "
        "--add-dir and WorkspaceManager.validate_path).  Shell commands are not "
        "available in this mode — use cc_run_with_shell for those."
    ),
)

CC_RUN_WITH_SHELL = ToolDefinition(
    name="cc_run_with_shell",
    description=(
        "Spawn Claude Code with Bash access to complete a task that requires running "
        "shell commands (e.g. test suites, build steps, linters) in addition to "
        "reading and writing files.  Requires approval under standard and paranoid profiles."
    ),
    parameters=_TASK_PROJECT_PARAMS,
    action_level=2,
    trust_level_required=TrustLevel.main,
    security_notes=(
        "Bash access is granted within the workspace project directory.  The Bash tool "
        "itself can execute arbitrary shell commands — use this mode only for tasks "
        "that genuinely need it (e.g. running tests).  Always review the task "
        "description before approving."
    ),
)

CC_GIT_COMMIT = ToolDefinition(
    name="cc_git_commit",
    description=(
        "Instruct Claude Code to stage all changes in a workspace project and commit "
        "them to the current branch.  The commit author is the configured assistant "
        "identity (e.g. 'Corvus (OpenRattler)'), not the human user."
    ),
    parameters=_COMMIT_PARAMS,
    action_level=3,
    trust_level_required=TrustLevel.main,
    security_notes=(
        "Commits are scoped to the workspace project repo.  The pre-push hook prevents "
        "any subsequent push to main — commits can only be pushed to corvus/* branches."
    ),
)

CC_GIT_PUSH_BRANCH = ToolDefinition(
    name="cc_git_push_branch",
    description=(
        "Instruct Claude Code to push a workspace branch to the remote.  Only "
        "corvus/* branches are permitted; pushing to main is a dead stop.  Requires "
        "approval under standard and paranoid profiles."
    ),
    parameters=_PUSH_PARAMS,
    action_level=2,
    trust_level_required=TrustLevel.main,
    security_notes=(
        "Branch name is validated before spawn: must start with the configured project "
        "prefix (e.g. 'corvus/').  The pre-push git hook provides a second layer of "
        "protection.  'cc_push_main' is a dead stop — this tool cannot push to main."
    ),
)

CC_PROMOTE_REQUEST = ToolDefinition(
    name="cc_promote_request",
    description=(
        "Request that a corvus/* branch be merged into the target branch (default: main).  "
        "This tool always requires human approval regardless of the configured security "
        "profile — it is the wall between CC's work and the human's main branch."
    ),
    parameters=_PROMOTE_PARAMS,
    action_level=1,
    trust_level_required=TrustLevel.main,
    security_notes=(
        "Level 1 — requires approval under every security profile, including minimal.  "
        "The human user retains exclusive control over what lands in main.  This tool "
        "only signals intent; the actual merge is performed by the human user."
    ),
)

# Sentinel dead-stop tool: if an agent ever constructs a call to this tool
# the dead-stop check in ToolExecutor fires before any handler runs.
# It is registered so the executor can look it up; it has no handler callable.
CC_BYPASS_PERMISSIONS = ToolDefinition(
    name="cc_bypass_permissions",
    description=(
        "DEAD STOP — never executes.  Sentinel tool that captures any agent attempt "
        "to invoke Claude Code with --dangerously-skip-permissions or equivalent "
        "permission bypass flags.  The dead-stop check fires before any handler runs."
    ),
    parameters=_BYPASS_PARAMS,
    action_level=1,
    trust_level_required=TrustLevel.main,
    security_notes=(
        "Listed in DEAD_STOP_ACTIONS.  No handler is registered.  "
        "The executor will raise DeadStopError before reaching any handler."
    ),
)

# ---------------------------------------------------------------------------
# All cc_* tool definitions in registration order
# ---------------------------------------------------------------------------

ALL_CC_TOOLS: list[ToolDefinition] = [
    CC_READ_ANALYZE,
    CC_WRITE_TASK,
    CC_RUN_WITH_SHELL,
    CC_GIT_COMMIT,
    CC_GIT_PUSH_BRANCH,
    CC_PROMOTE_REQUEST,
    CC_BYPASS_PERMISSIONS,
]


# ---------------------------------------------------------------------------
# Registration helper
# ---------------------------------------------------------------------------


def register_cc_tools(registry: ToolRegistry) -> None:
    """Register all cc_* tool definitions into *registry*.

    Called by startup.py only when ``CCConfig.enabled`` is True.  The
    CC_BYPASS_PERMISSIONS sentinel is registered without a handler so the
    executor can look it up and fire the dead-stop check.

    Args:
        registry: The application's ToolRegistry instance.
    """
    for tool_def in ALL_CC_TOOLS:
        # No handlers yet — full orchestration wired in piece 40.5.
        registry.register(tool_def, handler=None)
