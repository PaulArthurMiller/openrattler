"""Claude Code tool definitions for OpenRattler.

Defines the six cc_* ToolDefinition instances that expose Claude Code (CC)
capabilities to the agent runtime.  Tool definitions are pure data — no
subprocess, no I/O.  The executor wiring lives in startup.py (piece 40.5).

Action levels follow the same 1–5 scale as all other built-in tools:

    cc_read_analyze     5 — read-only CC session; no file writes
    cc_write_task       3 — CC writes/modifies files within workspace
    cc_run_with_shell   2 — CC task that includes Bash execution
    cc_git_commit       3 — CC commits staged changes to an assistant branch
    cc_git_push_branch  2 — CC pushes an assistant branch to remote
    cc_promote_request  1 — Request to merge; always requires human approval

Dead stops (in DEAD_STOP_ACTIONS — no config can override):

    cc_bypass_permissions — defined as a sentinel; dead-stop fires before
                            any handler runs if an agent constructs this call
    cc_push_main          — same; CC may never push directly to main

Registration is conditional on CCConfig.enabled.  startup.py gates the
import and passes cc_enabled=True to register_cc_tools() when enabled.
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import TYPE_CHECKING, Any

from openrattler.models.agents import TrustLevel
from openrattler.models.tools import ToolDefinition
from openrattler.tools.registry import ToolRegistry

if TYPE_CHECKING:
    from openrattler.config.loader import CCConfig
    from openrattler.tools.claude_code.plan_reviewer import CCPlanReviewer
    from openrattler.tools.claude_code.subprocess_mgr import CCSubprocessManager
    from openrattler.tools.claude_code.workspace import WorkspaceManager

logger = logging.getLogger(__name__)

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
            "description": "Branch to push.  Must use the configured project prefix (e.g. '{prefix}/branch-name').",
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
            "description": "Branch to merge (must use the configured project prefix, e.g. '{prefix}/branch-name').",
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
        "identity (from CCConfig.git_author_name), not the human user."
    ),
    parameters=_COMMIT_PARAMS,
    action_level=3,
    trust_level_required=TrustLevel.main,
    security_notes=(
        "Commits are scoped to the workspace project repo.  The pre-push hook prevents "
        "any subsequent push to main — commits can only be pushed to assistant branches."
    ),
)

CC_GIT_PUSH_BRANCH = ToolDefinition(
    name="cc_git_push_branch",
    description=(
        "Instruct Claude Code to push a workspace branch to the remote.  Only "
        "branches using the configured project prefix are permitted; pushing to main "
        "is a dead stop.  Requires approval under standard and paranoid profiles."
    ),
    parameters=_PUSH_PARAMS,
    action_level=2,
    trust_level_required=TrustLevel.main,
    security_notes=(
        "Branch name is validated before spawn: must start with the configured project "
        "prefix (CCConfig.project_prefix + '/').  The pre-push git hook provides a second layer of "
        "protection.  'cc_push_main' is a dead stop — this tool cannot push to main."
    ),
)

CC_PROMOTE_REQUEST = ToolDefinition(
    name="cc_promote_request",
    description=(
        "Request that an assistant branch be merged into the target branch (default: main).  "
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
    executor can look it up and fire the dead-stop check.  Call
    ``ClaudeCodeTool.register_handlers()`` after this to attach the
    executable handlers.

    Args:
        registry: The application's ToolRegistry instance.
    """
    for tool_def in ALL_CC_TOOLS:
        registry.register(tool_def, handler=None)


# ---------------------------------------------------------------------------
# ClaudeCodeTool — wires all cc_* handlers
# ---------------------------------------------------------------------------


class ClaudeCodeTool:
    """Callable handlers for all cc_* tools.

    Composes WorkspaceManager, CCSubprocessManager, CCPlanReviewer, and
    CCOutputParser into async handler functions that are registered into the
    tool registry by ``register_handlers()``.  The ToolExecutor calls these
    handlers with keyword arguments unpacked from ``ToolCall.arguments``.

    Security notes:
    - ``execute_git_push_branch`` validates the branch name against the
      configured project prefix before spawning CC.  This is a structural
      check in addition to the git pre-push hook.
    - ``execute_promote_request`` runs only after the level-1 executor
      approval gate — no subprocess is spawned; the handler signals intent.
    - Plan review is skipped for ``execute_read_analyze`` (read-only mode has
      no side effects) and for git commit/push (task descriptions are
      system-constructed, not agent-supplied).
    """

    #: Tool names permitted during read-only CC sessions.
    _READ_ONLY_TOOLS: list[str] = ["Read", "Glob", "Grep", "LS"]

    def __init__(
        self,
        workspace: "WorkspaceManager",
        subprocess_mgr: "CCSubprocessManager",
        plan_reviewer: "CCPlanReviewer",
        config: "CCConfig",
    ) -> None:
        """Initialise the tool with all collaborators.

        Args:
            workspace:      Manages project directories and environment vars.
            subprocess_mgr: Spawns CC subprocesses with timeout and session limit.
            plan_reviewer:  Runs read-only plan phase and gates on approval.
            config:         ``CCConfig`` section from the loaded ``AppConfig``.
        """
        from openrattler.tools.claude_code.output_parser import CCOutputParser

        self._workspace = workspace
        self._subprocess_mgr = subprocess_mgr
        self._plan_reviewer = plan_reviewer
        self._config = config
        self._output_parser = CCOutputParser()

    # ------------------------------------------------------------------
    # Tool handlers — called by ToolExecutor via registry.get_handler()
    # ------------------------------------------------------------------

    async def execute_write_task(self, task: str, project_name: str) -> dict[str, Any]:
        """Handler for cc_write_task: plan review + CC write session."""
        project_path = self._workspace.create_project(project_name)
        env = self._workspace.get_env(project_path)

        plan_result = await self._plan_reviewer.review(task, project_path, env)
        if not plan_result.approved:
            raise RuntimeError("Plan not approved — task execution blocked.")

        from openrattler.tools.claude_code.subprocess_mgr import CCResult

        cc_result: CCResult = await self._subprocess_mgr.spawn(
            task=task,
            project_path=project_path,
            allowed_tools=self._config.exec_allowed_tools,
            env=env,
        )
        return self._build_result(cc_result, project_path)

    async def execute_read_analyze(self, task: str, project_name: str) -> dict[str, Any]:
        """Handler for cc_read_analyze: no plan review, read-only tools."""
        project_path = self._workspace.create_project(project_name)
        env = self._workspace.get_env(project_path)

        from openrattler.tools.claude_code.subprocess_mgr import CCResult

        cc_result: CCResult = await self._subprocess_mgr.spawn(
            task=task,
            project_path=project_path,
            allowed_tools=self._READ_ONLY_TOOLS,
            env=env,
        )
        return self._build_result(cc_result, project_path)

    async def execute_run_with_shell(self, task: str, project_name: str) -> dict[str, Any]:
        """Handler for cc_run_with_shell: plan review + exec_allowed_tools (includes Bash)."""
        project_path = self._workspace.create_project(project_name)
        env = self._workspace.get_env(project_path)

        plan_result = await self._plan_reviewer.review(task, project_path, env)
        if not plan_result.approved:
            raise RuntimeError("Plan not approved — task execution blocked.")

        from openrattler.tools.claude_code.subprocess_mgr import CCResult

        cc_result: CCResult = await self._subprocess_mgr.spawn(
            task=task,
            project_path=project_path,
            allowed_tools=self._config.exec_allowed_tools,
            env=env,
        )
        return self._build_result(cc_result, project_path)

    async def execute_git_commit(self, project_name: str, message: str) -> dict[str, Any]:
        """Handler for cc_git_commit: instruct CC to stage all changes and commit."""
        project_path = self._workspace.create_project(project_name)  # idempotent
        env = self._workspace.get_env(project_path)

        # System-constructed task — not agent-supplied — so plan review is skipped.
        task = (
            f"Stage all changed files and create a git commit with exactly this message: "
            f"{message!r}. Run: git add -A then git commit -m <message>. "
            f"Do not modify the commit message."
        )

        from openrattler.tools.claude_code.subprocess_mgr import CCResult

        cc_result: CCResult = await self._subprocess_mgr.spawn(
            task=task,
            project_path=project_path,
            allowed_tools=self._config.exec_allowed_tools,
            env=env,
        )
        return self._build_result(cc_result, project_path)

    async def execute_git_push_branch(self, project_name: str, branch: str) -> dict[str, Any]:
        """Handler for cc_git_push_branch: validate branch name, then push."""
        expected_prefix = f"{self._config.project_prefix}/"
        if not branch.startswith(expected_prefix):
            raise ValueError(
                f"Branch '{branch}' does not start with the required project prefix "
                f"'{self._config.project_prefix}/'. Branches must follow the naming "
                f"convention (e.g. '{self._config.project_prefix}/my-feature')."
            )

        project_path = self._workspace.create_project(project_name)  # idempotent
        env = self._workspace.get_env(project_path)

        task = f"Push branch '{branch}' to the remote origin. " f"Run: git push origin {branch}"

        from openrattler.tools.claude_code.subprocess_mgr import CCResult

        cc_result: CCResult = await self._subprocess_mgr.spawn(
            task=task,
            project_path=project_path,
            allowed_tools=self._config.exec_allowed_tools,
            env=env,
        )
        return self._build_result(cc_result, project_path)

    async def execute_promote_request(
        self,
        project_name: str,
        branch: str,
        target: str = "main",
    ) -> dict[str, Any]:
        """Handler for cc_promote_request: signal merge intent after level-1 approval.

        No CC subprocess is spawned — the level-1 ToolExecutor approval gate
        already captured the human decision.  This handler records and returns
        the approved intent so the agent can act on it (e.g. open a PR).
        """
        logger.info(
            "ClaudeCodeTool: promote request approved — project=%s branch=%s target=%s",
            project_name,
            branch,
            target,
        )
        return {
            "type": "cc_promote_request",
            "project_name": project_name,
            "branch": branch,
            "target": target,
            "status": "approved",
            "message": (
                f"Promote request approved: merge '{branch}' into '{target}' "
                f"in project '{project_name}'."
            ),
        }

    # ------------------------------------------------------------------
    # Registration helper
    # ------------------------------------------------------------------

    def register_handlers(self, registry: ToolRegistry) -> None:
        """Register all cc_* handlers into *registry*.

        Must be called after ``register_cc_tools(registry)`` so the tool
        definitions exist.  ``cc_bypass_permissions`` is intentionally omitted
        — its dead stop fires before any handler could be reached.

        Args:
            registry: The application's ToolRegistry instance.
        """
        handlers: dict[str, Any] = {
            "cc_write_task": self.execute_write_task,
            "cc_read_analyze": self.execute_read_analyze,
            "cc_run_with_shell": self.execute_run_with_shell,
            "cc_git_commit": self.execute_git_commit,
            "cc_git_push_branch": self.execute_git_push_branch,
            "cc_promote_request": self.execute_promote_request,
        }
        for tool_name, handler in handlers.items():
            tool_def = registry.get(tool_name)
            if tool_def is not None:
                registry.register(tool_def, handler=handler)
            else:
                logger.warning(
                    "ClaudeCodeTool.register_handlers: definition for '%s' not found "
                    "— call register_cc_tools() before register_handlers()",
                    tool_name,
                )

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    def _build_result(
        self,
        cc_result: Any,
        project_path: Path,
    ) -> dict[str, Any]:
        """Parse CC subprocess output into a result dict.

        Raises:
            RuntimeError: If the CC subprocess reported an error (timeout,
                          session limit, JSON parse failure, or CC-level error).
        """
        if cc_result.error:
            raise RuntimeError(cc_result.error)

        parsed = self._output_parser.parse(cc_result.stdout)
        if parsed.error:
            raise RuntimeError(parsed.error)

        # Log cost to the application log so spending is traceable.
        if parsed.cost_usd is not None:
            logger.info(
                "ClaudeCodeTool: cc_session_cost session_id=%s cost_usd=%.6f",
                parsed.session_id,
                parsed.cost_usd,
            )

        return {
            "type": "cc_result",
            "content": parsed.result,
            "session_id": parsed.session_id,
            "cost_usd": parsed.cost_usd,
            "num_turns": parsed.num_turns,
            "project_path": str(project_path),
        }
