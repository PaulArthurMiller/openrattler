"""CCPlanReviewer — read-only plan phase for the Claude Code integration.

Before CC executes a write task, this reviewer spawns CC in read-only mode to
produce a plan describing what changes it intends to make.  The plan is then
routed through the existing 39.x approval system so the human can approve or
reject the plan before any file changes are made.

Flow
----
1. If ``CCConfig.plan_review_enabled`` is False: return ``approved=True`` immediately
   (no subprocess, no approval gate).
2. Build a plan-phase prompt that instructs CC to analyze the codebase and
   describe its intended changes — *without making any changes*.
3. Spawn CC via ``CCSubprocessManager`` with the read-only tool list
   (``Read``, ``Glob``, ``Grep``, ``LS``).
4. Parse CC's JSON output; extract the plan text.
5. Check ``policy.requires_approval(config.plan_review_approval_level)``.
   - If the policy says approval is not required (e.g. minimal profile), return
     ``PlanReviewResult(approved=True, plan=plan_text)`` immediately.
6. Build an ``ApprovalRequest`` with:
   - ``operation = "cc_plan_review"``
   - ``action_level = config.plan_review_approval_level``
   - ``context = {"plan": plan_text, "task": task}``   ← plan displayed as action
   - ``rationale = f"Plan for: {task}"``
   - ``timeout_seconds = config.plan_review_timeout_seconds``
7. Call ``approval_manager.request_approval(request)``; return
   ``PlanReviewResult(approved=result.approved, plan=plan_text)``.

Security notes
--------------
- The read-only tool list (``Read``, ``Glob``, ``Grep``, ``LS``) is hard-coded
  here and not configurable, so a config change cannot accidentally grant CC
  write access during the plan phase.
- Plan text is placed in ``context`` (the action block), not only in
  ``rationale`` (the agent-rationale block), so the user reads *what CC plans to
  do* before they read the agent's stated motivation.
- ``requesting_agent`` and ``session_key`` default to system values but can be
  overridden by ``ClaudeCodeTool`` in 40.5 to attach real call-chain context.
"""

from __future__ import annotations

import logging
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import TYPE_CHECKING, Optional

if TYPE_CHECKING:
    from openrattler.config.loader import CCConfig
    from openrattler.security.action_levels import ApprovalThresholdPolicy
    from openrattler.security.approval import ApprovalManager
    from openrattler.tools.claude_code.subprocess_mgr import CCSubprocessManager

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Read-only tool list for the plan phase
# ---------------------------------------------------------------------------

#: CC tool names permitted during the plan phase.  Hard-coded — not read from
#: config — so the plan phase cannot be accidentally granted write access.
_PLAN_PHASE_TOOLS: list[str] = ["Read", "Glob", "Grep", "LS"]

# ---------------------------------------------------------------------------
# Plan-phase prompt template
# ---------------------------------------------------------------------------

#: Prefix prepended to the caller's task description for the plan phase.
#: Instructs CC to analyse and describe — not to act.
_PLAN_PROMPT_PREFIX = (
    "Analyze the codebase and describe the plan you would follow to complete "
    "the following task. Do not make any changes. Output a structured plan "
    "including: files to be modified, files to be created, shell commands to "
    "be run (if any), and reasoning. Task: "
)

# ---------------------------------------------------------------------------
# PlanReviewResult
# ---------------------------------------------------------------------------


@dataclass
class PlanReviewResult:
    """Outcome of the plan review phase.

    Attributes:
        approved: True if the plan was approved (or review was skipped/not required).
        plan:     The plan text produced by CC.  None when review is disabled or
                  when the plan-phase subprocess failed to produce output.
    """

    approved: bool
    plan: Optional[str]


# ---------------------------------------------------------------------------
# CCPlanReviewer
# ---------------------------------------------------------------------------


class CCPlanReviewer:
    """Run a read-only CC plan phase and gate execution on human approval.

    Args:
        subprocess_mgr: Manager used to spawn the read-only CC subprocess.
        approval_manager: 39.x approval broker; receives the plan review request.
        config: ``CCConfig`` section of the loaded ``AppConfig``.
        policy: Threshold policy; used to decide whether human approval is needed
                for the plan at the configured ``plan_review_approval_level``.
    """

    def __init__(
        self,
        subprocess_mgr: "CCSubprocessManager",
        approval_manager: "ApprovalManager",
        config: "CCConfig",
        policy: "ApprovalThresholdPolicy",
    ) -> None:
        self._subprocess_mgr = subprocess_mgr
        self._approval_manager = approval_manager
        self._config = config
        self._policy = policy

    async def review(
        self,
        task: str,
        project_path: Path,
        env: dict[str, str],
        requesting_agent: str = "system:cc_plan_reviewer",
        session_key: str = "cc:plan",
    ) -> PlanReviewResult:
        """Run the plan phase and return whether execution should proceed.

        Args:
            task:             Natural-language task description for the CC session.
            project_path:     Workspace project path; passed to the subprocess as
                              ``cwd`` and as the ``--add-dir`` fence.
            env:              Environment variables injected into the CC process
                              (from ``WorkspaceManager.get_env()``).
            requesting_agent: Identity for the approval request audit trail.
                              Override with the real agent_id when available.
            session_key:      Session key for the approval request audit trail.
                              Override with the real session key when available.

        Returns:
            ``PlanReviewResult(approved=True, plan=...)`` if the plan was approved
            or if plan review is disabled / not required by policy.
            ``PlanReviewResult(approved=False, plan=...)`` if the user denied or
            the request timed out.
        """
        if not self._config.plan_review_enabled:
            logger.info("CCPlanReviewer: plan review disabled — skipping (approved=True)")
            return PlanReviewResult(approved=True, plan=None)

        # --- Step 1: Spawn CC in read-only mode to produce the plan ---
        plan_prompt = _PLAN_PROMPT_PREFIX + task
        logger.info(
            "CCPlanReviewer: spawning read-only CC for plan phase — project=%s", project_path
        )

        cc_result = await self._subprocess_mgr.spawn(
            task=plan_prompt,
            project_path=project_path,
            allowed_tools=_PLAN_PHASE_TOOLS,
            env=env,
        )

        # Import here to avoid a top-level import cycle in the claude_code package.
        from openrattler.tools.claude_code.output_parser import CCOutputParser

        parser = CCOutputParser()
        parsed = parser.parse(cc_result.stdout)

        if parsed.error:
            logger.warning("CCPlanReviewer: plan-phase CC run returned an error: %s", parsed.error)
            # Surface the error as a denied plan so the calling tool can handle it.
            return PlanReviewResult(approved=False, plan=None)

        plan_text: str = parsed.result
        logger.info(
            "CCPlanReviewer: plan produced (len=%d chars) — checking policy", len(plan_text)
        )

        # --- Step 2: Check whether the plan level requires human approval ---
        if not self._policy.requires_approval(self._config.plan_review_approval_level):
            logger.info(
                "CCPlanReviewer: policy threshold=%d, plan_review_level=%d — "
                "no approval required; auto-approving",
                self._policy.threshold,
                self._config.plan_review_approval_level,
            )
            return PlanReviewResult(approved=True, plan=plan_text)

        # --- Step 3: Request human approval for the plan ---
        from openrattler.security.approval import ApprovalRequest

        request = ApprovalRequest(
            approval_id=str(uuid.uuid4()),
            operation="cc_plan_review",
            context={"plan": plan_text, "task": task},
            requesting_agent=requesting_agent,
            session_key=session_key,
            provenance={
                "source": "cc_plan_reviewer",
                "project_path": str(project_path),
                "plan_review_level": self._config.plan_review_approval_level,
            },
            timestamp=datetime.now(timezone.utc),
            timeout_seconds=self._config.plan_review_timeout_seconds,
            action_level=self._config.plan_review_approval_level,
            rationale=f"Plan for: {task}",
        )

        logger.info(
            "CCPlanReviewer: submitting plan for approval — approval_id=%s level=%d timeout=%ds",
            request.approval_id,
            request.action_level,
            request.timeout_seconds,
        )

        result = await self._approval_manager.request_approval(request)

        logger.info(
            "CCPlanReviewer: plan approval resolved — approved=%s decided_by=%s",
            result.approved,
            result.decided_by,
        )

        return PlanReviewResult(approved=result.approved, plan=plan_text)
