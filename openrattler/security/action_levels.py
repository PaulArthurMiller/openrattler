"""Action severity levels, dead-stop registry, and approval threshold policy.

Action levels are integer constants (1–5) assigned to every registered tool.
They express how dangerous or consequential an action is:

    1 — Permanent, irreversible, or has financial cost
        (e.g. delete files permanently, send email, drop a database table)
    2 — Significant external action, hard to reverse
        (e.g. send SMS/Slack, push to a remote branch, write to an external API)
    3 — Moderate — modifies local state
        (e.g. write a file, update agent memory, modify configuration)
    4 — Low impact — accesses sensitive cross-agent state
        (e.g. read another session's transcript, create a new session)
    5 — Minimal — read-only or fully sandboxed
        (e.g. read a file, list a directory, read the memory store)

The default for any tool that does not declare a level is 5 — the safest
possible value.  Tools must opt in to lower (more dangerous) levels explicitly.

DEAD_STOP_ACTIONS
-----------------
A compile-time ``frozenset[str]`` of action names that may never execute under
any circumstances.  No config key can lower the threshold to permit them — the
check is in code, not in policy.  This is the same design as
``AUTHORIZED_SPAWNERS`` in ``creator_validator.py``.

DeadStopError
-------------
Raised when a dead-stop action is attempted.  Carries the action name so the
caller can audit-log which action was blocked before surfacing the error.

ApprovalThresholdPolicy
-----------------------
The policy object that decides whether a given action level requires approval.
A tool at level N requires approval if ``N <= policy.threshold``.

Profile → default threshold mapping:
    paranoid → 5  (all tools require approval, including read-only)
    standard → 3  (level 1–3 require approval; level 4–5 are auto-approved)
    minimal  → 1  (only permanent/irreversible actions require approval)

The threshold can be overridden by ``SecurityConfig.approval_threshold``; an
explicit threshold always takes precedence over the profile default.

Use ``ApprovalThresholdPolicy.from_security_config()`` to build the policy at
startup from the loaded ``AppConfig``.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from openrattler.config.loader import SecurityConfig

# ---------------------------------------------------------------------------
# Level descriptions
# ---------------------------------------------------------------------------

#: Human-readable label for each action level.  Keys are 1 (most dangerous) to
#: 5 (safest).  These strings are shown to users in approval prompts.
ACTION_LEVEL_DESCRIPTIONS: dict[int, str] = {
    1: "Permanent, irreversible, or has financial cost",
    2: "Significant external action — hard to reverse",
    3: "Moderate — modifies local state",
    4: "Low impact — accesses sensitive cross-agent state",
    5: "Minimal — read-only or sandboxed",
}

# ---------------------------------------------------------------------------
# Dead stop registry
# ---------------------------------------------------------------------------

#: Actions that may never execute regardless of config or approval.
#: This is a compile-time constant — it is never read from config and cannot
#: be overridden by any policy setting.
DEAD_STOP_ACTIONS: frozenset[str] = frozenset(
    {
        # Core dead stops
        "force_push_main",
        "drop_table",
        "rm_workspace_recursive",
        # Claude Code integration — CC may never bypass its permission model or
        # push directly to main.  These are sentinel tool names; if an agent ever
        # constructs a call to either, the dead-stop check fires before any
        # subprocess is spawned.
        "cc_bypass_permissions",
        "cc_push_main",
    }
)

# ---------------------------------------------------------------------------
# Heartbeat auto-approve registry
# ---------------------------------------------------------------------------

#: Operations automatically approved during heartbeat sessions when
#: ``HeartbeatConfig.bypass_approval`` is True.  Heartbeat turns are designed
#: to send at most one outbound message and update working memory, so these
#: operations are pre-authorized in that context.  All other operations still
#: go through the normal approval gate.
HEARTBEAT_AUTO_APPROVE_OPERATIONS: frozenset[str] = frozenset(
    {
        "send_slack_message",
        "send_email",
        "send_sms",
        "update_memory_narrative",
        "memory_write",
    }
)

# ---------------------------------------------------------------------------
# DeadStopError
# ---------------------------------------------------------------------------


class DeadStopError(Exception):
    """Raised when an agent attempts to invoke a dead-stop action.

    Dead-stop actions are listed in ``DEAD_STOP_ACTIONS`` and may never run
    under any circumstances — no approval flow is triggered, no handler is
    called.  The action name is carried on the exception so callers can
    audit-log the blocked attempt.

    Args:
        action: The name of the action that was blocked.
    """

    def __init__(self, action: str) -> None:
        self.action = action
        super().__init__(
            f"Action '{action}' is a dead-stop action and may never execute. "
            f"It is hardcoded in DEAD_STOP_ACTIONS and cannot be overridden by "
            f"any configuration or approval."
        )


# ---------------------------------------------------------------------------
# ApprovalThresholdPolicy
# ---------------------------------------------------------------------------

#: Default approval threshold for each security profile.
#: Tools with action_level <= threshold require human approval.
#:
#: - paranoid → 5: all tools require approval (even read-only)
#: - standard → 3: level 1–3 require approval (permanent, external, local writes)
#: - minimal  → 1: only level-1 actions require approval (permanent/irreversible)
_PROFILE_THRESHOLDS: dict[str, int] = {
    "paranoid": 5,
    "standard": 3,
    "minimal": 1,
}


class ApprovalThresholdPolicy:
    """Decides whether a given action level requires human approval.

    A tool at level N requires approval if ``N <= self.threshold``.  The
    threshold is resolved from the security profile at startup; it can be
    overridden by ``SecurityConfig.approval_threshold`` in the user's config.

    Args:
        threshold: The resolved threshold.  Tools with ``action_level <= threshold``
                   will trigger the approval gate.

    Security notes:
    - A higher threshold means *more* tools require approval (paranoid = 5).
    - A lower threshold means *fewer* tools require approval (minimal = 1).
    - The threshold is a policy dial — it does not replace the dead-stop check,
      which runs unconditionally before the threshold is consulted.

    Example::

        policy = ApprovalThresholdPolicy(threshold=3)
        policy.requires_approval(1)  # True  — permanent/irreversible
        policy.requires_approval(3)  # True  — at threshold
        policy.requires_approval(4)  # False — above threshold
        policy.requires_approval(5)  # False — read-only, safest
    """

    def __init__(self, threshold: int) -> None:
        if not (1 <= threshold <= 5):
            raise ValueError(
                f"ApprovalThresholdPolicy threshold must be between 1 and 5 (got {threshold})"
            )
        self.threshold = threshold

    def requires_approval(self, level: int) -> bool:
        """Return ``True`` if a tool at *level* must pass through the approval gate.

        Args:
            level: The tool's ``action_level`` (1=most dangerous, 5=safest).

        Returns:
            ``True`` when ``level <= self.threshold``; ``False`` otherwise.
        """
        return level <= self.threshold

    @classmethod
    def from_security_config(cls, config: "SecurityConfig") -> "ApprovalThresholdPolicy":
        """Build a policy from a ``SecurityConfig``.

        Resolution order:
        1. If ``config.approval_threshold`` is set (not None), use it directly.
        2. Otherwise look up the profile's default from ``_PROFILE_THRESHOLDS``.
        3. If the profile is unrecognised, fall back to ``standard`` (threshold 3).

        Args:
            config: The ``SecurityConfig`` section of the loaded ``AppConfig``.

        Returns:
            A new ``ApprovalThresholdPolicy`` with the resolved threshold.
        """
        # Explicit override takes priority.
        if config.approval_threshold is not None:
            return cls(threshold=config.approval_threshold)

        # Derive from the profile name; fall back to standard if unknown.
        profile = config.profile
        threshold = _PROFILE_THRESHOLDS.get(profile, _PROFILE_THRESHOLDS["standard"])
        return cls(threshold=threshold)
