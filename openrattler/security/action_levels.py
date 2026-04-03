"""Action severity levels and dead-stop registry.

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
"""

from __future__ import annotations

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
        "force_push_main",
        "drop_table",
        "rm_workspace_recursive",
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
