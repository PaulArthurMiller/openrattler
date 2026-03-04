"""Command filtering — classify shell commands as allow / approve / deny.

This module is intentionally conservative: commands in the deny list are
rejected outright; commands in the approval list require human review;
everything else is allowed.  Callers that prefer a deny-by-default policy
should additionally check the command against an explicit allowlist before
calling this module.

``CommandFilter`` is configurable so users can tighten or relax rules to
match their threat model without forking the core.

SECURITY NOTES
--------------
- Pattern checks run against the *full* command string (``cmd + args``), not
  just the command name.  This catches injection embedded in arguments such
  as ``echo $(cat /etc/passwd)``.
- All string comparisons are case-insensitive (``re.IGNORECASE`` / lower()).
  so ``RM``, ``Rm``, etc. are treated identically to ``rm``.
- ``check_args`` entries for approval-required commands are matched as exact
  argument strings.  Callers should normalise argument forms (e.g. split
  ``-rf`` into ``-r -f``) before calling if that matters for their use case.
- Mutations to a ``CommandFilter`` instance do **not** affect the module-level
  ``DANGEROUS_COMMANDS`` constant or any other instance.
"""

from __future__ import annotations

import copy
import re
from typing import Any, Optional

# ---------------------------------------------------------------------------
# Default command rules (mirrors SECURITY.md §5 "Command Filtering")
# ---------------------------------------------------------------------------

#: Default dangerous-command definitions.
#: Keys are lowercase command names (or the special key ``"patterns"``).
#: Values are rule dicts with the following optional keys:
#:   ``deny``              – bool, if True the command is rejected outright.
#:   ``approval_required`` – bool, if True the command requires human approval.
#:   ``check_args``        – list[str], approval is only required when at least
#:                           one of these strings appears in the args list.
#:                           If absent or empty, approval is always required.
#: The ``"patterns"`` key holds a list of regex strings applied to the full
#: command string (cmd + joined args); a match triggers an outright deny.
DANGEROUS_COMMANDS: dict[str, Any] = {
    # ------------------------------------------------------------------
    # Outright deny — destructive with no legitimate agent use-case
    # ------------------------------------------------------------------
    "mkfs": {"deny": True},
    "dd": {"deny": True},
    "format": {"deny": True},
    # ------------------------------------------------------------------
    # Require approval — powerful but may have legitimate uses
    # ------------------------------------------------------------------
    "rm": {
        "approval_required": True,
        "check_args": ["-rf", "-r", "*"],
    },
    "sudo": {
        "approval_required": True,
    },
    "chmod": {
        "approval_required": True,
        "check_args": ["777", "666"],
    },
    # ------------------------------------------------------------------
    # Dangerous patterns that apply to ANY command string
    # ------------------------------------------------------------------
    "patterns": [
        r">\s*/dev/",  # Redirect output to a device
        r"\|\s*sh\b",  # Pipe to shell
        r"`[^`]*`",  # Command substitution (backtick form)
        r"\$\([^)]*\)",  # Command substitution ($(...) form)
    ],
}


# ---------------------------------------------------------------------------
# CommandFilter class
# ---------------------------------------------------------------------------


class CommandFilter:
    """Classifies shell commands as ``"allow"`` / ``"approve"`` / ``"deny"``.

    One instance is created per security context.  The instance's rules can be
    adjusted at runtime via ``add_rule``, ``remove_rule``, and ``add_pattern``.

    Args:
        rules: Override the initial rule set.  If ``None`` the global
               ``DANGEROUS_COMMANDS`` dict is deep-copied as the starting
               configuration so that mutations to the instance never affect
               the module-level constant.

    Security notes:
    - Pattern checks are evaluated before per-command rules so that a
      safe-looking command with an injected argument is caught first.
    - Unknown commands default to ``"allow"`` (no approval required).
    - The ``check_args`` mechanism is intentionally simple — it checks for
      exact string membership in the args list.  Complex argument parsing
      (e.g. splitting combined flags like ``-rf``) is the caller's
      responsibility.
    """

    def __init__(self, rules: Optional[dict[str, Any]] = None) -> None:
        self._rules: dict[str, Any] = copy.deepcopy(DANGEROUS_COMMANDS if rules is None else rules)

    # ------------------------------------------------------------------
    # Configuration helpers
    # ------------------------------------------------------------------

    def add_rule(self, command: str, rule: dict[str, Any]) -> None:
        """Add or replace the rule for *command* (case-insensitive)."""
        self._rules[command.lower()] = rule

    def remove_rule(self, command: str) -> None:
        """Remove the rule for *command* (silently ignored if not present)."""
        self._rules.pop(command.lower(), None)

    def add_pattern(self, pattern: str) -> None:
        """Append a dangerous regex *pattern* to the pattern list."""
        patterns = self._rules.get("patterns")
        if isinstance(patterns, list):
            patterns.append(pattern)
        else:
            self._rules["patterns"] = [pattern]

    # ------------------------------------------------------------------
    # Main entry point
    # ------------------------------------------------------------------

    def filter_command(
        self,
        cmd: str,
        args: list[str],
    ) -> tuple[str, bool, Optional[str]]:
        """Classify a command invocation.

        Args:
            cmd:  The command name (e.g. ``"rm"``).
            args: List of argument strings (e.g. ``["-rf", "/tmp"]``).

        Returns:
            A 3-tuple ``(action, needs_approval, reason)`` where:

            - *action* is one of:

              - ``"allow"``   — safe to execute without approval.
              - ``"approve"`` — execution requires explicit human approval.
              - ``"deny"``    — must not be executed.

            - *needs_approval* is ``True`` when *action* is ``"approve"``,
              ``False`` otherwise (convenience flag for callers).

            - *reason* is a human-readable explanation string, or ``None``
              when *action* is ``"allow"``.

        Security notes:
        - Pattern checks run first so injected arguments are caught even when
          the base command looks safe.
        - The full string used for pattern matching is
          ``cmd + " " + " ".join(args)`` (stripped of leading/trailing space).
        - All command-name lookups are case-insensitive.
        """
        cmd_lower = cmd.lower().strip()
        full_str = (cmd + " " + " ".join(args)).strip()

        # 1. Check dangerous patterns against the full command string.
        patterns: list[str] = self._rules.get("patterns", [])
        for pattern in patterns:
            if re.search(pattern, full_str, re.IGNORECASE):
                return (
                    "deny",
                    False,
                    f"Command matches dangerous pattern: {pattern!r}",
                )

        # 2. Check per-command rules.
        rule: Optional[dict[str, Any]] = self._rules.get(cmd_lower)
        if rule is not None:
            if rule.get("deny"):
                return "deny", False, f"Command {cmd!r} is not permitted"

            if rule.get("approval_required"):
                check_args: list[str] = rule.get("check_args", [])
                # If check_args is empty, always require approval.
                # If check_args is non-empty, only require approval when at
                # least one of the checked args is present.
                if not check_args or any(arg in args for arg in check_args):
                    return (
                        "approve",
                        True,
                        f"Command {cmd!r} requires approval",
                    )

        # 3. Default: allow.
        return "allow", False, None


# ---------------------------------------------------------------------------
# Module-level convenience function
# ---------------------------------------------------------------------------

#: Shared default filter — uses the default ``DANGEROUS_COMMANDS`` rules.
#: Do not mutate this instance; create a new ``CommandFilter`` for custom rules.
_default_filter: CommandFilter = CommandFilter()


def filter_command(cmd: str, args: list[str]) -> tuple[str, bool, Optional[str]]:
    """Classify *cmd* / *args* using the default ``DANGEROUS_COMMANDS`` rules.

    This is a convenience wrapper around ``CommandFilter().filter_command()``.
    For custom rule sets, instantiate ``CommandFilter`` directly.

    Returns:
        ``(action, needs_approval, reason)`` — see ``CommandFilter.filter_command``.
    """
    return _default_filter.filter_command(cmd, args)
