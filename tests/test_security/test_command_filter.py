"""Tests for openrattler.security.command_filter.

These are critical security guarantees:
- Dangerous commands (mkfs, dd, format) are always denied
- High-risk commands (rm -rf, sudo) always require approval
- Shell injection patterns (pipe to sh, command substitution) are denied
- The CommandFilter class is configurable without affecting global defaults
"""

from __future__ import annotations

import pytest

from openrattler.security.command_filter import (
    DANGEROUS_COMMANDS,
    CommandFilter,
    filter_command,
)

# ---------------------------------------------------------------------------
# Module-level convenience function (uses default rules)
# ---------------------------------------------------------------------------


class TestDefaultFilterCommand:
    """Tests for the module-level filter_command convenience function."""

    def test_safe_command_allowed(self) -> None:
        """A known-safe command like 'ls' is allowed without approval."""
        action, needs_approval, reason = filter_command("ls", ["-la"])
        assert action == "allow"
        assert needs_approval is False
        assert reason is None

    def test_rm_rf_requires_approval(self) -> None:
        """rm with -rf requires approval."""
        action, needs_approval, reason = filter_command("rm", ["-rf", "/tmp/foo"])
        assert action == "approve"
        assert needs_approval is True
        assert reason is not None

    def test_rm_recursive_requires_approval(self) -> None:
        """rm with -r requires approval."""
        action, needs_approval, reason = filter_command("rm", ["-r", "/tmp/foo"])
        assert action == "approve"
        assert needs_approval is True

    def test_rm_plain_file_allowed(self) -> None:
        """rm of a single file (no -r or * args) is allowed without approval."""
        action, needs_approval, reason = filter_command("rm", ["myfile.txt"])
        assert action == "allow"
        assert needs_approval is False

    def test_mkfs_denied_outright(self) -> None:
        """mkfs is denied — no approval path exists."""
        action, needs_approval, reason = filter_command("mkfs", ["/dev/sda1"])
        assert action == "deny"
        assert needs_approval is False
        assert reason is not None

    def test_dd_denied_outright(self) -> None:
        """dd is denied — destructive disk operation."""
        action, needs_approval, reason = filter_command("dd", ["if=/dev/urandom", "of=/dev/sda"])
        assert action == "deny"

    def test_format_denied_outright(self) -> None:
        """format is denied outright."""
        action, needs_approval, reason = filter_command("format", ["C:"])
        assert action == "deny"

    def test_sudo_requires_approval(self) -> None:
        """sudo always requires approval (no check_args restriction)."""
        action, needs_approval, reason = filter_command("sudo", ["apt", "install", "pkg"])
        assert action == "approve"
        assert needs_approval is True

    def test_chmod_777_requires_approval(self) -> None:
        """chmod with 777 requires approval."""
        action, needs_approval, reason = filter_command("chmod", ["777", "/etc/shadow"])
        assert action == "approve"
        assert needs_approval is True

    def test_chmod_plain_allowed(self) -> None:
        """chmod with a non-dangerous mode is allowed without approval."""
        action, needs_approval, reason = filter_command("chmod", ["644", "file.txt"])
        assert action == "allow"

    def test_pipe_to_sh_denied(self) -> None:
        """A command containing '| sh' matches the dangerous pattern and is denied."""
        action, needs_approval, reason = filter_command("cat", ["file.txt", "|", "sh"])
        assert action == "deny"

    def test_redirect_to_dev_denied(self) -> None:
        """Redirection to a device file is denied."""
        action, needs_approval, reason = filter_command("echo", ["data", ">", "/dev/sda"])
        assert action == "deny"

    def test_command_substitution_dollar_paren_denied(self) -> None:
        """$(command) substitution in args is denied."""
        action, needs_approval, reason = filter_command("echo", ["$(cat /etc/passwd)"])
        assert action == "deny"

    def test_command_substitution_backtick_denied(self) -> None:
        """Backtick command substitution in args is denied."""
        action, needs_approval, reason = filter_command("echo", ["`whoami`"])
        assert action == "deny"

    def test_case_insensitive_deny(self) -> None:
        """Command names are matched case-insensitively."""
        action, _, _ = filter_command("MKFS", ["/dev/sdb"])
        assert action == "deny"

    def test_case_insensitive_approve(self) -> None:
        """Approval checks are also case-insensitive."""
        action, needs_approval, _ = filter_command("SUDO", ["ls"])
        assert action == "approve"
        assert needs_approval is True


# ---------------------------------------------------------------------------
# CommandFilter class (configurable rules)
# ---------------------------------------------------------------------------


class TestCommandFilterClass:
    """Tests for the configurable CommandFilter class."""

    def test_custom_deny_rule_added(self) -> None:
        """A user-added deny rule is enforced."""
        cf = CommandFilter()
        cf.add_rule("curl", {"deny": True})
        action, _, _ = cf.filter_command("curl", ["https://evil.com"])
        assert action == "deny"

    def test_custom_approve_rule_added(self) -> None:
        """A user-added approval rule is enforced."""
        cf = CommandFilter()
        cf.add_rule("wget", {"approval_required": True})
        action, needs_approval, _ = cf.filter_command("wget", ["http://example.com"])
        assert action == "approve"
        assert needs_approval is True

    def test_rule_removed(self) -> None:
        """Removing a rule causes the command to fall through to the default (allow)."""
        cf = CommandFilter()
        cf.remove_rule("mkfs")
        action, _, _ = cf.filter_command("mkfs", ["/dev/sda1"])
        assert action == "allow"

    def test_remove_nonexistent_rule_is_silent(self) -> None:
        """Removing a rule that doesn't exist does not raise."""
        cf = CommandFilter()
        cf.remove_rule("nonexistent_command")  # should not raise

    def test_custom_pattern_added(self) -> None:
        """A user-added pattern is enforced against the full command string."""
        cf = CommandFilter()
        cf.add_pattern(r"evil\.com")
        action, _, _ = cf.filter_command("curl", ["evil.com"])
        assert action == "deny"

    def test_global_default_not_mutated_by_add_rule(self) -> None:
        """Mutations to a CommandFilter instance do not affect DANGEROUS_COMMANDS."""
        cf = CommandFilter()
        cf.add_rule("curl", {"deny": True})
        assert "curl" not in DANGEROUS_COMMANDS

    def test_global_default_not_mutated_by_add_pattern(self) -> None:
        """Adding a pattern to a CommandFilter does not affect DANGEROUS_COMMANDS."""
        original_patterns = list(DANGEROUS_COMMANDS["patterns"])  # type: ignore[arg-type]
        cf = CommandFilter()
        cf.add_pattern(r"totally_custom_pattern")
        assert DANGEROUS_COMMANDS["patterns"] == original_patterns  # type: ignore[index]

    def test_two_instances_are_independent(self) -> None:
        """Two CommandFilter instances with separate rules do not interfere."""
        cf1 = CommandFilter()
        cf2 = CommandFilter()
        cf1.add_rule("curl", {"deny": True})
        # cf2 should not be affected by cf1's mutation
        action, _, _ = cf2.filter_command("curl", ["https://example.com"])
        assert action == "allow"

    def test_custom_rules_override_default(self) -> None:
        """Passing a fully custom rules dict replaces defaults entirely."""
        cf = CommandFilter(rules={"ls": {"deny": True}})
        # ls is now denied in this instance
        action, _, _ = cf.filter_command("ls", [])
        assert action == "deny"
        # mkfs is no longer in the rules — should be allowed
        action, _, _ = cf.filter_command("mkfs", ["/dev/sda1"])
        assert action == "allow"
