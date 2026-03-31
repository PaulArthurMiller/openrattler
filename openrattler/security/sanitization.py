"""Public re-export of the injection-detection pattern set.

This module is the single import point for the suspicious-content pattern
catalogue used across all sanitization pipelines in OpenRattler.  The
pattern definitions live in ``openrattler.security.patterns``; this module
re-exports them so consumers always import from a stable, purpose-named
location rather than the lower-level pattern module.

Usage::

    from openrattler.security.sanitization import (
        SUSPICIOUS_PATTERNS,
        scan_for_suspicious_content,
    )

SECURITY NOTES
--------------
- Never duplicate ``SUSPICIOUS_PATTERNS`` in a consumer module — import
  from here so every pipeline shares the same pattern set and updates
  propagate everywhere automatically.
- ``SUSPICIOUS_PATTERNS`` is the authoritative list; additions should be
  made in ``openrattler.security.patterns``, not here.
"""

from openrattler.security.patterns import SUSPICIOUS_PATTERNS, scan_for_suspicious_content

__all__ = ["SUSPICIOUS_PATTERNS", "scan_for_suspicious_content"]
