"""Path, session key, and agent ID sanitization utilities.

These helpers are called at every trust boundary where external strings are
used as filesystem paths or routing identifiers.  The functions raise
``ValueError`` on any suspicious input so callers can handle errors uniformly
without catching unexpected exception types.

SECURITY NOTES
--------------
- ``sanitize_path`` resolves symlinks (``Path.resolve()``) before checking
  containment, so a symlink inside an allowed directory that points outside it
  is rejected.
- ``sanitize_session_key`` uses an allowlist regex — only the characters
  ``[a-zA-Z0-9_-:]`` are permitted, preventing shell injection, SQL injection,
  and path injection via session keys.
- ``validate_agent_id`` uses a stricter allowlist that forbids colons, keeping
  agent IDs as simple single-segment identifiers.
"""

from __future__ import annotations

import re
from pathlib import Path

# ---------------------------------------------------------------------------
# Compiled patterns (module-level for efficiency)
# ---------------------------------------------------------------------------

#: Session keys must have at least three colon-separated segments, each
#: containing only alphanumeric characters, hyphens, or underscores.
#: Examples: ``agent:main:main``, ``agent:main:telegram:group:123``
_SESSION_KEY_RE: re.Pattern[str] = re.compile(r"^[a-zA-Z0-9_-]+(:[a-zA-Z0-9_-]+){2,}$")

#: Agent IDs are simple single-segment identifiers — no colons, no slashes.
#: Examples: ``main``, ``local``, ``my-agent``, ``agent_123``
_AGENT_ID_RE: re.Pattern[str] = re.compile(r"^[a-zA-Z0-9_-]+$")


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def sanitize_path(path: str, allowed_dirs: list[Path]) -> Path:
    """Resolve *path* to an absolute ``Path`` and verify it is inside *allowed_dirs*.

    Args:
        path:         Raw path string (may be relative or absolute).
        allowed_dirs: Non-empty list of trusted root directories.  At least
                      one directory must contain the resolved path.

    Returns:
        The resolved absolute ``Path`` object.

    Raises:
        ValueError: If *path* is empty, contains a ``..`` traversal component,
                    or resolves to a location outside every allowed directory.

    Security notes:
    - The explicit ``..`` check fails fast with a clear message before
      ``resolve()`` is called.
    - ``Path.resolve()`` follows symlinks, so a symlink inside an allowed
      directory that points outside it is caught by the containment check.
    - Containment is verified with ``relative_to``, which raises ``ValueError``
      when the path is not a descendant of the candidate root.
    """
    if not path:
        raise ValueError("path must not be empty")

    # Explicit traversal component check — defense-in-depth before resolve().
    if ".." in Path(path).parts:
        raise ValueError(f"path traversal detected in {path!r}")

    resolved = Path(path).resolve()

    for allowed in allowed_dirs:
        resolved_allowed = allowed.resolve()
        try:
            resolved.relative_to(resolved_allowed)
            return resolved
        except ValueError:
            continue

    raise ValueError(f"path {path!r} (resolved: {resolved}) is outside all allowed directories")


def sanitize_session_key(key: str) -> str:
    """Validate and return *key* if it matches the expected session key format.

    Valid examples::

        agent:main:main
        agent:main:telegram:group:123
        agent:main:subagent:abc-123

    Args:
        key: Raw session key string.

    Returns:
        The original *key* unchanged if valid.

    Raises:
        ValueError: If the key is empty, uses invalid characters, or does not
                    contain at least three colon-separated segments.

    Security notes:
    - The allowlist regex rejects semicolons, slashes, spaces, and all other
      characters that could be used for injection or path manipulation.
    - At least three segments are required (e.g. ``type:scope:context``),
      which is the minimum meaningful session key.
    """
    if not key:
        raise ValueError("session key must not be empty")
    if not _SESSION_KEY_RE.match(key):
        raise ValueError(
            f"invalid session key {key!r}: must be 3+ colon-separated "
            "alphanumeric/hyphen/underscore segments"
        )
    return key


def validate_agent_id(agent_id: str) -> str:
    """Validate and return *agent_id* if it matches the expected format.

    Valid examples::

        main
        local
        my-agent
        agent_123

    Args:
        agent_id: Raw agent ID string.

    Returns:
        The original *agent_id* unchanged if valid.

    Raises:
        ValueError: If the ID is empty or contains characters outside
                    ``[a-zA-Z0-9_-]``.

    Security notes:
    - Colons are explicitly excluded so agent IDs cannot be mistaken for
      session keys and cannot embed routing sequences.
    - The allowlist is identical to the ``_SAFE_COMPONENT`` pattern used in
      ``openrattler.gateway.router`` for consistency.
    """
    if not agent_id:
        raise ValueError("agent_id must not be empty")
    if not _AGENT_ID_RE.match(agent_id):
        raise ValueError(
            f"invalid agent_id {agent_id!r}: only alphanumeric characters, "
            "hyphens, and underscores are allowed"
        )
    return agent_id
