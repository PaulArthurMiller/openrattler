"""Built-in file operation tools: file_read, file_write, file_list.

SECURITY MODEL
--------------
All paths are validated against a module-level allowlist of directories before
any I/O is performed.  This prevents:

* **Path traversal** — paths containing ``..`` are rejected immediately, before
  resolution, so the allowlist check is never reached with a deceptive path.
* **Escape from the allowlist** — after ``..``-free resolution the absolute path
  must be ``relative_to`` at least one allowed directory; otherwise the operation
  is denied.
* **Oversized reads** — ``file_read`` rejects files larger than the configured
  size limit (default 1 MB) to prevent memory exhaustion.

The allowlist is intentionally empty by default so that importing this module
cannot read or write any file until an explicit call to
``configure_allowed_directories`` has been made.
"""

from __future__ import annotations

import asyncio
from pathlib import Path
from typing import Optional

from openrattler.models.agents import TrustLevel
from openrattler.tools.registry import tool

# ---------------------------------------------------------------------------
# Module-level configuration
# ---------------------------------------------------------------------------

_ALLOWED_DIRS: list[Path] = []
_MAX_FILE_SIZE: int = 1024 * 1024  # 1 MB


def configure_allowed_directories(
    dirs: list[Path | str],
    *,
    max_file_size: int = 1024 * 1024,
) -> None:
    """Set the directories that file operations are permitted to access.

    Args:
        dirs:          Paths to allow.  Each is resolved to an absolute path.
        max_file_size: Maximum file size in bytes for ``file_read``; defaults
                       to 1 MB.  Pass ``0`` to disable the limit.

    Security note:
        Pass an empty list to disable all file access (the default state).
    """
    global _ALLOWED_DIRS, _MAX_FILE_SIZE
    _ALLOWED_DIRS = [Path(d).resolve() for d in dirs]
    _MAX_FILE_SIZE = max_file_size


# ---------------------------------------------------------------------------
# Path validation helper
# ---------------------------------------------------------------------------


def _validate_path(raw: str) -> Path:
    """Resolve *raw* and verify it falls within an allowed directory.

    Args:
        raw: The raw path string supplied by the LLM or caller.

    Returns:
        The fully-resolved ``Path``.

    Raises:
        ValueError: If the path contains ``..``, resolves outside all allowed
                    directories, or no allowed directories are configured.
    """
    # Reject traversal sequences before any resolution.
    if ".." in Path(raw).parts:
        raise ValueError(f"Path traversal rejected: {raw!r}")

    resolved = Path(raw).resolve()

    if not _ALLOWED_DIRS:
        raise ValueError(
            "No allowed directories configured; file access is disabled. "
            "Call configure_allowed_directories() first."
        )

    for allowed in _ALLOWED_DIRS:
        try:
            resolved.relative_to(allowed)
            return resolved
        except ValueError:
            continue

    raise ValueError(f"Path {raw!r} (resolved: {resolved}) is outside all allowed directories.")


# ---------------------------------------------------------------------------
# Built-in file tools
# ---------------------------------------------------------------------------


@tool(
    trust_level_required=TrustLevel.main,
    security_notes=(
        "Path traversal mitigation: '..' is rejected before resolution; "
        "resolved path must be within a configured allowed directory. "
        "File size is capped at the configured limit (default 1 MB)."
    ),
)
async def file_read(path: str) -> str:
    """Read a file from an allowed directory and return its text content.

    SECURITY:
    - Path must be within a configured allowed directory.
    - Paths containing '..' are rejected before resolution.
    - Files exceeding the configured size limit are rejected.
    - Trust level required: main.
    """
    safe_path = _validate_path(path)

    def _read() -> str:
        size = safe_path.stat().st_size
        if _MAX_FILE_SIZE and size > _MAX_FILE_SIZE:
            raise ValueError(f"File too large: {size} bytes (limit: {_MAX_FILE_SIZE} bytes).")
        return safe_path.read_text(encoding="utf-8")

    return await asyncio.to_thread(_read)


@tool(
    trust_level_required=TrustLevel.main,
    requires_approval=True,
    security_notes=(
        "Path traversal mitigation applied. "
        "Writes are atomic (temp file + Path.replace()). "
        "Requires human approval before execution."
    ),
)
async def file_write(path: str, content: str) -> str:
    """Write text content to a file in an allowed directory.

    SECURITY:
    - Path must be within a configured allowed directory.
    - Paths containing '..' are rejected before resolution.
    - Writes are atomic: content is written to a temp file then renamed.
    - Trust level required: main.  Requires human approval.
    """
    safe_path = _validate_path(path)

    def _write() -> None:
        safe_path.parent.mkdir(parents=True, exist_ok=True)
        tmp = safe_path.with_suffix(safe_path.suffix + ".tmp")
        tmp.write_text(content, encoding="utf-8")
        tmp.replace(safe_path)

    await asyncio.to_thread(_write)
    return f"Written {len(content)} characters to {safe_path}."


@tool(
    trust_level_required=TrustLevel.main,
    security_notes=(
        "Path traversal mitigation applied. "
        "Only directories within the configured allowlist are accessible."
    ),
)
async def file_list(directory: str) -> list[str]:
    """List the entries in a directory within an allowed directory.

    Returns a sorted list of entry names (not full paths).

    SECURITY:
    - Directory must be within a configured allowed directory.
    - Paths containing '..' are rejected before resolution.
    - Trust level required: main.
    """
    safe_dir = _validate_path(directory)

    def _list() -> list[str]:
        if not safe_dir.is_dir():
            raise ValueError(f"Not a directory: {directory!r}")
        return sorted(entry.name for entry in safe_dir.iterdir())

    return await asyncio.to_thread(_list)
