"""CLI entry point — openrattler init / chat / run / sessions list / auth.

Usage (after ``pip install -e .``)::

    openrattler init                # create workspace, default config
    openrattler chat                # start interactive chat
    openrattler run                 # start full production server
    openrattler sessions list       # list all session keys
    openrattler auth google         # run Google OAuth consent flow
    openrattler auth google --reauthorize  # force re-authorisation

Or directly::

    python -m openrattler init
    python -m openrattler chat
    python -m openrattler run

SECURITY NOTES
--------------
- ``init`` creates ``~/.openrattler`` with ``mode=0o700`` so only the owning
  user can read or write the directory.
- ``chat`` never prints the config file contents; API keys remain private.
- ``run`` reads ``OPENRATTLER_WS_SECRET`` for the Gateway token secret.
- ``auth google`` reads the passphrase from ``GOOGLE_OAUTH_PASSPHRASE`` (env
  var) so automated restarts do not require interactive input.
"""

from __future__ import annotations

import argparse
import asyncio
import sys
from pathlib import Path

from openrattler.cli.chat import DEFAULT_WORKSPACE, CLIChat
from openrattler.config.loader import DEFAULT_CONFIG_PATH, AppConfig, save_config

# ---------------------------------------------------------------------------
# Workspace initialisation
# ---------------------------------------------------------------------------


def init_workspace(workspace_dir: Path = DEFAULT_WORKSPACE) -> None:
    """Create the OpenRattler workspace directory structure.

    Creates the following layout (relative to *workspace_dir*)::

        <workspace_dir>/          # 0o700
          config.json             # default AppConfig (written only if absent)
          sessions/               # JSONL transcripts
          memory/                 # JSON memory files
          audit/                  # JSONL audit log

    If the workspace already exists this function is a no-op for each item
    that is already present (idempotent).

    Args:
        workspace_dir: Root directory.  Defaults to ``~/.openrattler``.

    Security notes:
    - The workspace root is created with ``mode=0o700`` (user-only access)
      to protect API keys, transcripts, and audit logs from other local users.
    - Subdirectories inherit the parent's permissions from the OS.
    """
    workspace_dir.mkdir(parents=True, exist_ok=True, mode=0o700)

    for subdir in ("sessions", "memory", "audit"):
        (workspace_dir / subdir).mkdir(exist_ok=True)

    config_path = workspace_dir / "config.json"
    if not config_path.exists():
        save_config(AppConfig(), config_path)
        print(f"Created default config: {config_path}")
    else:
        print(f"Config already exists: {config_path}")

    print(f"Workspace ready: {workspace_dir}")


# ---------------------------------------------------------------------------
# Session listing
# ---------------------------------------------------------------------------


def list_sessions(workspace_dir: Path = DEFAULT_WORKSPACE) -> list[str]:
    """Return all session keys found in *workspace_dir*/sessions/.

    Walks the sessions directory and converts JSONL file paths back to
    session keys (``agent/main/main.jsonl`` → ``"agent:main:main"``).

    Args:
        workspace_dir: Root workspace directory.  Defaults to ``~/.openrattler``.

    Returns:
        Sorted list of session key strings.  Empty list if no sessions exist.
    """
    sessions_dir = workspace_dir / "sessions"
    if not sessions_dir.exists():
        return []

    keys: list[str] = []
    for jsonl_file in sessions_dir.rglob("*.jsonl"):
        relative = jsonl_file.relative_to(sessions_dir)
        parts = list(relative.parts)
        parts[-1] = parts[-1].removesuffix(".jsonl")
        keys.append(":".join(parts))
    return sorted(keys)


# ---------------------------------------------------------------------------
# CLI subcommand handlers
# ---------------------------------------------------------------------------


def _cmd_init(args: argparse.Namespace) -> None:
    workspace = Path(args.workspace) if args.workspace else DEFAULT_WORKSPACE
    init_workspace(workspace)


def _cmd_chat(args: argparse.Namespace) -> None:
    workspace = Path(args.workspace) if args.workspace else DEFAULT_WORKSPACE
    config_path = Path(args.config) if args.config else DEFAULT_CONFIG_PATH
    chat = CLIChat(workspace_dir=workspace, config_path=config_path)
    asyncio.run(chat.start())


def _cmd_run(args: argparse.Namespace) -> None:
    import asyncio
    import logging as _logging

    _logging.basicConfig(
        level=_logging.INFO,
        format="%(asctime)s %(name)s %(levelname)s %(message)s",
        datefmt="%H:%M:%S",
    )

    from openrattler.startup import build_application

    workspace = Path(args.workspace) if args.workspace else DEFAULT_WORKSPACE
    config_path = Path(args.config) if args.config else DEFAULT_CONFIG_PATH

    async def _run() -> None:
        ctx = await build_application(
            workspace_dir=workspace,
            config_path=config_path,
            gateway_host=args.host,
            gateway_port=args.port,
            start_gateway=True,
        )
        await ctx.run_until_interrupted()

    try:
        asyncio.run(_run())
    except KeyboardInterrupt:
        pass


def _cmd_sessions_list(args: argparse.Namespace) -> None:
    workspace = Path(args.workspace) if args.workspace else DEFAULT_WORKSPACE
    keys = list_sessions(workspace)
    if keys:
        for key in keys:
            print(key)
    else:
        print("No sessions found.")


async def _cmd_auth_google_async(args: argparse.Namespace) -> None:
    """Run the Google OAuth consent flow (async implementation)."""
    from openrattler.auth.google_oauth import AuthorizationError, GoogleCredentialManager

    workspace = Path(args.workspace) if args.workspace else DEFAULT_WORKSPACE
    config_path = Path(args.config) if args.config else DEFAULT_CONFIG_PATH
    config = __import__("openrattler.config.loader", fromlist=["load_config"]).load_config(
        config_path
    )

    google_cfg = config.google_auth
    creds_dir = workspace / google_cfg.credentials_path
    client_secrets = creds_dir / google_cfg.client_secrets_file

    if not client_secrets.exists():
        print(
            f"Error: client_secrets.json not found at {client_secrets}.\n"
            "Download it from Google Cloud Console and place it there, then retry."
        )
        sys.exit(1)

    manager = GoogleCredentialManager(
        credentials_path=creds_dir,
        scopes=google_cfg.scopes,
        token_file=google_cfg.token_file,
        callback_port=google_cfg.oauth_callback_port,
    )

    if manager.is_authorized() and not getattr(args, "reauthorize", False):
        print(
            "Already authorized. Use --reauthorize to force a new consent flow\n"
            "and replace the existing token."
        )
        return

    print("Opening browser for Google OAuth consent…")
    await manager.authorize()
    print("Authorization complete. Encrypted tokens saved.")


def _cmd_auth_google(args: argparse.Namespace) -> None:
    asyncio.run(_cmd_auth_google_async(args))


# ---------------------------------------------------------------------------
# Argument parser
# ---------------------------------------------------------------------------


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="openrattler",
        description="OpenRattler — security-first personal AI assistant",
    )
    parser.add_argument(
        "--workspace",
        default=None,
        metavar="DIR",
        help=f"workspace directory (default: {DEFAULT_WORKSPACE})",
    )

    subparsers = parser.add_subparsers(dest="command", metavar="<command>")
    subparsers.required = True

    # init
    subparsers.add_parser(
        "init",
        help="create workspace directory and default config",
    )

    # chat
    chat_parser = subparsers.add_parser(
        "chat",
        help="start interactive CLI chat",
    )
    chat_parser.add_argument(
        "--config",
        default=None,
        metavar="FILE",
        help=f"config file path (default: {DEFAULT_CONFIG_PATH})",
    )

    # run
    run_parser = subparsers.add_parser(
        "run",
        help="start the full production server (Gateway + channels + Social Secretary)",
    )
    run_parser.add_argument(
        "--config",
        default=None,
        metavar="FILE",
        help=f"config file path (default: {DEFAULT_CONFIG_PATH})",
    )
    run_parser.add_argument(
        "--host",
        default="127.0.0.1",
        metavar="HOST",
        help="WebSocket Gateway bind host (default: 127.0.0.1)",
    )
    run_parser.add_argument(
        "--port",
        default=8765,
        type=int,
        metavar="PORT",
        help="WebSocket Gateway bind port (default: 8765)",
    )

    # sessions
    sessions_parser = subparsers.add_parser(
        "sessions",
        help="session management commands",
    )
    sessions_sub = sessions_parser.add_subparsers(dest="sessions_command", metavar="<action>")
    sessions_sub.required = True
    sessions_sub.add_parser("list", help="list all session keys")

    # auth
    auth_parser = subparsers.add_parser(
        "auth",
        help="authentication management commands",
    )
    auth_sub = auth_parser.add_subparsers(dest="auth_command", metavar="<provider>")
    auth_sub.required = True
    google_parser = auth_sub.add_parser(
        "google",
        help="authorize Google APIs (Gmail, Drive, Calendar) via OAuth 2.0",
    )
    google_parser.add_argument(
        "--config",
        default=None,
        metavar="FILE",
        help=f"config file path (default: {DEFAULT_CONFIG_PATH})",
    )
    google_parser.add_argument(
        "--reauthorize",
        action="store_true",
        default=False,
        help="force a new consent flow even if already authorized",
    )

    return parser


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------


def main(argv: list[str] | None = None) -> None:
    """Parse arguments and dispatch to the appropriate subcommand."""
    parser = _build_parser()
    args = parser.parse_args(argv)

    if args.command == "init":
        _cmd_init(args)
    elif args.command == "chat":
        _cmd_chat(args)
    elif args.command == "run":
        _cmd_run(args)
    elif args.command == "sessions":
        if args.sessions_command == "list":
            _cmd_sessions_list(args)
    elif args.command == "auth":
        if args.auth_command == "google":
            _cmd_auth_google(args)
    else:  # pragma: no cover
        parser.print_help()
        sys.exit(1)


if __name__ == "__main__":  # pragma: no cover
    main()
