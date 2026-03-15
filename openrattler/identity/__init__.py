"""Identity system — loads and assembles the agent's system prompt from identity files.

The identity system separates the agent's sense of self, operational guidance,
and user context into discrete Markdown files.  At session start, ``IdentityLoader``
assembles these into a single coherent system prompt.

Runtime files (USER.md, MEMORY.md) live in the workspace identity directory
(``~/.openrattler/identity/``).  Source templates (SOUL.md, IDENTITY.md,
BOOTSTRAP.md, HEARTBEAT.md) are shipped with the package and copied into the
workspace on first run so the user can customise them without touching source code.

Security notes:
- USER.md is never committed to source control — it lives only in the runtime
  workspace and may contain personal information.
- MEMORY.md is written only through the ``update_memory_narrative`` tool, which
  routes all writes through the MemorySecurityAgent before touching disk.
"""
