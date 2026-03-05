# OpenRattler Build Guide

## Agent Instructions

### Before Starting ANY Build Piece

1. **Pull latest `main`** and create a feature branch:
   ```bash
   git checkout main
   git pull origin main
   git checkout -b build/<piece_number>-<short-name>
   ```
   Example: `git checkout -b build/1.1-universal-message-models`

2. **Activate the virtual environment** (created in Piece 0.1):
   ```bash
   # Windows (PowerShell)
   .\.venv\Scripts\Activate.ps1
   # Linux/macOS
   source .venv/bin/activate
   ```

3. **Read the project documents** referenced in that piece's "Reference Documents" section. These are located in the `.claude/` directory of the project. Follow the patterns, naming conventions, and security principles defined there. Do not deviate from the architecture.

### After Completing ANY Build Piece

1. **Run the full check suite** before committing:
   ```bash
   black --check .
   mypy openrattler/
   pytest
   ```

2. **Update `PROGRESS.md`** with:
   - What was completed (files created, classes implemented)
   - Test results (pass/fail, coverage if available)
   - Any suggested changes or improvements discovered during implementation
   - Next steps (what the next build piece should be aware of)

3. **Commit and push your feature branch:**
   ```bash
   git add .
   git commit -m "Build Piece <number>: <short description>"
   git push origin build/<piece_number>-<short-name>
   ```

4. **Create a Pull Request** targeting `main`. The PR description should include:
   - Build piece number and name
   - Summary of what was implemented
   - Test results
   - Any open questions or concerns for the reviewer

**Do NOT merge the PR.** The human reviewer will review and merge.

### General Rules

- Python 3.11+ with type hints everywhere
- Pydantic v2 for all data models and validation
- `asyncio` for all I/O operations
- `pytest` + `pytest-asyncio` for all tests
- Format with `black`, type-check with `mypy`
- Security checklist applies to every piece (see SECURITY_QUICKREF.md)
- Use allowlists, never denylists
- Every public function needs a docstring with security notes where applicable
- All work happens inside the activated virtual environment

---

## Phase 0: Project Bootstrap

### Build Piece 0.1 — Project Structure and Dev Environment

**Goal:** Create the project skeleton, virtual environment, git repository, install dependencies, and verify the dev toolchain works.

**Reference Documents:** AGENTS.md (Project Structure section), README.md

**Note:** This is the only piece that does NOT start from a feature branch (there's no repo yet). After this piece, all subsequent pieces follow the branch workflow above.

**Checklist:**
- [ ] Initialize git repository:
  ```bash
  git init
  git checkout -b main
  ```
- [ ] Create a Python virtual environment and activate it:
  ```bash
  python -m venv .venv
  # Windows (PowerShell):
  .\.venv\Scripts\Activate.ps1
  # Linux/macOS:
  # source .venv/bin/activate
  ```
- [ ] Create the project directory tree:
  ```
  openrattler/
    __init__.py
    models/
      __init__.py
    gateway/
      __init__.py
    agents/
      __init__.py
    tools/
      __init__.py
    storage/
      __init__.py
    channels/
      __init__.py
    mcp/
      __init__.py
    security/
      __init__.py
    config/
      __init__.py
    cli/
      __init__.py
  tests/
    __init__.py
    test_models/
      __init__.py
    test_storage/
      __init__.py
    test_tools/
      __init__.py
    test_gateway/
      __init__.py
    test_agents/
      __init__.py
    test_security/
      __init__.py
    test_config/
      __init__.py
    test_cli/
      __init__.py
    test_integration/
      __init__.py
  ```
- [ ] Create `pyproject.toml` with project metadata, Python 3.11+ requirement, and dependencies:
  - Core: `aiohttp`, `pydantic>=2.0`, `openai`, `anthropic`
  - Dev: `pytest`, `pytest-asyncio`, `black`, `mypy`, `pytest-cov`
- [ ] Install dependencies inside the venv:
  ```bash
  pip install -e ".[dev]"
  ```
- [ ] Create a minimal `openrattler/__init__.py` with version string
- [ ] Create a `conftest.py` at the test root with common fixtures (e.g., `tmp_path` for storage tests)
- [ ] Write a single smoke test (`tests/test_smoke.py`) that imports `openrattler` and asserts the version string
- [ ] Run `black --check .`, `mypy openrattler/`, and `pytest` — all should pass on this empty skeleton
- [ ] Create a `.gitignore` for Python projects (include `.venv/`, `__pycache__/`, `*.pyc`, `.mypy_cache/`, `*.egg-info/`, `dist/`, `build/`)
- [ ] Make initial commit on `main`:
  ```bash
  git add .
  git commit -m "Build Piece 0.1: Project structure and dev environment"
  ```
- [ ] If using a remote (GitHub, etc.), create the remote repo and push:
  ```bash
  git remote add origin <your-repo-url>
  git push -u origin main
  ```

**Outputs / Interface Contract:**
- Other pieces depend on: `openrattler` package importable, `pytest` runnable, `.venv` present and populated
- The `openrattler/__init__.py` must export `__version__: str`

**Testing focus:** Verify the toolchain is operational — `pytest`, `black`, `mypy` all run clean. The smoke test imports the package successfully. The venv is active and dependencies are installed.

---

## Phase 1: Core Data Models

### Build Piece 1.1 — UniversalMessage and Supporting Types

**Goal:** Implement the UniversalMessage Pydantic model and all its supporting types. This is the backbone of the entire system — every component communicates through this model.

**Reference Documents:** UNIVERSAL_MESSAGE_PROTOCOL.md, ARCHITECTURE.md (Security-First Design Principles)

**Checklist:**
- [ ] Create `openrattler/models/__init__.py`
- [ ] Create `openrattler/models/messages.py` with:
  - [ ] `UniversalMessage` — the full Pydantic model as specified in the protocol doc (message_id, from_agent, to_agent, session_key, channel, type, operation, params, metadata, trust_level, requires_approval, timestamp, parent_message_id, trace_id, error)
  - [ ] `Literal` types for `type` field: `"request"`, `"response"`, `"event"`, `"error"`
  - [ ] `Literal` types for `trust_level`: `"public"`, `"main"`, `"local"`, `"security"`, `"mcp"`
  - [ ] A factory/helper method `create_message(...)` that auto-generates `message_id` (UUID) and `timestamp`
  - [ ] A method `create_response(original_message, ...)` that auto-fills `parent_message_id` and `trace_id` from the original
  - [ ] A method `create_error(original_message, code, message, details)` for error responses
- [ ] Create `openrattler/models/errors.py` with standard error codes as an enum:
  - `PERMISSION_DENIED`, `INVALID_PARAMS`, `RATE_LIMIT_EXCEEDED`, `TIMEOUT`, `NOT_FOUND`, `APPROVAL_DENIED`, `NETWORK_ERROR`, `INTERNAL_ERROR`
- [ ] Write tests in `tests/test_models/test_messages.py`:
  - [ ] Test creating a valid UniversalMessage with all required fields
  - [ ] Test that `message_id` is a valid UUID
  - [ ] Test that missing required fields raise `ValidationError`
  - [ ] Test `create_response()` correctly inherits `trace_id` and sets `parent_message_id`
  - [ ] Test `create_error()` produces a message with `type="error"` and correct error dict
  - [ ] Test that invalid `trust_level` or `type` values are rejected
  - [ ] Test serialization to dict and back (round-trip)

**Testing focus:** Pydantic validation catches bad data, factory methods produce correct messages, round-trip serialization works.

**Outputs / Interface Contract:**
- Must export from `openrattler.models.messages`: `UniversalMessage`, `create_message()`, `create_response()`, `create_error()`
- Must export from `openrattler.models.errors`: `ErrorCode` enum
- Every downstream piece imports `UniversalMessage` — its field names and types are the system's backbone — Session, Agent Config, and Tool Models

**Goal:** Implement the data models for sessions, agent configuration, and tool call schemas.

**Reference Documents:** ARCHITECTURE.md (Session Routing, Agent Runtime, Tool Framework sections), AGENT_CREATOR.md (AgentConfig, TaskTemplate)

**Checklist:**
- [ ] Create `openrattler/models/sessions.py` with:
  - [ ] `SessionKey` — a validated string type that enforces the format `agent:<agent_id>:<context>` (use a Pydantic `field_validator`)
  - [ ] `Session` — holds `key: SessionKey`, `history: list[UniversalMessage]`, `created_at: datetime`, `updated_at: datetime`, `agent_id: str`
  - [ ] `Peer` model with `kind: Literal["dm", "group", "thread"]`, `id: str`, optional `parent: Peer`
- [ ] Create `openrattler/models/agents.py` with:
  - [ ] `TrustLevel` enum: `public`, `main`, `local`, `security`, `mcp`
  - [ ] `AgentConfig` — full model as described in architecture: `agent_id`, `name`, `description`, `model`, `model_selection`, `fallback_models`, `allowed_tools`, `denied_tools`, `trust_level`, `can_spawn_subagents`, `max_cost_per_turn`, `session_key`, `workspace`, `system_prompt`, `memory_files`
  - [ ] `TaskTemplate` — the template schema from AGENT_CREATOR.md: `name`, `description`, `system_prompt`, `required_tools`, `suggested_model`, `typical_complexity_range`, `suggested_cost_limit`, `workflow`
  - [ ] `AgentCreationRequest` — the request schema from AGENT_CREATOR.md with all fields
  - [ ] `AgentSpawnLimits` — spawn limits config with sensible defaults
- [ ] Create `openrattler/models/tools.py` with:
  - [ ] `ToolDefinition` — `name: str`, `description: str`, `parameters: dict` (JSON Schema), `requires_approval: bool`, `trust_level_required: TrustLevel`, `security_notes: str`
  - [ ] `ToolCall` — `tool_name: str`, `arguments: dict`, `call_id: str`
  - [ ] `ToolResult` — `call_id: str`, `success: bool`, `result: Any`, `error: Optional[str]`
- [ ] Create `openrattler/models/audit.py` with:
  - [ ] `AuditEvent` — `event: str`, `timestamp: datetime`, `session_key: Optional[str]`, `agent_id: Optional[str]`, `details: dict`, `trace_id: Optional[str]`
- [ ] Write tests in `tests/test_models/`:
  - [ ] `test_sessions.py` — valid/invalid session key formats, Session creation
  - [ ] `test_agents.py` — AgentConfig validation, spawn limits defaults, template creation
  - [ ] `test_tools.py` — ToolCall/ToolResult round-trip, ToolDefinition validation
  - [ ] `test_audit.py` — AuditEvent creation and serialization

**Testing focus:** Session key format validation rejects bad keys, AgentConfig enforces required fields, all models serialize cleanly to JSON.

**Outputs / Interface Contract:**
- Must export from `openrattler.models.sessions`: `SessionKey`, `Session`, `Peer`
- Must export from `openrattler.models.agents`: `TrustLevel`, `AgentConfig`, `TaskTemplate`, `AgentCreationRequest`, `AgentSpawnLimits`
- Must export from `openrattler.models.tools`: `ToolDefinition`, `ToolCall`, `ToolResult`
- Must export from `openrattler.models.audit`: `AuditEvent`
- `TrustLevel` is used in permission checks everywhere — its values must exactly match: `public`, `main`, `local`, `security`, `mcp`

### Build Piece 2.1 — JSONL Transcript Storage

**Goal:** Build the session transcript storage that reads and writes conversation history in JSONL format. This is how all conversation state is persisted.

**Reference Documents:** ARCHITECTURE.md (Session Routing, JSONL for Session Transcripts), PROGRESS.md (Design Decisions — JSONL)

**Checklist:**
- [ ] Create `openrattler/storage/__init__.py`
- [ ] Create `openrattler/storage/transcripts.py` with a `TranscriptStore` class:
  - [ ] `__init__(self, base_dir: Path)` — accepts a base directory for all transcript files
  - [ ] `async def append(self, session_key: str, message: UniversalMessage) -> None` — appends a single message as a JSON line to `{base_dir}/{session_key_as_path}.jsonl` (convert `:` in session keys to `/` for directory structure)
  - [ ] `async def load(self, session_key: str) -> list[UniversalMessage]` — reads all lines and returns deserialized messages
  - [ ] `async def load_recent(self, session_key: str, n: int) -> list[UniversalMessage]` — returns last N messages (efficient tail read)
22  - [ ] `async def exists(self, session_key: str) -> bool` — check if transcript exists
  - [ ] `async def list_sessions(self) -> list[str]` — return all known session keys
  - [ ] Path sanitization: reject session keys containing `..`, absolute paths, or non-alphanumeric characters outside of `:` and `-`
- [ ] Write tests in `tests/test_storage/test_transcripts.py`:
  - [ ] Test append + load round-trip (append 3 messages, load them back, verify equality)
  - [ ] Test load_recent returns correct subset
  - [ ] Test empty transcript returns empty list
  - [ ] Test path sanitization rejects `../../../etc/passwd` style keys
  - [ ] Test that concurrent appends don't corrupt the file (use asyncio.gather with multiple appends)
  - [ ] Test list_sessions finds all created transcripts

**Testing focus:** Data integrity on round-trip, path traversal prevention, correct file structure creation, no data loss on concurrent writes.

**Outputs / Interface Contract:**
- Must export from `openrattler.storage.transcripts`: `TranscriptStore`
- `TranscriptStore` is consumed by `AgentRuntime` (Piece 6.1) and `sessions_history` tool (Piece 4.2)
- Methods `append()`, `load()`, `load_recent()` must accept `session_key: str` and work with `UniversalMessage` objects — Memory Store

**Goal:** Build the structured memory store that agents use for persistent knowledge (preferences, learned facts, instructions).

**Reference Documents:** ARCHITECTURE.md (Memory Security section, Structured Memory vs Flat Files decision), SECURITY.md (Memory Security Review)

**Checklist:**
- [ ] Create `openrattler/storage/memory.py` with a `MemoryStore` class:
  - [ ] `__init__(self, base_dir: Path)` — base directory for agent memory files
  - [ ] `async def load(self, agent_id: str) -> dict` — load the agent's memory JSON file, return empty dict if not found
  - [ ] `async def save(self, agent_id: str, memory: dict) -> None` — write memory to JSON file with atomic write (write to temp, then rename)
  - [ ] `async def compute_diff(self, agent_id: str, proposed: dict) -> dict` — compare current memory to proposed changes, return a diff structure with `added`, `removed`, `modified` keys
  - [ ] `async def apply_changes(self, agent_id: str, changes: dict, approved_by: str) -> bool` — apply changes and append to history log within the memory file
  - [ ] Path sanitization matching TranscriptStore
- [ ] Write tests in `tests/test_storage/test_memory.py`:
  - [ ] Test load returns empty dict for new agent
  - [ ] Test save + load round-trip
  - [ ] Test compute_diff correctly identifies added/removed/modified keys
  - [ ] Test apply_changes appends to history
  - [ ] Test atomic write (if interrupted mid-write, old data preserved)
  - [ ] Test path sanitization

**Testing focus:** Diff computation is accurate, atomic writes prevent corruption, history log grows correctly.

---

### Build Piece 2.3 — Audit Log

**Goal:** Build the append-only audit log that records all security-relevant events.

**Reference Documents:** SECURITY.md (Audit Logging section, Audit Log Protections), SECURITY_QUICKREF.md (Security Checklist)

**Checklist:**
- [ ] Create `openrattler/storage/audit.py` with an `AuditLog` class:
  - [ ] `__init__(self, log_path: Path, hmac_key: Optional[str] = None)` — path to the audit log file, optional HMAC key for tamper detection
  - [ ] `async def log(self, event: AuditEvent) -> None` — append event as JSONL with optional HMAC signature field
  - [ ] `async def query(self, event_type: Optional[str] = None, since: Optional[datetime] = None, session_key: Optional[str] = None, trace_id: Optional[str] = None, limit: int = 100) -> list[AuditEvent]` — filtered query over the log
  - [ ] `async def verify_integrity(self) -> tuple[bool, list[int]]` — verify HMAC signatures, return (all_valid, list_of_bad_line_numbers)
  - [ ] Enforce append-only: the class should never offer a delete or modify method
  - [ ] HMAC computation: `hmac.new(key, json_line_bytes, hashlib.sha256).hexdigest()`
- [ ] Create a convenience function `audit_log(event: str, **details)` that creates an AuditEvent and appends it (this will be used throughout the codebase)
- [ ] Write tests in `tests/test_storage/test_audit.py`:
  - [ ] Test logging an event and querying it back
  - [ ] Test query filters (by event_type, since, session_key, trace_id)
  - [ ] Test HMAC integrity verification passes on unmodified log
  - [ ] Test HMAC integrity verification fails on tampered log (modify a line)
  - [ ] Test that the class provides no delete/modify methods
  - [ ] Test limit parameter caps results

**Testing focus:** Append-only guarantee, HMAC tamper detection works, query filters return correct subsets.

**Outputs / Interface Contract:**
- Must export from `openrattler.storage.audit`: `AuditLog`, `audit_log()` convenience function
- `AuditLog` is passed to nearly every component — `ToolExecutor`, `PitchCatchValidator`, `AgentCreator`, `ApprovalManager`, `AgentRuntime`
- The `audit_log()` convenience function must be importable as a standalone for easy use throughout the codebase

### Build Piece 3.1 — Session Router

**Goal:** Implement the deterministic session routing logic that maps incoming messages to the correct isolated session.

**Reference Documents:** ARCHITECTURE.md (Session Routing Logic, Gateway section), SECURITY.md (Session Isolation), ARCHITECTURE_SUMMARY.md (Session Isolation pattern)

**Checklist:**
- [ ] Create `openrattler/gateway/__init__.py`
- [ ] Create `openrattler/gateway/router.py` with:
  - [ ] `route_to_session(channel: str, account_id: str, peer: Peer) -> str` — the deterministic routing function as specified in ARCHITECTURE.md
    - DMs → `agent:{agent_id}:main`
    - Groups → `agent:{agent_id}:{channel}:group:{peer.id}`
    - Threads → `{parent_session}:thread:{peer.id}`
  - [ ] `Binding` model: `channel: str`, `agent_id: str`, optional filters (`team_id`, `guild_id`, `peer_kind`)
  - [ ] `resolve_agent(channel: str, bindings: list[Binding], **filters) -> str` — given channel and bindings config, return the appropriate agent_id
  - [ ] Input validation: reject empty strings, validate channel names against an allowlist
- [ ] Write tests in `tests/test_gateway/test_router.py`:
  - [ ] Test DM routing produces correct session key
  - [ ] Test group routing produces isolated session key per group
  - [ ] Test thread routing extends parent session key
  - [ ] Test that different channels produce different session keys
  - [ ] Test binding resolution (Slack team → work agent, Telegram DM → main agent, Discord guild → public agent)
  - [ ] **Security test**: Verify two different group IDs produce different session keys (isolation)
  - [ ] **Security test**: Verify a group session key cannot match a DM session key

**Testing focus:** Deterministic routing (same inputs always produce same key), isolation guarantees between channels/groups/DMs.

---

## Phase 4: Tool Framework

### Build Piece 4.1 — Tool Registry and Permission Checking

**Goal:** Build the tool registration system and permission enforcement layer. Tools register with metadata; the system checks whether a given agent is allowed to use a given tool before execution.

**Reference Documents:** ARCHITECTURE.md (Tool Framework section, Tool Permission Model), SECURITY.md (Tool Permission Model), SECURITY_QUICKREF.md

**Checklist:**
- [ ] Create `openrattler/tools/__init__.py`
- [ ] Create `openrattler/tools/registry.py` with:
  - [ ] `ToolRegistry` class:
    - [ ] `register(self, tool: ToolDefinition, handler: Callable) -> None` — register a tool with its definition and async handler function
    - [ ] `get(self, name: str) -> Optional[ToolDefinition]` — look up a tool definition
    - [ ] `list_tools(self) -> list[ToolDefinition]` — return all registered tools
    - [ ] `list_tools_for_agent(self, agent_config: AgentConfig) -> list[ToolDefinition]` — return only tools this agent is allowed to use
  - [ ] `@tool` decorator that auto-registers a function with inferred metadata (name from function name, description from docstring, parameters from type hints)
- [ ] Create `openrattler/tools/permissions.py` with:
  - [ ] `check_permission(agent_config: AgentConfig, tool_name: str, tool_def: ToolDefinition) -> tuple[bool, Optional[str]]` — returns (allowed, rejection_reason)
    - Check `tool_name` is in `agent_config.allowed_tools`
    - Check `tool_name` is NOT in `agent_config.denied_tools`
    - Check `agent_config.trust_level` meets `tool_def.trust_level_required`
    - Return reason string if denied
  - [ ] `needs_approval(tool_def: ToolDefinition) -> bool` — returns whether this tool requires human approval before execution
- [ ] Create `openrattler/tools/executor.py` with:
  - [ ] `ToolExecutor` class:
    - [ ] `__init__(self, registry: ToolRegistry, audit_log: AuditLog)`
    - [ ] `async def execute(self, agent_config: AgentConfig, tool_call: ToolCall) -> ToolResult` — full execution flow: permission check → approval check → execute handler → audit log → return result
    - [ ] Wrap handler execution in try/except to always return a ToolResult (never raise)
    - [ ] Log all executions (success and failure) to the audit log
- [ ] Write tests in `tests/test_tools/`:
  - [ ] `test_registry.py`:
    - [ ] Test registering and retrieving a tool
    - [ ] Test the `@tool` decorator auto-registration
    - [ ] Test `list_tools_for_agent` filters correctly
  - [ ] `test_permissions.py`:
    - [ ] Test allowed tool passes
    - [ ] Test denied tool fails with reason
    - [ ] Test tool not in allowlist fails
    - [ ] Test trust level enforcement (public agent can't use local-level tool)
  - [ ] `test_executor.py`:
    - [ ] Test successful execution produces ToolResult with success=True
    - [ ] Test permission-denied execution produces ToolResult with success=False
    - [ ] Test handler exception produces ToolResult with error message
    - [ ] Test audit log receives entries for each execution

**Testing focus:** Permission checks are airtight (no false allows), the decorator works, executor never raises (always returns ToolResult), audit logging captures everything.

**Outputs / Interface Contract:**
- Must export from `openrattler.tools.registry`: `ToolRegistry`, `tool` decorator
- Must export from `openrattler.tools.permissions`: `check_permission()`, `needs_approval()`
- Must export from `openrattler.tools.executor`: `ToolExecutor`
- `ToolExecutor.execute()` must accept `AgentConfig` + `ToolCall` and always return `ToolResult` (never raise)
- `ToolRegistry` is consumed by `AgentRuntime` (Piece 6.1), `AgentCreator` (Piece 12.1), and `Gateway` (Piece 11.1) — Built-in Tools (Safe Set)

**Goal:** Implement a small set of safe, commonly-used tools to exercise the tool framework. These are the tools that main agents can use directly without the Creator.

**Reference Documents:** ARCHITECTURE.md (Tool Framework), SECURITY.md (Command Filtering), AGENTS.md (Testing Strategy)

**Checklist:**
- [ ] Create `openrattler/tools/builtin/__init__.py`
- [ ] Create `openrattler/tools/builtin/file_ops.py`:
  - [ ] `file_read(path: str) -> str` tool:
    - Path sanitization: reject paths containing `..`, resolve to absolute, verify within allowed directories
    - Configurable allowed directories (default: agent workspace only)
    - Max file size limit (default: 1MB)
    - Trust level required: `main`
    - Security note in docstring about path traversal
  - [ ] `file_write(path: str, content: str) -> str` tool:
    - Same path sanitization as file_read
    - `requires_approval: True`
    - Trust level required: `main`
    - Atomic write (temp file + rename)
  - [ ] `file_list(directory: str) -> list[str]` tool:
    - Path sanitization
    - Trust level required: `main`
- [ ] Create `openrattler/tools/builtin/session_tools.py`:
  - [ ] `sessions_history(target_session_key: str, n: int = 10) -> list[dict]` tool:
    - Trust level required: `main`
    - `requires_approval: True` (cross-session access)
    - Security note about cross-session data access
- [ ] Write tests in `tests/test_tools/`:
  - [ ] `test_file_ops.py`:
    - [ ] Test file_read reads a file correctly
    - [ ] Test file_read rejects path traversal (`../../etc/passwd`)
    - [ ] Test file_read rejects paths outside allowed directories
    - [ ] Test file_read rejects files over size limit
    - [ ] Test file_write creates a file correctly
    - [ ] Test file_write rejects path traversal
    - [ ] Test file_list returns directory contents
  - [ ] `test_session_tools.py`:
    - [ ] Test sessions_history returns correct messages
    - [ ] Test sessions_history respects the `n` limit

**Testing focus:** Path sanitization is bulletproof, no way to escape allowed directories, file operations handle edge cases (empty files, large files, missing directories).

---

## Phase 5: LLM Provider Abstraction

### Build Piece 5.1 — LLM Provider Interface and OpenAI Implementation

**Goal:** Build the model-agnostic LLM provider interface so the system can work with any LLM backend. Implement the OpenAI-compatible provider first (covers OpenAI and many compatible APIs).

**Reference Documents:** ARCHITECTURE.md (Agent Runtime section), AGENTS.md (Model-Agnostic principle), ARCHITECTURE_SUMMARY.md (Cost Optimization Strategy)

**Checklist:**
- [ ] Create `openrattler/agents/__init__.py`
- [ ] Create `openrattler/agents/providers/__init__.py`
- [ ] Create `openrattler/agents/providers/base.py` with:
  - [ ] `LLMProvider` abstract base class:
    - [ ] `async def complete(self, messages: list[dict], tools: Optional[list[dict]] = None, model: Optional[str] = None, max_tokens: int = 4096) -> LLMResponse`
    - [ ] `async def health_check(self) -> bool`
  - [ ] `LLMResponse` model: `content: str`, `tool_calls: list[ToolCall]`, `usage: TokenUsage`, `model: str`, `finish_reason: str`
  - [ ] `TokenUsage` model: `prompt_tokens: int`, `completion_tokens: int`, `total_tokens: int`, `estimated_cost_usd: float`
- [ ] Create `openrattler/agents/providers/openai_provider.py` with:
  - [ ] `OpenAIProvider(LLMProvider)`:
    - [ ] `__init__(self, api_key: str, default_model: str = "gpt-4o-mini", base_url: Optional[str] = None)` — base_url allows pointing at compatible APIs
    - [ ] Implement `complete()` — calls OpenAI API, parses response, extracts tool calls, computes estimated cost
    - [ ] Implement `health_check()` — simple API ping
    - [ ] Handle rate limit errors with exponential backoff (max 3 retries)
    - [ ] Never log API keys
- [ ] Create `openrattler/agents/providers/anthropic_provider.py` with:
  - [ ] `AnthropicProvider(LLMProvider)`:
    - [ ] Same interface, adapted for Anthropic's message format
    - [ ] Handle Anthropic-specific tool use format
- [ ] Write tests in `tests/test_agents/test_providers.py`:
  - [ ] Test with a **mock** HTTP server (do NOT require real API keys in tests)
  - [ ] Test that a normal response is parsed into LLMResponse correctly
  - [ ] Test that tool calls in the response are parsed into ToolCall objects
  - [ ] Test that rate limit responses trigger retry
  - [ ] Test that token usage is computed
  - [ ] Test health_check

**Testing focus:** All tests use mocked HTTP responses (no real API calls). Response parsing handles edge cases (empty content, multiple tool calls, no tool calls). API keys never appear in logs or errors.

**Outputs / Interface Contract:**
- Must export from `openrattler.agents.providers.base`: `LLMProvider` (ABC), `LLMResponse`, `TokenUsage`
- Must export from `openrattler.agents.providers.openai_provider`: `OpenAIProvider`
- Must export from `openrattler.agents.providers.anthropic_provider`: `AnthropicProvider`
- `LLMProvider.complete()` must return `LLMResponse` containing `tool_calls: list[ToolCall]` using the `ToolCall` model from Piece 1.2
- `AgentRuntime` (Piece 6.1) depends on the `LLMProvider` interface — any provider implementation must be swappable

### Build Piece 6.1 — Agent Turn Loop

**Goal:** Build the core agent runtime that processes a user message through the full cycle: load session → build prompt → call LLM → execute tools → return response. This is the heart of the system.

**Reference Documents:** ARCHITECTURE.md (Agent Runtime section, Agent Turn Loop), AGENTS.md (Core Philosophy), SECURITY_QUICKREF.md

**Checklist:**
- [ ] Create `openrattler/agents/runtime.py` with:
  - [ ] `AgentRuntime` class:
    - [ ] `__init__(self, config: AgentConfig, provider: LLMProvider, tool_executor: ToolExecutor, transcript_store: TranscriptStore, memory_store: MemoryStore, audit_log: AuditLog)`
    - [ ] `async def initialize_session(self, session_key: str) -> Session` — load transcript, load memory, build system prompt
    - [ ] `async def process_message(self, session: Session, user_message: UniversalMessage) -> UniversalMessage` — the main turn loop:
      1. Append user message to session history
      2. Build messages array for LLM (system prompt + history)
      3. Call LLM provider
      4. If LLM returns tool calls: execute each via ToolExecutor, feed results back to LLM, repeat (max 10 tool loops to prevent infinite loops)
      5. Build response UniversalMessage
      6. Append assistant response to transcript
      7. Audit log the turn
      8. Return response
    - [ ] `_build_system_prompt(self, memory: dict) -> str` — combine agent's system prompt template with memory data
    - [ ] `_build_messages(self, session: Session) -> list[dict]` — convert session history to LLM message format
    - [ ] Tool loop safety: maximum iterations, timeout per tool call
- [ ] Write tests in `tests/test_agents/test_runtime.py`:
  - [ ] Test a simple user message → assistant response (no tool use) using a mocked LLM
  - [ ] Test a message that triggers one tool call → tool result → final response
  - [ ] Test the tool loop stops at max iterations (prevent infinite loops)
  - [ ] Test that all messages are appended to the transcript
  - [ ] Test that the audit log receives a turn entry
  - [ ] Test session initialization loads existing transcript correctly

**Testing focus:** All tests use mocked LLM and tool handlers. The turn loop terminates correctly, transcripts are updated, audit logging works. No infinite loops possible.

**Outputs / Interface Contract:**
- Must export from `openrattler.agents.runtime`: `AgentRuntime`
- `AgentRuntime.process_message(session, user_message)` is the primary entry point consumed by `Gateway` (Piece 11.1) and `CLIChat` (Piece 10.1)
- Must accept any `LLMProvider` implementation (provider-agnostic)
- The `Session` object returned by `initialize_session()` is passed into `process_message()` — this is the main state container

### Build Piece 7.1 — PitchCatch Validator Framework

**Goal:** Build the security validation layer that sits at every trust boundary. This is the core of OpenRattler's security model — every message between components passes through a validator.

**Reference Documents:** ARCHITECTURE.md (Pitch-Catch Handoffs, Security-First Design Principles), UNIVERSAL_MESSAGE_PROTOCOL.md (PitchCatch Validator section), SECURITY_QUICKREF.md, SECURITY.md

**Checklist:**
- [ ] Create `openrattler/security/__init__.py`
- [ ] Create `openrattler/security/validator.py` with:
  - [ ] `PitchCatchValidator` class:
    - [ ] `__init__(self, component_id: str, trust_level: TrustLevel, allowed_operations: list[str], required_params: dict[str, list[str]], optional_params: dict[str, list[str]], rate_limiter: RateLimiter, audit_log: AuditLog)`
    - [ ] `async def validate_incoming(self, message: UniversalMessage) -> UniversalMessage` — the full validation pipeline:
      1. Check operation is in allowed_operations
      2. Check trust level is sufficient
      3. Validate required params are present
      4. Strip extraneous params (need-to-know isolation)
      5. Check rate limits
      6. Audit log the message
      7. Return sanitized message (or raise PermissionError)
    - [ ] `async def structure_outgoing(self, operation: str, params: dict, to_agent: str, type: str = "response") -> UniversalMessage` — package output as UniversalMessage
- [ ] Create `openrattler/security/rate_limiter.py` with:
  - [ ] `RateLimiter` class:
    - [ ] `__init__(self, max_per_minute: int, max_per_hour: int)`
    - [ ] `async def check(self, key: str) -> bool` — returns True if within limits
    - [ ] `async def record(self, key: str) -> None` — record a request
    - [ ] In-memory implementation using timestamps (no external dependencies)
- [ ] Write tests in `tests/test_security/`:
  - [ ] `test_validator.py`:
    - [ ] Test valid message passes validation
    - [ ] Test disallowed operation is rejected
    - [ ] Test insufficient trust level is rejected
    - [ ] Test missing required params are rejected
    - [ ] Test extraneous params are stripped (need-to-know)
    - [ ] Test rate-limited message is rejected
    - [ ] Test audit log receives validation events
  - [ ] `test_rate_limiter.py`:
    - [ ] Test requests within limit pass
    - [ ] Test requests exceeding per-minute limit fail
    - [ ] Test rate limit resets after time window passes

**Testing focus:** Validation catches every category of bad message. Need-to-know stripping actually removes params. Rate limiter correctly tracks windows.

---

## Phase 8: Input Sanitization and Security Utilities

### Build Piece 8.1 — Input Validation and Path Sanitization

**Goal:** Build the shared security utilities used across the codebase — path sanitization, command filtering, input validation helpers.

**Reference Documents:** SECURITY.md (Command Filtering, Input/Output Filtering), SECURITY_QUICKREF.md (Security Checklist), ARCHITECTURE.md (Security Architecture)

**Checklist:**
- [ ] Create `openrattler/security/sanitize.py` with:
  - [ ] `sanitize_path(path: str, allowed_dirs: list[Path]) -> Path` — resolve path to absolute, verify it's within an allowed directory, reject `..` traversal, return clean Path or raise ValueError
  - [ ] `sanitize_session_key(key: str) -> str` — validate session key format, reject dangerous characters
  - [ ] `validate_agent_id(agent_id: str) -> str` — validate agent ID format
- [ ] Create `openrattler/security/command_filter.py` with:
  - [ ] `DANGEROUS_COMMANDS` dict as specified in ARCHITECTURE.md (rm, sudo, dd, mkfs, chmod, etc.)
  - [ ] `filter_command(cmd: str, args: list[str]) -> tuple[str, bool, Optional[str]]` — returns (action: "allow"|"deny"|"approve", needs_approval: bool, reason: str)
  - [ ] `CommandFilter` class that is configurable (users can add/remove patterns)
- [ ] Create `openrattler/security/patterns.py` with:
  - [ ] `SUSPICIOUS_PATTERNS` list as specified in SECURITY.md (command injection, exfiltration, privilege escalation, instruction override, credential access patterns)
  - [ ] `scan_for_suspicious_content(text: str) -> list[tuple[str, str]]` — returns list of (pattern_name, matched_text) tuples
- [ ] Write tests in `tests/test_security/`:
  - [ ] `test_sanitize.py`:
    - [ ] Test valid path within allowed dir passes
    - [ ] Test `../../etc/passwd` is rejected
    - [ ] Test symlink outside allowed dir is rejected (if possible)
    - [ ] Test valid session key passes
    - [ ] Test session key with injection characters is rejected
  - [ ] `test_command_filter.py`:
    - [ ] Test safe command (ls) is allowed
    - [ ] Test `rm -rf` requires approval
    - [ ] Test `mkfs` is denied outright
    - [ ] Test `sudo` requires approval
  - [ ] `test_patterns.py`:
    - [ ] Test each suspicious pattern category is detected
    - [ ] Test clean text returns no matches
    - [ ] Test mixed text with injection attempt is caught

**Testing focus:** No path traversal possible, all dangerous commands caught, suspicious patterns reliably detected. These tests are critical security guarantees.

---

## Phase 9: Configuration System

### Build Piece 9.1 — Configuration Loading and Security Profiles

**Goal:** Build the configuration system that loads user settings, agent configs, and security profiles from JSON files.

**Reference Documents:** README.md (Configuration section), ARCHITECTURE_SUMMARY.md (Tunable Security), SECURITY_PHILOSOPHY.md (Tunable Security Profiles), SECURITY.md

**Checklist:**
- [ ] Create `openrattler/config/__init__.py`
- [ ] Create `openrattler/config/loader.py` with:
  - [ ] `AppConfig` Pydantic model — top-level config covering:
    - `agents: dict[str, AgentConfig]`
    - `security: SecurityConfig`
    - `budget: BudgetConfig`
    - `channels: dict[str, ChannelConfig]`
  - [ ] `SecurityConfig` with `profile: Literal["minimal", "standard", "paranoid"]` and individual overrides
  - [ ] `BudgetConfig` with `daily_limit_usd`, `monthly_limit_usd`, `prefer_tier`
  - [ ] `load_config(config_path: Path) -> AppConfig` — load from JSON with defaults for missing fields
  - [ ] `save_config(config: AppConfig, config_path: Path) -> None` — save to JSON
  - [ ] Config path default: `~/.openrattler/config.json`
- [ ] Create `openrattler/config/profiles.py` with:
  - [ ] `SECURITY_PROFILES` dict mapping profile names to SecurityConfig settings:
    - `minimal`: Most controls off (for development/testing)
    - `standard`: Balanced security/usability (default)
    - `paranoid`: All controls maxed
  - [ ] `apply_profile(config: AppConfig, profile: str) -> AppConfig` — apply a security profile, preserving user overrides
- [ ] Write tests in `tests/test_config/`:
  - [ ] `test_loader.py`:
    - [ ] Test loading a valid config file
    - [ ] Test defaults applied for missing fields
    - [ ] Test invalid config raises validation error
    - [ ] Test round-trip (save then load)
  - [ ] `test_profiles.py`:
    - [ ] Test each profile sets expected values
    - [ ] Test applying profile preserves user overrides

**Testing focus:** Config loads cleanly with defaults, profiles are consistent, invalid configs are caught by Pydantic.

---

## Phase 10: CLI Interface

### Build Piece 10.1 — Basic CLI Chat Interface

**Goal:** Build a command-line chat interface so we can test the full stack end-to-end. This is the first channel adapter and serves as the primary development/testing tool.

**Reference Documents:** ARCHITECTURE.md (Extension Points — Adding a New Channel), UNIVERSAL_MESSAGE_PROTOCOL.md (Channel Adapters), AGENTS.md (CLI Interface)

**Checklist:**
- [ ] Create `openrattler/cli/__init__.py`
- [ ] Create `openrattler/cli/chat.py` with:
  - [ ] `CLIChat` class:
    - [ ] Implements the channel adapter pattern (translate user input → UniversalMessage → process → display response)
    - [ ] `async def start(self)` — interactive chat loop:
      1. Load or create config
      2. Initialize AgentRuntime with configured provider, tools, and storage
      3. Initialize session (DM session: `agent:main:main`)
      4. Loop: prompt for input → send as UniversalMessage → receive response → display
    - [ ] Support `/quit` or `/exit` to end the session
    - [ ] Support `/session` to display current session key
    - [ ] Support `/history [n]` to show last N messages
    - [ ] Support `/audit [n]` to show last N audit events
    - [ ] Handle Ctrl+C gracefully
- [ ] Create `openrattler/cli/main.py` with:
  - [ ] `openrattler init` — create `~/.openrattler/` directory, default config, workspace dirs
  - [ ] `openrattler chat` — launch CLIChat
  - [ ] `openrattler sessions list` — list all session keys
  - [ ] Use `argparse` for command parsing
- [ ] Create `openrattler/__main__.py` so `python -m openrattler` works
- [ ] Write tests in `tests/test_cli/`:
  - [ ] `test_init.py` — test that `init` creates expected directory structure
  - [ ] `test_chat.py` — test CLIChat with mocked LLM (send a message, verify it flows through the system and returns a response, verify transcript is created)

**Testing focus:** The full stack works end-to-end with mocked LLM. Messages flow through routing → runtime → tools → response. Transcript and audit log are populated.

---

## Phase 11: Gateway (WebSocket Server)

### Build Piece 11.1 — WebSocket Gateway Server

## Phase 11: Gateway Assembly

### ⚠️ Security Prerequisites — Read Before Coding

This phase implements the Gateway WebSocket server. The Gateway is the only 
external-facing component in OpenRattler and is the primary attack surface 
for infrastructure-level exploitation (as distinct from AI-layer attacks like 
prompt injection).

Per SU-007 in SECURITY_UPGRADES.md, the following requirements are 
**mandatory acceptance criteria** for this phase — not optional enhancements 
to add later:

1. **Authentication is mandatory**: No connection accepted without a valid 
   token. No config option to disable auth. Minimal profile uses a static 
   token; standard+ uses JWT with expiration.
2. **Protocol version enforcement**: Reject connections requesting versions 
   below MIN_PROTOCOL_VERSION. Log downgrade attempts.
3. **Reverse proxy trust**: Never auto-trust proxy headers. Explicit 
   trusted_proxies config required.
4. **Connection-level rate limiting**: Rate-limit new WebSocket connections 
   per IP before any message processing. This is separate from Layer 8 
   operation-level rate limiting.
5. **Endpoint minimization**: Expose only the authenticated WebSocket 
   endpoint and an unauthenticated health check. No REST endpoints for 
   tool execution, session listing, or debug info.
6. **Session transcript protection**: Transcripts are never accessible via 
   the Gateway API. Filesystem permissions restrict access to the 
   OpenRattler process user only.

For full context including threat background, implementation examples, and 
test criteria, see SU-007 in SECURITY_UPGRADES.md.

**Goal:** Build the WebSocket server that channels connect to. This is the central hub through which all external communications flow.

**Reference Documents:** ARCHITECTURE.md (Gateway section), UNIVERSAL_MESSAGE_PROTOCOL.md (Message Schema), SECURITY.md (Session Isolation)

**Checklist:**
- [ ] Create `openrattler/gateway/server.py` with:
  - [ ] `Gateway` class:
    - [ ] `__init__(self, host: str, port: int, config: AppConfig, audit_log: AuditLog)`
    - [ ] `async def start(self) -> None` — start aiohttp WebSocket server
    - [ ] `async def stop(self) -> None` — graceful shutdown
    - [ ] `async def handle_connection(self, ws) -> None` — WebSocket connection handler:
      1. Authenticate connection (token-based)
      2. Register channel
      3. Listen for messages → route to correct session → process → send response
    - [ ] `async def route_message(self, message: UniversalMessage) -> UniversalMessage` — use SessionRouter to find agent, use AgentRuntime to process
    - [ ] `async def authenticate(self, ws, first_message: dict) -> Optional[str]` — validate auth token, return channel_id or None
  - [ ] Connection tracking: maintain dict of active WebSocket connections per channel
  - [ ] Graceful disconnect handling (remove from tracking, log)
- [ ] Create `openrattler/gateway/auth.py` with:
  - [ ] `TokenAuth` class:
    - [ ] `generate_token(channel_id: str) -> str` — create a JWT-like token
    - [ ] `validate_token(token: str) -> Optional[str]` — validate and return channel_id or None
    - [ ] Token expiration support
  - [ ] Use `hmac` + `hashlib` for signing (no external JWT library needed initially)
- [ ] Write tests in `tests/test_gateway/`:
  - [ ] `test_server.py`:
    - [ ] Test server starts and accepts WebSocket connections
    - [ ] Test authentication succeeds with valid token
    - [ ] Test authentication fails with invalid token
    - [ ] Test message routing returns a response
    - [ ] Test graceful disconnect handling
  - [ ] `test_auth.py`:
    - [ ] Test token generation and validation round-trip
    - [ ] Test expired token is rejected
    - [ ] Test tampered token is rejected

**Testing focus:** Auth is enforced (no unauthenticated messages processed), messages route correctly, server handles connection/disconnection gracefully.

---

## Phase 12: Agent Creator

### Build Piece 12.1 — Agent Creator Core

**Goal:** Build the Agent Creator — the security chokepoint that validates and creates specialized subagents on demand.

**Reference Documents:** AGENT_CREATOR.md (entire document), ARCHITECTURE.md (Agent Creator section), SECURITY.md, ARCHITECTURE_SUMMARY.md (Creator Path flow)

**Checklist:**
- [ ] Create `openrattler/agents/creator.py` with:
  - [ ] `AgentCreator` class:
    - [ ] `__init__(self, config: AgentConfig, spawn_limits: AgentSpawnLimits, agent_registry: dict, audit_log: AuditLog, tool_registry: ToolRegistry)`
    - [ ] `async def create_agent(self, request: AgentCreationRequest) -> AgentConfig` — the full creation flow:
      1. Security validation (authorize spawner)
      2. Check spawn limits (depth, width, rate, cost)
      3. Get template
      4. Select model
      5. Build AgentConfig with isolated session key
      6. Register agent
      7. Audit log
      8. Set timeout
      9. Return config
    - [ ] `async def kill_agent(self, agent_id: str, reason: str) -> None` — terminate a subagent
    - [ ] `async def list_agents(self, session_key: Optional[str] = None) -> list[AgentConfig]` — list active subagents
    - [ ] `async def handle_retry(self, request: AgentCreationRequest) -> AgentConfig` — kill previous attempts, create new
- [ ] Create `openrattler/agents/templates.py` with:
  - [ ] `TASK_TEMPLATES` dict with built-in templates as specified in AGENT_CREATOR.md:
    - `research` — web search/fetch specialist
    - `coding` — code generation/analysis
    - `execution` — API calls and structured operations
    - `analysis` — data analysis
- [ ] Create `openrattler/agents/creator_validator.py` with:
  - [ ] `CreatorSecurityValidator` class (hardcoded, not templated):
    - [ ] `async def validate_agent_request(self, request: AgentCreationRequest) -> tuple[bool, Optional[str]]`
    - [ ] `is_authorized_spawner(from_agent: str) -> bool`
    - [ ] `check_spawn_limits(request) -> None` (raises SpawnLimitError)
    - [ ] `task_matches_intent(task: str, original_user_message: str) -> bool` — stub that returns True (LLM-based validation will be added later)
    - [ ] `tools_match_task(tools: list[str], task: str) -> bool` — stub that returns True (LLM-based validation will be added later)
  - [ ] Note: The LLM-based intent/tool validation methods are stubbed for now. They'll be wired up when we integrate real LLM calls. The stubs should have clear TODO comments.
- [ ] Write tests in `tests/test_agents/`:
  - [ ] `test_creator.py`:
    - [ ] Test creating a subagent from a valid request
    - [ ] Test spawn depth limit enforcement
    - [ ] Test spawn width limit enforcement (max children per parent)
    - [ ] Test session-wide subagent limit
    - [ ] Test rate limit enforcement
    - [ ] Test killing a subagent removes it from registry
    - [ ] Test retry kills previous agent before creating new one
    - [ ] Test created agent has isolated session key
    - [ ] Test created agent's trust level never exceeds parent's
    - [ ] Test audit log receives creation events
  - [ ] `test_templates.py`:
    - [ ] Test all built-in templates are present
    - [ ] Test template fields are valid

**Testing focus:** Spawn limits are enforced correctly, trust levels never escalate, isolated session keys are generated, retry logic works. This is a critical security component.

---

## Phase 13: Memory Security

### Build Piece 13.1 — Memory Security Agent

**Goal:** Build the security review system for memory changes. This prevents persistent memory poisoning attacks.

**Reference Documents:** SECURITY.md (Memory Security Review, Suspicious Patterns), ARCHITECTURE.md (Memory Security section)

**Checklist:**
- [ ] Create `openrattler/security/memory_security.py` with:
  - [ ] `MemorySecurityAgent` class:
    - [ ] `__init__(self, suspicious_patterns: list[str], audit_log: AuditLog)`
    - [ ] `async def review_memory_change(self, agent_id: str, diff: dict, session_key: str) -> SecurityResult` — the review pipeline:
      1. Pattern matching against SUSPICIOUS_PATTERNS
      2. Check if non-main session is modifying instructions
      3. Return SecurityResult(suspicious=True/False, reason=str)
      4. Audit log the review
    - [ ] Note: LLM-based subtle attack detection is stubbed for now with a TODO. The pattern-matching layer alone provides significant protection.
  - [ ] `SecurityResult` model: `suspicious: bool`, `reason: Optional[str]`, `confidence: int`
- [ ] Update `openrattler/storage/memory.py`:
  - [ ] Add `async def apply_changes_with_review(self, agent_id: str, changes: dict, session_key: str, security_agent: MemorySecurityAgent) -> tuple[bool, Optional[str]]` — runs security review before applying changes
- [ ] Write tests in `tests/test_security/`:
  - [ ] `test_memory_security.py`:
    - [ ] Test clean memory change passes review
    - [ ] Test memory change with `rm -rf` pattern is flagged
    - [ ] Test memory change with instruction override pattern is flagged
    - [ ] Test memory change with credential pattern is flagged
    - [ ] Test non-main session modifying instructions is flagged
    - [ ] Test main session modifying instructions passes
    - [ ] Test audit log receives review events

**Testing focus:** All suspicious patterns are caught, non-main session writes to instructions are blocked, clean changes pass through.

---

## Phase 14: Channel Adapters

### Build Piece 14.1 — Channel Adapter Base and CLI Adapter

**Goal:** Formalize the channel adapter interface and refactor the CLI chat to use it. This sets the pattern for all future channel integrations.

**Reference Documents:** UNIVERSAL_MESSAGE_PROTOCOL.md (Channel Adapters section), ARCHITECTURE.md (Adding a New Channel), README.md (Channel Integration)

**Checklist:**
- [ ] Create `openrattler/channels/__init__.py`
- [ ] Create `openrattler/channels/base.py` with:
  - [ ] `ChannelAdapter` abstract base class:
    - [ ] `channel_name: str` property
    - [ ] `async def receive(self) -> UniversalMessage` — wait for incoming, translate
    - [ ] `async def send(self, message: UniversalMessage) -> None` — translate and send
    - [ ] `async def connect(self) -> None` — establish connection
    - [ ] `async def disconnect(self) -> None` — clean disconnection
    - [ ] `def get_session_key(self, peer_info: dict) -> str` — derive session key from channel-specific peer info
- [ ] Create `openrattler/channels/cli_adapter.py`:
  - [ ] `CLIAdapter(ChannelAdapter)`:
    - [ ] Wraps stdin/stdout as a channel
    - [ ] `receive()` prompts for input, wraps in UniversalMessage
    - [ ] `send()` prints response text to stdout
    - [ ] Session key: always `agent:main:main` (personal DM context)
- [ ] Refactor `openrattler/cli/chat.py` to use `CLIAdapter` instead of directly constructing messages
- [ ] Write tests:
  - [ ] Test CLIAdapter produces valid UniversalMessage from text input
  - [ ] Test CLIAdapter send formats response correctly
  - [ ] Test session key is always `agent:main:main`

**Testing focus:** The adapter pattern works, CLI adapter produces valid messages, session keys are correct.

---

## Phase 15: Integration Testing

### Build Piece 15.1 — End-to-End Integration Tests

**Goal:** Write integration tests that verify the full message flow from user input through every layer and back. This validates that all the pieces work together correctly.

**Reference Documents:** ARCHITECTURE_SUMMARY.md (Message Flow examples), AGENTS.md (Testing Strategy), all architecture docs

**Checklist:**
- [ ] Create `tests/test_integration/__init__.py`
- [ ] Create `tests/test_integration/test_full_flow.py`:
  - [ ] Test: User sends text message → routed to session → runtime processes → LLM responds → response returned → transcript updated → audit logged
  - [ ] Test: User message triggers tool call → tool executed → result fed back → final response returned
  - [ ] Test: Tool permission denied → graceful error message returned
  - [ ] Test: Two different "users" (different peer IDs) get isolated sessions — messages don't leak
  - [ ] Test: Rate limit triggers after threshold exceeded
- [ ] Create `tests/test_integration/test_security_flow.py`:
  - [ ] Test: Message from public channel cannot access main-only tools
  - [ ] Test: Path traversal in tool arguments is caught
  - [ ] Test: Session isolation — group A message cannot read group B transcript
  - [ ] Test: Memory update with suspicious pattern is flagged
  - [ ] Test: Spawn limit prevents excessive subagent creation
- [ ] All integration tests use mocked LLM provider (deterministic responses)
- [ ] Create `tests/conftest.py` fixtures:
  - [ ] `full_stack` fixture that sets up all components (storage, audit, tools, runtime, router) with temp directories

**Testing focus:** The system works as a whole. Security boundaries hold end-to-end. No component breaks when connected to others.

---

## Phase 16: Approval System

### Build Piece 16.1 — Approval Request/Response Flow

**Goal:** Build the human-in-the-loop approval system for high-risk operations. When a tool requires approval, the system pauses execution, presents the request to the user, and waits for a decision.

**Reference Documents:** SECURITY.md (Approval Gates), ARCHITECTURE.md (Approval System), SECURITY_QUICKREF.md (Provenance over trust principle)

**Checklist:**
- [ ] Create `openrattler/security/approval.py` with:
  - [ ] `ApprovalRequest` model: `approval_id: str`, `operation: str`, `context: dict`, `requesting_agent: str`, `session_key: str`, `provenance: dict` (channel, trust_level, timestamp — independently of agent's stated reason), `timestamp: datetime`, `timeout_seconds: int`
  - [ ] `ApprovalResult` model: `approval_id: str`, `approved: bool`, `decided_by: str`, `timestamp: datetime`
  - [ ] `ApprovalManager` class:
    - [ ] `async def request_approval(self, request: ApprovalRequest) -> ApprovalResult` — store pending request, notify handler, wait for response (with timeout)
    - [ ] `async def resolve(self, approval_id: str, approved: bool, decided_by: str) -> None` — resolve a pending request
    - [ ] `async def list_pending(self) -> list[ApprovalRequest]` — list unresolved requests
    - [ ] Timeout handling: deny on timeout (fail secure)
    - [ ] Audit log every request and resolution
  - [ ] `CLIApprovalHandler` — for CLI, prints the request details including provenance and prompts for y/n
- [ ] Wire approval into `ToolExecutor`:
  - [ ] When `needs_approval(tool_def)` is True, create ApprovalRequest and wait for resolution before executing
- [ ] Write tests:
  - [ ] Test approval flow: request → approve → tool executes
  - [ ] Test denial flow: request → deny → tool returns permission denied
  - [ ] Test timeout flow: request → no response → auto-deny
  - [ ] Test provenance is included in request (not just agent's stated reason)
  - [ ] Test audit log captures both request and resolution

**Testing focus:** Fail-secure on timeout, provenance is always present, the full approve/deny cycle works.

---

## Phase 17: Network Channel Adapters

### Build Piece 17.1 — Email Channel Adapter ✅

**Goal:** Add email as an inbound/outbound channel. Polls an IMAP mailbox for new messages; delivers replies via SMTP with STARTTLS.

**Reference Documents:** UNIVERSAL_MESSAGE_PROTOCOL.md (Channel Adapters), SECURITY.md (Input Validation, Allowlists)

**Checklist:**
- [x] Create `openrattler/channels/email_adapter.py` with:
  - [x] `EmailAdapter(ChannelAdapter)` — polls IMAP, sends SMTP
  - [x] Config keys: `imap_host`, `smtp_host`, `username`, `password`, `sender_allowlist`, `default_to_address`
  - [x] `connect()` — marks connected (IMAP connections are per-poll, not persistent)
  - [x] `receive()` — loops calling `asyncio.to_thread(_fetch_unseen, ...)`; catches exceptions, audit-logs as `email_imap_error`, keeps polling
  - [x] `send()` — operation `"send_email"`, delivers via `asyncio.to_thread(_smtp_send, ...)`
  - [x] `get_session_key({"from_address": ...})` — `sha256(addr.lower())[:12]` → `agent:{id}:email:{hash}`
  - [x] Sender allowlist checked before UniversalMessage is built
  - [x] Rate limit 10/min, 60/hr per session key
  - [x] Suspicious content scan on subject + body; audit-log hits; still deliver
  - [x] `_password` never logged
  - [x] HTML stripping via stdlib `HTMLParser`; prefers `text/plain` over `text/html`
  - [x] SMTP errors propagated; IMAP errors caught
- [x] Update `openrattler/channels/__init__.py` docstring
- [x] Write 38 tests across 8 test classes

**Testing focus:** Allowlist rejection, rate limit, trust level hardcoded, HTML stripping, IMAP error recovery, SMTP error propagation, credential never in audit.

---

### Build Piece 17.2 — SMS Channel Adapter ✅

**Goal:** Add SMS as an inbound/outbound channel using Twilio's REST API. Polls `Messages.json` for inbound; POSTs to `Messages.json` for outbound. No new runtime dependencies (`aiohttp` already in use).

**Reference Documents:** UNIVERSAL_MESSAGE_PROTOCOL.md (Channel Adapters), SECURITY.md (Input Validation, Allowlists)

**Checklist:**
- [x] Create `openrattler/channels/sms_adapter.py` with:
  - [x] `SMSAdapter(ChannelAdapter)` — polls Twilio, posts Twilio
  - [x] Config keys: `account_sid`, `auth_token`, `from_number`, `sender_allowlist`, `default_to_number`
  - [x] `connect()` — creates persistent `aiohttp.ClientSession` with `BasicAuth(sid, token)` and `ClientTimeout(total=30)`; resets `_seen_sids`; sets `_connected_at`
  - [x] `disconnect()` — closes session; idempotent
  - [x] `receive()` — loops calling `_fetch_new_sms()`; catches exceptions in `receive()`, audit-logs as `sms_fetch_error`, keeps polling
  - [x] `_fetch_new_sms()` — GET `Messages.json` with `To=`, `DateSent>=`, `PageSize=20`; filters `direction=="inbound"` and `sid not in _seen_sids`
  - [x] `send()` — operation `"send_sms"`; POST form-encoded; auth_token never logged; body logged as `body_length` only
  - [x] `get_session_key({"from_number": ...})` — `sha256(number)[:12]` → `agent:{id}:sms:{hash}`
  - [x] `_seen_sids: set[str]` — reset on `connect()` to prevent cross-session re-delivery
  - [x] Sender allowlist, rate limit, suspicious content scan, credential guard — same posture as 17.1
- [x] Update `openrattler/channels/__init__.py` docstring
- [x] Write 33 tests across 8 test classes

**Key difference from 17.1:** Error handling lives in `receive()` (not inside `_fetch_new_sms`). Patch `_fetch_new_sms` to raise in tests that need audit events — `receive()` catches and logs. Do not patch `asyncio.to_thread` for audit tests (not used in SMS adapter).

**Testing focus:** Same as 17.1 plus deduplication (`_seen_sids` reset on reconnect), HTTP error handling via `aiohttp.ClientError`, auth token never in audit.

---

### Build Piece 17.3 — Slack Channel Adapter

**Goal:** Add Slack as an inbound/outbound channel. Polls `conversations.history` for inbound messages; posts via `chat.postMessage`. No new runtime dependencies.

**Reference Documents:** UNIVERSAL_MESSAGE_PROTOCOL.md (Channel Adapters), SECURITY.md (Input Validation, Allowlists)

**Branch:** `build/17.3-slack-channel`

**Config shape (`ChannelConfig.settings`):**
```json
{
  "bot_token":             "xoxb-...",
  "channel_id":            "C1234567890",
  "poll_interval_seconds": 10,
  "sender_allowlist":      ["U1234567"]
}
```
Required keys: `bot_token`, `channel_id`, `sender_allowlist`. `poll_interval_seconds` defaults to `10`.

**Checklist:**
- [x] Create `openrattler/channels/slack_adapter.py` with:
  - [x] `SlackAdapter(ChannelAdapter)`:
    - [x] Attributes: `_bot_token`, `_channel_id`, `_poll_interval`, `_sender_allowlist: set[str]`, `_oldest_ts: Optional[str]`, `_seen_ts: set[str]`, `_session: Optional[aiohttp.ClientSession]`, `_connected: bool`, `_rate_limiter`, `_audit`, `_agent_id`
  - [x] `channel_name` → `"slack"`
  - [x] `connect()` — creates persistent `aiohttp.ClientSession` with `headers={"Authorization": f"Bearer {bot_token}"}` and `ClientTimeout(total=30)`; resets `_seen_ts`; sets `_oldest_ts = str(datetime.now(timezone.utc).timestamp())`
  - [x] `disconnect()` — closes session; idempotent
  - [x] `receive()` — loops calling `_fetch_new_messages()`; catches exceptions in `receive()`, audit-logs as `slack_fetch_error`, keeps polling
  - [x] `_fetch_new_messages()` — GET `conversations.history` with `channel=`, `oldest=_oldest_ts`, `limit=20`; check `data["ok"]` (Slack always returns HTTP 200 — never rely on `raise_for_status()` alone); filter via `_is_valid_message()`; raise `RuntimeError` if `ok==False`
  - [x] `send()` — operation `"send_slack_message"`; POST JSON `{"channel": ..., "text": ...}`; check `data["ok"]`, raise `RuntimeError` on failure; `bot_token` never logged; body logged as `body_length` only
  - [x] `get_session_key({"sender_id": ...})` — `sha256(sender_id)[:12]` → `agent:{id}:slack:{hash}` (no case-folding; Slack IDs are opaque strings)
  - [x] `_seen_ts: set[str]` — reset on `connect()`; mark seen AFTER allowlist check, BEFORE rate limit check
  - [x] `_is_valid_message()` — helper gating human vs bot messages; `allow_bot_messages` config flag
  - [x] Sender allowlist, rate limit, suspicious content scan, credential guard — same posture as 17.1/17.2
- [x] Update `openrattler/channels/__init__.py` docstring
- [x] Write 35 tests across 8 test classes

**Critical gotchas:**
- **Slack always returns HTTP 200.** Check `data.get("ok")` in both `_fetch_new_messages()` and `send()`. `resp.raise_for_status()` will never trigger for Slack errors.
- **Auth is Bearer token, not BasicAuth.** Pass `headers={"Authorization": f"Bearer {bot_token}"}` to `ClientSession`, not `auth=`.
- **Subtype filtering is essential.** A plain human message has NO `"subtype"` key. Check `"subtype" in msg` to exclude all system events (bot_message, channel_join, etc.) at once.
- **Bot messages have `bot_id`, not `user`.** Filter with `"user" not in msg` to exclude bots without checking `bot_id` explicitly.
- **`ts` is a string, not a float.** Use as-is for deduplication — do not parse to float (precision loss for 16-digit timestamps).
- **`send()` error is `RuntimeError`, not `aiohttp.ClientResponseError`.** HTTP always 200 means `raise_for_status()` never fires; raise `RuntimeError(f"Slack API error: {data['error']}")` on `ok==False`.
- **`send()` uses `json=payload`, not `data=form`.** Slack `chat.postMessage` requires JSON body.
- **`_oldest_ts` bounds the poll window.** Set to `str(datetime.now(timezone.utc).timestamp())` in `connect()` so only messages from this session forward are fetched.

**Test plan (~32 tests):**

| # | Test | What it verifies |
|---|------|-----------------|
| 1 | `test_channel_name` | Returns `"slack"` |
| 2 | `test_is_channel_adapter` | Instance of `ChannelAdapter` |
| 3 | `test_connect_sets_flags` | `_connected=True`, `_oldest_ts` set, `_session` created |
| 4 | `test_disconnect_clears_flags` | `_connected=False`, session closed |
| 5 | `test_disconnect_idempotent` | Second `disconnect()` does not raise |
| 6 | `test_seen_ts_reset_on_reconnect` | `_seen_ts` cleared when `connect()` called again |
| 7 | `test_get_session_key_deterministic` | Same user ID → same key |
| 8 | `test_get_session_key_prefix` | Key starts with `"agent:"` |
| 9 | `test_get_session_key_format` | `agent / main / slack / <12-char hash>` |
| 10 | `test_receive_returns_message` | Happy path → `UniversalMessage` |
| 11 | `test_receive_sets_correct_fields` | `trust_level="main"`, `operation="user_message"`, `channel="slack"` |
| 12 | `test_receive_rejects_unknown_sender` | User not in allowlist → `PermissionError` + audit `slack_sender_rejected` |
| 13 | `test_receive_marks_ts_as_seen` | `_seen_ts` contains `ts` after delivery |
| 14 | `test_receive_skips_seen_ts` | Same `ts` not re-delivered |
| 15 | `test_receive_polls_until_message` | Loops on empty, returns when message arrives |
| 16 | `test_receive_raises_on_disconnect` | `disconnect()` mid-poll → `EOFError` |
| 17 | `test_receive_suspicious_content_logged` | Injection pattern in text → audit `slack_suspicious_content` |
| 18 | `test_receive_suspicious_content_still_delivered` | Message still returned despite hit |
| 19 | `test_receive_rate_limited` | Exceeded limit → `PermissionError` + audit `slack_rate_limited` |
| 20 | `test_fetch_error_handled` | `RuntimeError` from `_fetch_new_messages` → audit `slack_fetch_error`, adapter keeps polling |
| 21 | `test_filters_bot_messages` | Message without `user` field → `_fetch_new_messages` returns `[]` |
| 22 | `test_filters_subtype_messages` | Message with `subtype="bot_message"` → `_fetch_new_messages` returns `[]` |
| 23 | `test_send_message` | Happy path: correct JSON POSTed to `chat.postMessage` |
| 24 | `test_send_wrong_operation` | `operation != "send_slack_message"` → `ValueError` |
| 25 | `test_send_audit_logged` | `slack_sent` event with `channel_id` and `body_length` |
| 26 | `test_send_token_not_logged` | `bot_token` not in any audit detail |
| 27 | `test_send_error_propagated` | `ok=False` from Slack → `RuntimeError` raised to caller |
| 28 | `test_config_missing_bot_token` | Missing `bot_token` → `ValueError` |
| 29 | `test_config_missing_channel_id` | Missing `channel_id` → `ValueError` |
| 30 | `test_config_missing_sender_allowlist` | Missing `sender_allowlist` → `ValueError` |
| 31 | `test_receive_content_in_params` | `params["content"]` == Slack message text |
| 32 | `test_receive_metadata_has_ts` | `metadata["message_ts"]` == Slack `ts` |

**Key differences from 17.2 (SMS):**

| Aspect | SMSAdapter | SlackAdapter |
|--------|------------|--------------|
| Auth | `BasicAuth(sid, token)` on session | `headers={"Authorization": "Bearer {token}"}` on session |
| Error detection | `resp.raise_for_status()` | `data["ok"] == False` (HTTP always 200) |
| Send error type | `aiohttp.ClientResponseError` | `RuntimeError` |
| Outbound format | form-encoded `data=` | JSON `json=` |
| Message ID field | Twilio `sid` | Slack `ts` |
| Sender identity field | `from` (E.164) | `user` (Slack user ID) |
| Extra filtering | direction == "inbound" | no `subtype`, `user` present |
| `get_session_key` peer key | `from_number` | `user_id` |
| Operation name | `"send_sms"` | `"send_slack_message"` |
| Audit events | `sms_*` | `slack_*` |

**Verification:**
```bash
source .venv/Scripts/activate
black --check .
mypy openrattler/
pytest tests/test_channels/test_slack_adapter.py -v
pytest   # full suite; expect 874 prior + ~32 new
```

---

## Build Order Summary

| Piece | Name | Dependencies | Est. Review Size |
|-------|------|-------------|-----------------|
| 0.1 | Project Structure | None | Small |
| 1.1 | UniversalMessage Models | 0.1 | Medium |
| 1.2 | Session/Agent/Tool Models | 1.1 | Medium |
| 2.1 | Transcript Storage | 1.1 | Medium |
| 2.2 | Memory Store | 1.2 | Medium |
| 2.3 | Audit Log | 1.2 | Medium |
| 3.1 | Session Router | 1.2 | Small |
| 4.1 | Tool Registry & Permissions | 1.2, 2.3 | Medium |
| 4.2 | Built-in Tools | 4.1, 2.1 | Medium |
| 5.1 | LLM Provider Interface | 1.1, 1.2 | Medium |
| 6.1 | Agent Turn Loop | 2.1, 2.2, 2.3, 4.1, 5.1 | Large |
| 7.1 | PitchCatch Validator | 1.1, 2.3 | Medium |
| 8.1 | Input Sanitization | None (can parallelize) | Medium |
| 9.1 | Configuration System | 1.2 | Medium |
| 10.1 | CLI Interface | 6.1, 3.1, 9.1 | Medium |
| 11.1 | WebSocket Gateway | 3.1, 6.1, 7.1 | Large |
| 12.1 | Agent Creator | 1.2, 2.3, 4.1, 7.1 | Large |
| 13.1 | Memory Security | 2.2, 2.3, 8.1 | Medium |
| 14.1 | Channel Adapter Base | 1.1, 10.1 | Small |
| 15.1 | Integration Tests | All above | Large |
| 16.1 | Approval System | 4.1, 2.3, 7.1 | Medium |
| 17.1 | Email Channel Adapter | 14.1, 7.1, 2.3 | Medium |
| 17.2 | SMS Channel Adapter | 14.1, 7.1, 2.3 | Medium |
| 17.3 | Slack Channel Adapter | 14.1, 7.1, 2.3 | Medium |

---

## Parallelization Opportunities

These pieces can be built simultaneously if using multiple agents:

- **Track A (Data):** 0.1 → 1.1 → 1.2 → 2.1/2.2/2.3 (storage can parallelize)
- **Track B (Security):** 8.1 can start anytime after 0.1
- **Track C (Config):** 9.1 can start after 1.2

After the data models and storage are in place, Tracks A/B/C converge and the remaining pieces build sequentially.

---

## Notes for the Human Reviewer

Each build piece is designed so that when you receive it for review, you're looking at a coherent group of related files. Here's what to focus on during review:

- **Models (Phase 1):** Do the field types and validations match the architecture docs? Are required fields actually required?
- **Storage (Phase 2):** Is path sanitization present? Are writes atomic? Does HMAC verification work?
- **Routing (Phase 3):** Do session keys look right? Is isolation guaranteed?
- **Tools (Phase 4):** Are permissions checked before every execution? Does the decorator work intuitively?
- **LLM (Phase 5):** Are API keys protected? Does retry logic make sense?
- **Runtime (Phase 6):** Is the tool loop bounded? Does transcript capture everything?
- **Security (Phase 7-8):** Does validation actually strip params? Do patterns catch the attacks described in SECURITY.md?
- **Config/CLI (Phase 9-10):** Does `init` create everything needed? Can you chat with the mocked agent?
- **Gateway/Creator (Phase 11-12):** Are auth tokens validated? Do spawn limits hold?
- **Integration (Phase 15):** Do the security tests actually prove isolation?
- 