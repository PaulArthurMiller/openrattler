# OpenRattler — Build Progress

## Build Piece 0.1 — Project Structure and Dev Environment ✅

**Status:** Complete — committed to `main`

### Files Created

- `openrattler/__init__.py` — package root with `__version__ = "0.1.0"`
- `openrattler/{models,gateway,agents,tools,storage,channels,mcp,security,config,cli}/__init__.py`
- `tests/__init__.py` and all `tests/test_*/` sub-packages
- `pyproject.toml` — project metadata, Python 3.11+ requirement, all dependencies
- `tests/conftest.py` — shared fixture placeholder
- `tests/test_smoke.py` — imports openrattler and asserts `__version__` is a non-empty string
- `.gitignore` — standard Python gitignore (`.venv/`, `__pycache__/`, `.mypy_cache/`, etc.)

### Test Results

```
1 passed in 0.04s
```

- `black --check .` — all 23 files unchanged ✅
- `mypy openrattler/` — no issues in 11 source files ✅
- `pytest` — 1 test collected, 1 passed ✅

### Implementation Notes

- Python 3.11.9 available via `py -3.11` Windows launcher (not on PATH as `python`)
- Virtual environment: `.venv/` (activate with `.venv/Scripts/activate` in bash)
- Build backend: `setuptools.build_meta` (not the newer `setuptools.backends.legacy:build`)
- `pytest-asyncio` 1.3.0 installed — `asyncio_mode = "auto"` configured in `pyproject.toml`
- Removed unused `import pytest` from `conftest.py` to satisfy black

---

## Build Piece 1.1 — UniversalMessage and Supporting Types ✅

**Status:** Complete — on branch `build/1.1-universal-message-models`, PR pending review

### Files Created

- `openrattler/models/errors.py` — `ErrorCode(str, Enum)` with all 8 standard codes
- `openrattler/models/messages.py` — `UniversalMessage` Pydantic v2 model + factory helpers
- `openrattler/models/__init__.py` — exports `UniversalMessage`, `create_message`, `create_response`, `create_error`, `ErrorCode`
- `tests/test_models/test_messages.py` — 44 tests across 5 test classes

### Test Results

```
45 passed in 0.09s  (44 new + 1 smoke)
```

- `black --check .` — 26 files unchanged ✅
- `mypy openrattler/` — no issues in 13 source files ✅
- `pytest` — 45 collected, 45 passed ✅

### Design Decisions

- `MessageType` and `TrustLevelType` are module-level `Literal` type aliases (not enums) — this keeps Pydantic validation tight while avoiding a parallel enum hierarchy for simple string literals
- `ErrorCode` is `str, Enum` so its `.value` is the raw string, and it JSON-serialises cleanly without extra configuration
- `create_message()` auto-generates both `message_id` (UUID4) and `trace_id` (UUID4) when not supplied; passing an explicit `trace_id` continues an existing trace
- `create_response()` defaults `operation` to the original's value — callers can override when the response operation name differs
- All timestamps are `datetime.now(timezone.utc)` — always timezone-aware UTC
- `# noqa: A002` comment on the `type` parameter suppresses the "shadows builtin" lint note while keeping the name consistent with the Pydantic field

---

## Build Piece 1.2 — Session, Agent, Tool, and Audit Models ✅

**Status:** Complete — on branch `build/1.2-session-agent-tool-models`, PR pending review

### Files Created

- `openrattler/models/sessions.py` — `SessionKey` (Annotated validated str), `Session`, `Peer` (self-referential with `model_rebuild()`)
- `openrattler/models/agents.py` — `TrustLevel` (str Enum), `AgentConfig`, `TaskTemplate` (with complexity range validator), `AgentCreationRequest`, `AgentSpawnLimits`
- `openrattler/models/audit.py` — `AuditEvent`
- `openrattler/models/tools.py` — `ToolDefinition`, `ToolCall`, `ToolResult`
- `openrattler/models/__init__.py` — updated to export all new symbols
- `tests/test_models/test_sessions.py` — 25 tests
- `tests/test_models/test_agents.py` — 31 tests
- `tests/test_models/test_audit.py` — 9 tests
- `tests/test_models/test_tools.py` — 22 tests

### Test Results

```
132 passed in 0.21s  (87 new + 45 prior)
```

- `black --check .` — 34 files unchanged ✅
- `mypy openrattler/` — no issues in 17 source files ✅
- `pytest` — 132 collected, 132 passed ✅

### Design Decisions

- `SessionKey` is `Annotated[str, BeforeValidator(...)]` — makes it a reusable, exportable type alias that enforces format at every validation point; rejects `..`, absolute paths, missing `agent:` prefix, and non-alphanumeric characters
- `Peer` uses `Optional["Peer"]` + `model_rebuild()` for the self-referential `parent` field (Pydantic v2 pattern)
- `TrustLevel` is `str, Enum` with values matching `TrustLevelType` literals in `messages.py` exactly — downstream permission checks can compare enum values directly to string literals
- `TaskTemplate.typical_complexity_range` uses a `@field_validator` to enforce 0–10 bounds and min≤max
- `ToolDefinition.trust_level_required: TrustLevel` (enum, not Literal) — permission layer can iterate over enum values and compare programmatically
- `ToolResult.result: Any` — tool output is intentionally untyped; the executor validates it before returning to the LLM

---

## Build Piece 6.1 — Agent Turn Loop ✅

**Status:** Complete — on branch `build/6.1-agent-turn-loop`, PR pending review

### Files Created / Modified

- `openrattler/models/sessions.py` — added `system_prompt: str` field to `Session`
- `openrattler/agents/runtime.py` — `AgentRuntime` class: `initialize_session`, `process_message`, and all helpers
- `tests/test_agents/test_runtime.py` — 23 tests across 5 test classes

### Test Results

```
425 passed in 5.80s  (23 new + 402 prior)
```

- `black --check .` — all files unchanged ✅
- `mypy openrattler/` — no issues ✅
- `pytest` — 425 collected, 425 passed ✅

### Design Decisions

- **Never raises**: `process_message` wraps all logic in `try/except` — tool-loop overflow, provider errors, and any unexpected exception are all returned as `type="error"` `UniversalMessage` objects. Callers always receive a structured reply.
- **Bounded tool loop**: `_MAX_TOOL_LOOPS = 10` caps the tool execution cycle per turn. If the limit is hit, an error response is returned and the audit log marks `exceeded_loop_limit: True`.
- **Memory key extraction**: `MemoryStore` only accepts colon-free identifiers (e.g. `"main"`), but `AgentConfig.agent_id` uses full session-key style strings (e.g. `"agent:main:main"`). `initialize_session` extracts the bare agent name via `session_key.split(":")[1]` for memory lookups, keeping the full `agent_id` on the `Session` object for routing/audit purposes.
- **System prompt composition**: `_build_system_prompt` appends a `## Memory` section when the memory dict is non-empty, so the LLM always has access to persistent facts without cluttering empty sessions.
- **Ephemeral tool messages**: `assistant` tool-call turns and `tool` result turns are added only to the in-memory `messages` list for the current turn — they are never written to the transcript store, keeping the transcript clean for `_build_messages` on subsequent turns.
- **Audit event per turn**: every `process_message` call logs an `agent_turn` event with `tool_loops`, `finish_reason`, and `exceeded_loop_limit`, regardless of success or failure.

---

## Build Piece 5.1 — LLM Provider Interface and OpenAI/Anthropic Implementations ✅

**Status:** Complete — on branch `build/5.1-llm-provider-abstraction`, PR pending review

### Files Created / Modified

- `openrattler/agents/__init__.py` — package docstring
- `openrattler/agents/providers/__init__.py` — package docstring
- `openrattler/agents/providers/base.py` — `LLMProvider` ABC, `LLMResponse`, `TokenUsage`
- `openrattler/agents/providers/openai_provider.py` — `OpenAIProvider` with retry/backoff
- `openrattler/agents/providers/anthropic_provider.py` — `AnthropicProvider` with message/tool format conversion
- `tests/test_agents/__init__.py` — test package
- `tests/test_agents/test_providers.py` — 29 tests

### Test Results

```
402 passed in 5.45s  (29 new + 373 prior)
```

- `black --check .` — 58 files unchanged ✅
- `mypy openrattler/` — no issues in 31 source files ✅
- `pytest` — 402 collected, 402 passed ✅

### Design Decisions

- **OpenAI format as canonical message format**: `complete()` accepts messages in OpenAI format (`{"role": "...", "content": "..."}`); `AnthropicProvider` converts internally — `system` messages are extracted and passed as Anthropic's top-level `system` parameter, `tool` role messages become Anthropic `tool_result` user turns
- **Tool format conversion**: tools are accepted in OpenAI function-calling format; Anthropic provider maps `function.parameters` → `input_schema`
- **Retry backoff**: both providers retry `RateLimitError` up to 3 times with `2^attempt` second delays (1 s, 2 s, 4 s); all other errors propagate immediately
- **API key safety**: keys are stored in `_client` only; they never appear in log output, error messages, or exception tracebacks — errors are re-raised verbatim from the SDK which sanitises them
- **Cost estimation**: per-model `_COST_PER_1K` tables (approximations); `estimated_cost_usd` is provided as a best-effort float, not billed amount
- **Tests use real SDK response objects**: `ChatCompletion`, `AnthropicMessage`, `TextBlock`, `ToolUseBlock` etc. are constructed directly from the SDK types rather than using `MagicMock` for response data, giving realistic parse coverage
- **Health checks**: both providers ping `client.models.list()`; return `False` on any exception

### Known Limitations: OpenAI Format as Canonical

The `complete()` interface uses OpenAI's message format as the canonical standard. This was a deliberate pragmatic choice (OpenAI format is the de facto industry standard; many providers implement it, so `OpenAIProvider` covers them all via `base_url`), but it bakes in asymmetry:

1. **Interface is not truly neutral.** `OpenAIProvider` is a passthrough. `AnthropicProvider` carries all the conversion burden. A properly symmetric design would define custom internal `Message`/`ToolResult` Pydantic models and have *each* provider convert from them.

2. **Anthropic-specific features are inaccessible.** Prompt caching, extended thinking (`thinking` content blocks), vision content, and strongly-typed structured output all require Anthropic-native constructs that do not map through the OpenAI format. The current interface provides no way to express them.

3. **Multi-turn tool use conversion is simplified.** The `tool_result` conversion (OpenAI `role:"tool"` → Anthropic `user` message with `tool_result` content block) handles the common single-tool case. Complex interleaved multi-tool turns may produce message sequences that the Anthropic API rejects.

4. **Tool arguments are a JSON string (OpenAI) vs. native dict (Anthropic).** `OpenAIProvider._parse_response` parses the string; malformed JSON falls back to `{"_raw": ...}`. Anthropic `input` is always a native dict and requires no parsing.

**Recommended follow-up (not a blocker for 6.1):** Define internal `Message` and `ToolResult` Pydantic models as the true canonical format. Have `AgentRuntime._build_messages()` produce those, and have each provider convert from them. This would make Anthropic-specific features expressible and remove the asymmetry.

### Notes for Piece 6.1 (Agent Turn Loop)

- `AgentRuntime.__init__` will accept a `LLMProvider` — either `OpenAIProvider` or `AnthropicProvider` (or any future implementation)
- `complete()` takes `messages: list[dict[str, Any]]` in OpenAI format; `AgentRuntime._build_messages()` must produce this format
- Tool calls in `LLMResponse.tool_calls` are already `ToolCall` objects ready for `ToolExecutor.execute()`

---

## Build Piece 4.2 — Built-in Tools ✅

**Status:** Complete — on branch `build/4.2-built-in-tools`, PR pending review

### Files Created / Modified

- `openrattler/tools/builtin/__init__.py` — package docstring
- `openrattler/tools/builtin/file_ops.py` — `file_read`, `file_write`, `file_list` with path sanitization
- `openrattler/tools/builtin/session_tools.py` — `sessions_history` with cross-session access controls
- `openrattler/tools/registry.py` — added `@overload` signatures for `tool()` to satisfy mypy strict mode
- `tests/test_tools/test_file_ops.py` — 26 tests across 3 test classes
- `tests/test_tools/test_session_tools.py` — 10 tests

### Test Results

```
373 passed in 1.15s  (36 new + 337 prior)
```

- `black --check .` — 53 files unchanged ✅
- `mypy openrattler/` — no issues in 27 source files ✅
- `pytest` — 373 collected, 373 passed ✅

### Design Decisions

- **Allowlist-only, disabled by default**: `_ALLOWED_DIRS` starts empty — no file access is possible until `configure_allowed_directories()` is called explicitly. This means importing the module cannot read or write files as a side effect.
- **Dual-layer path validation**: `..` is rejected in `Path.parts` *before* resolution (defence against traversal-via-symlink and OS normalisation tricks), then the fully-resolved path must be `relative_to` at least one allowed directory.
- **Configurable size limit**: `file_read` rejects files exceeding `_MAX_FILE_SIZE` (default 1 MB) to prevent memory exhaustion; tests can set `max_file_size=N` via `configure_allowed_directories`.
- **Atomic writes**: `file_write` writes to `.tmp` then calls `Path.replace()` (not `rename()`) for atomicity even when the target already exists on Windows.
- **`sessions_history` disabled by default**: module-level `_transcript_store` is `None` until `configure_transcript_store()` is called; any invocation before that raises `RuntimeError`.
- **`@overload` on `tool()`**: Added typed overloads (`@tool` vs `@tool(...)`) to `registry.py` so mypy strict mode can infer the return type and not flag decorated functions as untyped. The runtime implementation is unchanged.

### Notes for Piece 5.x (LLM Provider Abstraction)

- All built-in tools are ready to be registered into a `ToolRegistry` via `registry.register(fn._tool_definition, fn)` or by calling `configure_default_registry()` before importing the builtin modules.
- `sessions_history` will need `AgentRuntime` to wire up `configure_transcript_store(store)` at startup.
- `file_read`/`file_write`/`file_list` will need `configure_allowed_directories([agent_workspace])` at session start.

---

## Build Piece 4.1 — Tool Registry and Permission Checking ✅

**Status:** Complete — on branch `build/4.1-tool-registry-permissions`, PR pending review

### Files Created / Modified

- `openrattler/tools/__init__.py` — package docstring
- `openrattler/tools/permissions.py` — `check_permission()`, `needs_approval()`, `_TRUST_ORDER`
- `openrattler/tools/registry.py` — `ToolRegistry`, `@tool` decorator, `configure_default_registry()`
- `openrattler/tools/executor.py` — `ToolExecutor` (permission-gated, audit-logged, never-raising)
- `tests/test_tools/test_permissions.py` — 18 tests across 3 test classes
- `tests/test_tools/test_registry.py` — 22 tests across 2 test classes
- `tests/test_tools/test_executor.py` — 18 tests across 4 test classes

### Test Results

```
337 passed in 0.89s  (57 new + 280 prior)
```

- `black --check .` — 48 files unchanged ✅
- `mypy openrattler/` — no issues in 24 source files ✅
- `pytest` — 337 collected, 337 passed ✅

### Design Decisions

- **Trust level ordering**: `public(0) < mcp(1) < main(2) = security(2) < local(3)` — higher number = more trusted; an agent can only invoke a tool if its trust rank ≥ the tool's required rank
- **Deny takes priority**: `denied_tools` is checked before `allowed_tools`, so a tool in both lists is always rejected
- **Empty allowlist denies all**: an agent with `allowed_tools=[]` cannot invoke any tool, not even public ones
- **`@tool` decorator dual form**: supports both `@tool` (no parens) and `@tool(...)` (with parens) via `fn=None` default; attaches `._tool_definition` to the decorated function for introspection
- **Parameter inference**: `_infer_parameters()` skips runtime-injected names (`self`, `session`, `context`, `agent_config`), maps Python types to JSON Schema types, and marks parameters without defaults as `required`
- **`ToolExecutor` never raises**: every code path catches exceptions and returns a `ToolResult`; the LLM always receives a structured response, never a traceback
- **Approval stub**: `needs_approval(tool_def)` is evaluated on every call but not yet acted upon — the human-in-the-loop flow (Piece 16.1) will route through an `ApprovalManager` here
- **Audit log on every path**: success, permission denied, handler exception, and unknown-tool are all logged with `event="tool_execution"` and `success` bool

---

## Build Piece 3.1 — Session Router ✅

**Status:** Complete — on branch `build/3.1-session-router`, PR pending review

### Files Created / Modified

- `openrattler/gateway/__init__.py` — package docstring
- `openrattler/gateway/router.py` — `route_to_session()`, `Binding`, `resolve_agent()`
- `tests/test_gateway/test_router.py` — 35 tests across 5 test classes

### Test Results

```
280 passed in 0.94s  (35 new + 245 prior)
```

- `black --check .` — 42 files unchanged ✅
- `mypy openrattler/` — no issues in 21 source files ✅
- `pytest` — 280 collected, 280 passed ✅

### Design Decisions

- `route_to_session` takes `agent_id` (not `account_id` as the BUILD_GUIDE typo'd) — the parameter name must match what's embedded in the output key `agent:{agent_id}:...`
- `ALLOWED_CHANNELS` is a module-level `frozenset` used by both `route_to_session` and `resolve_agent` — allowlist, not denylist, per the security principle
- `resolve_agent` fails closed: raises `ValueError` on no match rather than returning a default agent, preventing silent misrouting
- Thread routing is recursive — each level validates its own `peer.id`, so every component of a deeply nested key is safe
- DM sessions always collapse to `agent:{agent_id}:main` regardless of peer ID, ensuring personal DM context is shared across reconnections
- `Binding` filter fields are `Optional[str]` — a `None` field on a binding acts as a wildcard (matches anything the caller provides for that key)

### Notes for Piece 4.1 (Tool Registry & Permissions)

- `AuditLog` is now needed as a dependency of `ToolExecutor` — the test fixture will inject an `AuditLog(tmp_path/...)` instance
- `TrustLevel` enum is in `openrattler.models.agents`; `ToolDefinition`, `ToolCall`, `ToolResult` are in `openrattler.models.tools` — import directly
- `AgentConfig.allowed_tools` and `AgentConfig.denied_tools` are both `list[str]` (tool names); `AgentConfig.trust_level` is `TrustLevel`

---

## Build Piece 2.3 — Audit Log ✅

**Status:** Complete — on branch `build/2.3-audit-log`, PR pending review

### Files Created

- `openrattler/storage/audit.py` — `AuditLog` + `audit_log()` convenience function + HMAC helpers + sync I/O helpers
- `tests/test_storage/test_audit.py` — 34 tests across 7 test classes

### Test Results

```
245 passed in 3.04s  (34 new + 211 prior)
```

- `black --check .` — 40 files unchanged ✅
- `mypy openrattler/` — no issues in 20 source files ✅
- `pytest` — 245 collected, 245 passed ✅

### Design Decisions

- **No `delete`, `clear`, `modify`, or `truncate` methods** — append-only by design; the audit log is intentionally write-only after the fact
- **HMAC signing**: when `hmac_key` is set, each event dict is serialized with `json.dumps(sort_keys=True, separators=(',',':'))` for canonical byte ordering, signed with HMAC-SHA256, and the `_hmac` hex digest is added to the written JSON line. Verification re-derives the canonical bytes and uses `hmac.compare_digest` (constant-time) to prevent timing attacks
- **Unsigned lines in a signed log are flagged as bad** — they may represent injected lines added after signing was enabled
- **`query()` returns the last `limit` matching events** (most recent tail), consistent with `load_recent` semantics in transcripts
- **`audit_log()` convenience function** uses an explicit `log=` kwarg or a module-level default set by `configure_default_log()`; silently no-ops when no log is configured so it's safe to call anywhere

### Notes for Piece 3.1 (Session Router)

- `AuditLog` is now ready to be injected into downstream components
- `AuditEvent` model is in `openrattler.models.audit`; `AuditLog` + `audit_log` are in `openrattler.storage.audit`
- Session routing produces keys of the form `agent:{agent_id}:{context}` — the router needs the `Peer` and `Binding` models from `openrattler.models.sessions`

---

## Build Piece 2.2 — Memory Store ✅

**Status:** Complete — on branch `build/2.2-memory-store`, PR pending review

### Files Created

- `openrattler/storage/memory.py` — `MemoryStore` + diff/path helpers + sync I/O helpers
- `tests/test_storage/test_memory.py` — 41 tests across 6 test classes

### Test Results

```
211 passed in 1.68s  (41 new + 170 prior)
```

- `black --check .` — 38 files unchanged ✅
- `mypy openrattler/` — no issues in 19 source files ✅
- `pytest` — 211 collected, 211 passed ✅

### Design Decisions

- Agent memory lives at `{base_dir}/{agent_id}/memory.json` — one directory and one file per agent
- Agent ID validation rejects `..`, absolute paths, and any character outside `[a-zA-Z0-9_-]`; colons are explicitly rejected so agent IDs cannot masquerade as session keys
- Writes are atomic via temp-file (`memory.tmp`) + `Path.replace()` rename; `replace()` is used (not `rename()`) because it is atomic even when the target already exists on Windows
- `compute_diff` excludes the `history` key from comparison — history grows monotonically and comparing it would produce spurious noise
- `apply_changes` silently ignores any `"history"` key in caller-supplied changes — callers can never overwrite history; it is always append-only
- History entries record `timestamp` (ISO UTC), `change` (human-readable diff summary), and `approved_by` (identity of authoriser)

### Notes for Piece 2.3 (Audit Log)

- `AuditEvent` model already exists in `openrattler/models/audit.py` from Piece 1.2 — import it directly
- The audit log is append-only JSONL (like transcripts) but with optional HMAC signing per entry
- `AuditLog` will be consumed by many downstream components — keep the constructor simple and `log()` fast

---

## Build Piece 2.1 — JSONL Transcript Storage ✅

**Status:** Complete — on branch `build/2.1-transcript-storage`, PR pending review

### Files Created / Modified

- `openrattler/storage/__init__.py` — package docstring
- `openrattler/storage/transcripts.py` — `TranscriptStore` + path helpers + sync I/O helpers
- `tests/test_storage/__init__.py` — empty package marker
- `tests/test_storage/test_transcripts.py` — 38 tests across 7 test classes

### Test Results

```
170 passed in 0.39s  (38 new + 132 prior)
```

- `black --check .` — 36 files unchanged ✅
- `mypy openrattler/` — no issues in 18 source files ✅
- `pytest` — 170 collected, 170 passed ✅

### Design Decisions

- Session key → filesystem path: replace `:` with path separators, append `.jsonl` suffix; `agent:main:main` → `{base_dir}/agent/main/main.jsonl`
- `_validate_session_key()` guards all public methods: rejects `..`, absolute paths, missing `agent:` prefix, and any character outside `[a-zA-Z0-9_-:]`
- Per-session `asyncio.Lock` stored in `self._locks` dict — safe because asyncio event loop is single-threaded between `await` points
- All file I/O dispatched via `asyncio.to_thread()` to keep the event loop unblocked
- `load_recent()` reads all lines then slices the tail — fast enough for typical session lengths; a backwards-seek optimisation can be added if needed
- `list_sessions()` uses `Path.rglob("*.jsonl")` and `_path_to_key()` for the reverse mapping
