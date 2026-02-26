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
