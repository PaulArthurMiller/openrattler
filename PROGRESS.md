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

### Next Steps for Piece 2.1

- Reference documents: `ARCHITECTURE.md` (Session Routing, JSONL for Session Transcripts), `PROGRESS.md`
- Create feature branch: `git checkout -b build/2.1-transcript-storage`
- Implement `openrattler/storage/transcripts.py` with `TranscriptStore`
- Path sanitization must reject `..`, absolute paths, and non-safe characters in session keys
- Use `asyncio` for all file I/O; concurrent append safety is required
