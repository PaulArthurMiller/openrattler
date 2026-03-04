# OpenRattler Development Progress

## Current Status: Planning & Architecture

**Last Updated:** 2025-02-22

**Current Phase:** Phase 0 - Project Setup & Planning

---

## Completed

### 2025-02-22: Project Initialization
- ✅ Created project concept and goals
- ✅ Analyzed OpenClaw architecture for inspiration
- ✅ Identified security improvements (memory security layer, structured memory)
- ✅ Designed session isolation model
- ✅ Defined tool permission framework
- ✅ Created initial documentation:
  - `.claude/AGENTS.md` - Project context and guidelines
  - `.claude/ARCHITECTURE.md` - System design and data flow
  - `.claude/PROGRESS.md` - Development tracking (this file)

---

## In Progress

### Phase 0: Project Setup
- [ ] Create project structure (`openrattler/` package)
- [ ] Set up development environment
  - [ ] Python 3.11+ venv
  - [ ] Install core dependencies (aiohttp, pydantic, openai, anthropic)
  - [ ] Configure black, mypy, pytest
- [ ] Initialize git repository
- [ ] Create basic README.md with project overview

---

## Next Steps (Prioritized)

### Immediate (This Week)
1. Create project directory structure:
   ```
   openrattler/
     gateway/        # WebSocket server
     agents/         # Agent runtime
     tools/          # Tool framework
     storage/        # Sessions, memory, audit logs
     channels/       # Channel adapters
     cli/            # Command-line interface
   ```

2. Implement core data models (Pydantic):
   - `Session` - session state and history
   - `Message` - user/assistant/tool messages
   - `ToolCall` - tool invocation schema
   - `Memory` - structured memory store
   - `AuditEvent` - audit log entries

3. Build foundational storage layer:
   - JSONL session transcript read/write
   - Memory JSON load/save
   - Audit log appender

### Short Term (Next 2 Weeks)

**Gateway Foundation:**
- [ ] Basic WebSocket server (aiohttp)
- [ ] Session routing logic
- [ ] Token-based authentication
- [ ] Message broadcasting

**Agent Runtime:**
- [ ] LLM provider abstraction (OpenAI-compatible API)
- [ ] Session initialization (load transcript + memory)
- [ ] Agent turn loop (prompt → LLM → tools → response)
- [ ] Tool call parsing and execution

**Tool Framework:**
- [ ] Tool registry and decorator
- [ ] Permission checking
- [ ] Basic tools:
  - `file_read` - Read files with path validation
  - `file_write` - Write files with approval
  - `web_search` - Web search integration
  - `sessions_history` - Cross-session retrieval

**CLI Interface:**
- [ ] `openrattler init` - Initialize workspace
- [ ] `openrattler chat` - Direct chat with main agent
- [ ] `openrattler sessions list` - View active sessions
- [ ] `openrattler audit log` - View audit trail

### Medium Term (Next Month)

**Security Layer:**
- [ ] Memory security agent
- [ ] Approval request/response flow
- [ ] Command filtering (dangerous command detection)
- [ ] Audit log viewer

**Channels:**
- [ ] Telegram bot integration
- [ ] CLI channel adapter
- [ ] Channel routing configuration

**Testing:**
- [ ] Unit tests for session routing
- [ ] Integration tests for agent turns
- [ ] Security tests for injection attempts
- [ ] Tool permission tests

### Long Term (2-3 Months)

**Advanced Features:**
- [ ] Subagent spawning and orchestration
- [ ] Local LLM integration (Ollama)
- [ ] Privileged local agent
- [ ] WhatsApp channel (web automation)
- [ ] Discord bot integration
- [ ] Web dashboard for approvals

---

## Design Decisions Log

### 2025-02-22: Hybrid Agent Architecture (Direct Tools + Optional Creator)
**Decision:** Main/channel agents can use tools directly; Creator spawns specialists when needed
**Rationale:**
- Fast path for common operations (no extra latency)
- Creator provides security chokepoint for complex/risky tasks
- Best of both worlds: efficiency + security
- Avoids cost multiplication from excessive delegation

**When to use tools directly:**
- Common operations (search, email, file ops)
- Single-step tasks
- Conversational responses

**When to use Creator:**
- Need tools parent doesn't have
- Complex multi-step pipelines
- Parallel execution
- Task isolation

### 2025-02-22: Agent Creator as Security Chokepoint
**Decision:** Creator validates all subagent creation requests with hardcoded security logic
**Rationale:**
- Centralized enforcement (one place to audit/patch)
- Task-intent alignment (LLM validates request matches user message)
- Tool-task alignment (validates tools appropriate for stated task)
- Prevents privilege escalation (children can't exceed parent permissions)
- Complete audit trail (every creation logged)

### 2025-02-22: Task Templates for Agent Types
**Decision:** Use templates (not classes) to define specialist agent types
**Rationale:**
- Universal architecture (one Agent runtime, many configs)
- Easy to add new types (just add template, no code)
- Flexible (templates customizable per spawn)
- Consistent (all agents use same underlying runtime)

### 2025-02-22: Structured Memory vs Flat Files
**Decision:** Use structured JSON memory instead of flat Markdown (AGENTS.md)
**Rationale:** 
- Enables programmatic diff and review
- Type-safe with Pydantic validation
- Security layer can apply rules per field type
- Still renders to Markdown for LLM prompt

### 2025-02-22: JSONL for Session Transcripts
**Decision:** Use JSON Lines format for conversation history
**Rationale:**
- Efficient append (no full file rewrite)
- Easy to tail/stream
- Line-oriented for simple parsing
- Standard format (widely supported)

### 2025-02-22: Tool Permission Model
**Decision:** Per-agent allow/deny lists with approval prompts for high-risk
**Rationale:**
- Explicit is better than implicit (allowlist > denylist)
- Approval adds human oversight for edge cases
- Per-agent granularity enables privilege separation
- Auditable (all approvals logged)

### 2025-02-22: Session Isolation Strategy
**Decision:** Deterministic routing based on (channel, account, peer)
**Rationale:**
- Prevents cross-contamination by design
- No runtime checks needed (routing IS the boundary)
- Explicit cross-session access via tools
- Clear audit trail for all access

### 2025-02-22: UniversalMessage Protocol
**Decision:** Standard message format for all inter-component communication
**Rationale:**
- Enables extensibility (new channels, agents, MCP servers)
- MCP-compatible (can translate to/from JSON-RPC)
- Security hooks at every boundary (pitch-catch validation)
- End-to-end traceability (trace_id across all hops)

### 2025-02-22: MCP Integration with Trust Tiers
**Decision:** Three-tier MCP trust model (Bundled, User-Installed, Auto-Discovered)
**Rationale:**
- Bundled servers fully trusted (code-reviewed)
- User-installed requires explicit approval
- Auto-discovered never auto-installs
- Sandbox isolation for all MCP execution
- Multi-channel auth for financial transactions

### 2025-02-22: Model Selection Strategies
**Decision:** Support fixed, cost-optimized, quality-optimized, and adaptive model selection
**Rationale:**
- Users control cost/quality tradeoff
- Can use subscription accounts before API
- Adaptive selects model based on task complexity
- Fallback chains ensure availability

### 2025-02-22: Spawn Limits to Prevent Cascades
**Decision:** Hard limits on depth, width, rate, cost, and timeout for agent spawning
**Rationale:**
- Prevents infinite recursion
- Prevents exponential fan-out
- Prevents slow death spirals from retries
- Resource exhaustion protection
- Budget enforcement

### 2025-02-22: Retry Kills Previous Attempts
**Decision:** When retrying agent creation, kill previous attempt first
**Rationale:**
- Prevents multiple agents working on same task
- Avoids cost of late completions
- Avoids confusing duplicate responses
- Clean resource management

---

## Known Issues / Tech Debt

*None yet - project just starting!*

---

## Questions / Blockers

### Open Questions
1. **Approval UI**: Should we build a web dashboard or stay CLI-only initially?
   - *Leaning toward:* CLI-only for MVP, web dashboard in Phase 2
   
2. **Subagent isolation**: In-process (asyncio tasks) or subprocess?
   - *Leaning toward:* In-process for simplicity, subprocess if we need hard isolation

3. **Security agent model**: Rule-based scanner or full LLM review?
   - *Leaning toward:* Hybrid - rules for obvious issues, LLM for subtle patterns

4. **Local LLM timeline**: When to integrate Ollama?
   - *Decision:* Defer to Phase 4, focus on cloud LLM first

### Blockers
*None currently*

---

## Resources & References

- OpenClaw repo: https://github.com/openclaw/openclaw
- OpenClaw docs: https://docs.openclaw.ai
- Python AsyncIO: https://docs.python.org/3/library/asyncio.html
- Pydantic: https://docs.pydantic.dev/
- OWASP Python Security: https://cheatsheetseries.owasp.org/cheatsheets/Python_Security_Cheat_Sheet.html

---

## Notes for Future Sessions

- Focus on getting one complete vertical slice working (CLI → Gateway → Agent → Tool → Response)
- Don't over-engineer the first iteration
- Prioritize security architecture over feature velocity
- Document decisions as we go
- Run security review on every new tool before merging

---

## Session Log

### Session 1 (2025-02-22)
- Initial architecture discussion with human
- Created planning documents
- Identified skills needed for development
- Ready to start implementation

---

## Build Pieces Completed

### Piece 8.1 — Input Validation and Path Sanitization (2026-03-04)

**Files Created:**
- `openrattler/security/sanitize.py` — `sanitize_path`, `sanitize_session_key`, `validate_agent_id`
- `openrattler/security/command_filter.py` — `DANGEROUS_COMMANDS`, `CommandFilter`, `filter_command`
- `openrattler/security/patterns.py` — `SUSPICIOUS_PATTERNS`, `scan_for_suspicious_content`
- `tests/test_security/test_sanitize.py` — 17 tests (1 skipped: symlink on Windows)
- `tests/test_security/test_command_filter.py` — 25 tests
- `tests/test_security/test_patterns.py` — 27 tests

**Test Results:** 544 passed, 1 skipped — full suite clean

**Key Design Decisions:**
- `sanitize_path` resolves symlinks before checking containment (catches symlink escapes)
- `CommandFilter` deep-copies `DANGEROUS_COMMANDS` at construction so mutations never affect the global
- `SUSPICIOUS_PATTERNS` uses `(category, regex)` tuples for structured matching
- Pattern checks in `filter_command` run before per-command rules to catch injected arguments
- `scan_for_suspicious_content` returns one entry per regex match (not per pattern), capturing the matched text

**Notes for Next Piece (9.1 — Configuration System):**
- `sanitize_path`, `sanitize_session_key`, and `validate_agent_id` should be used inside config loading wherever paths or IDs appear in config files
- `CommandFilter` and `scan_for_suspicious_content` should be wired into the tool executor and security agent in later pieces
- The symlink test is skipped on Windows without elevated privileges; it will pass on Linux/macOS CI

### Piece 9.1 — Configuration Loading and Security Profiles (2026-03-04)

**Files Created:**
- `openrattler/config/__init__.py` — public API exports
- `openrattler/config/loader.py` — `SecurityConfig`, `BudgetConfig`, `ChannelConfig`, `AppConfig`, `load_config`, `save_config`, `DEFAULT_CONFIG_PATH`
- `openrattler/config/profiles.py` — `SECURITY_PROFILES`, `PROFILE_ORDER`, `apply_profile`
- `tests/test_config/test_loader.py` — 14 tests
- `tests/test_config/test_profiles.py` — 21 tests

**Test Results:** 579 passed, 1 skipped — full suite clean

**Key Design Decisions:**
- `SecurityConfig` uses `Optional[bool] = None` for all layer fields so `None` means "use profile default" — explicit `True`/`False` means user override
- `apply_profile` resolves `None` → profile default, preserves non-None user values; never mutates the input config
- `ChannelConfig.settings: dict[str, Any]` holds channel-specific keys (e.g. twilio_sid) cleanly without `extra="allow"` complexity
- `save_config` creates parent dir with `mode=0o700` to protect secrets at rest
- `load_config` returns default `AppConfig()` for missing files — first-run works without setup

**Notes for Next Piece (10.1 — CLI Chat Interface):**
- Import `load_config`, `apply_profile` from `openrattler.config` for config loading in the CLI
- `ChannelConfig` is the right model to use for the CLI channel entry in `config.channels["cli"]`
- `DEFAULT_CONFIG_PATH` (`~/.openrattler/config.json`) should be the default for `openrattler init`

### Piece 10.1 — Basic CLI Chat Interface (2026-03-04)

**Files Created:**
- `openrattler/cli/chat.py` — `CLIChat` with `open()`, `send()`, `start()`, `_handle_command()`; slash commands: /quit, /exit, /help, /session, /history [n], /audit [n]
- `openrattler/cli/main.py` — `init_workspace()`, `list_sessions()`, argparse CLI with `init`, `chat`, `sessions list` subcommands
- `openrattler/__main__.py` — `python -m openrattler` entry point
- `tests/test_cli/test_init.py` — 13 tests for `init_workspace` and `list_sessions`
- `tests/test_cli/test_chat.py` — 14 tests for `CLIChat` with mocked LLM provider

**Test Results:** 606 passed, 1 skipped — full suite clean

**Key Design Decisions:**
- `CLIChat` accepts an optional injected `LLMProvider` so tests never touch a real API
- `open()` does all async component initialisation; `send()` is the unit-testable message processor; `start()` is the production stdin loop
- `CLI_SESSION_KEY = "agent:main:main"` is hardcoded — user input can never override the session routing
- Provider auto-detected from `ANTHROPIC_API_KEY` then `OPENAI_API_KEY` env vars; `RuntimeError` if neither is set
- `send()` always returns a printable string — error responses become `[Error: ...]` rather than raising
- `Session.key` (not `session_key`) is the Pydantic field name on the `Session` model

**Notes for Next Piece:**
- The next build piece is 11.1 (check BUILD_GUIDE.md for details)