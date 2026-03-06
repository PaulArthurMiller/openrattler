# OpenRattler — Build Progress

## Build Piece SS-A — Social Secretary Models ✅

**Status:** Complete — on branch `build/social-secretary-models`, PR pending review

### Files Created

- `openrattler/models/social.py` — All Social Secretary data models:
  - `SocialAlert` — single flagged event for main to surface; confidence bounds, Literal event_type/urgency/etc.
  - `ContactEntry` — person record with relevant_details, social_ids, attention_level
  - `LearningObservation` — open question for main to resolve; lifecycle open→resolved→archived
  - `SocialSecretaryConfig` — processor config with cycle_interval_minutes (ge=15), security_profile Literal
  - `AlertQueue`, `ContactsStore`, `LearningQueue` — JSON-backed container models
- `tests/test_models/test_social.py` — 68 tests across 7 test classes

### Test Results

```
1165 passed, 1 skipped in 38.79s  (68 new + 1097 prior)
```

- `black --check .` — all files pass ✅
- `mypy openrattler/models/social.py` — no issues ✅
- `pytest` — 1165 collected (+1 skipped), 1165 passed ✅

### Design Decisions

- **JSON storage, not UniversalMessage**: Alerts, contacts, and observations are persistent state (accumulating, acknowledged over time) — not in-flight messages. The build guide explicitly confirms this split.
- **All constrained strings use `Literal` types**: Pydantic rejects invalid values at model construction, before they can reach storage or the LLM.
- **`cycle_interval_minutes ge=15`**: Enforced at the model level to prevent runaway API usage regardless of how the config is loaded.
- **`SocialAlert.raw_reference_id`**: Stores only the platform post ID (not content) — consistent with the security principle that raw social media content never persists past the evaluation cycle.

---

## Build Piece MCP-E — Integration and Bundled Servers ✅

**Status:** Complete — on branch `build/mcp-integration`, PR pending review

### Files Created / Modified

- `openrattler/mcp/manifests/weather-mcp.json` — Bundled weather MCP server manifest (NWS API, stdio transport)
- `openrattler/mcp/servers/__init__.py` — Package for bundled server implementations
- `openrattler/mcp/servers/weather.py` — `get_forecast` + `get_alerts` via FastMCP + httpx
- `openrattler/config/loader.py` — Added `MCPServerEntry`, `MCPConfig`; `mcp` field on `AppConfig`
- `openrattler/cli/chat.py` — MCP startup wiring in `open()`, `close()` method, cleanup in `start()`
- `pyproject.toml` — Added `httpx>=0.27` dependency
- `tests/test_mcp/test_integration.py` — 15 tests across 4 test classes
- `tests/test_mcp/test_weather_server.py` — 9 tests across 2 test classes

### Test Results

```
1097 passed, 1 skipped in 37.65s  (24 new + 1073 prior)
```

- `black --check .` — all files pass ✅
- `mypy openrattler/mcp/servers/weather.py openrattler/config/loader.py openrattler/cli/chat.py` — no issues ✅
- `pytest` — 1097 collected (+1 skipped), 1097 passed ✅

### Design Decisions

- **Graceful MCP startup failure**: `CLIChat.open()` wraps `connect_all_bundled()` in try/except so a failing bundled server (subprocess crash, timeout) is logged as a warning rather than crashing the entire chat session. This keeps existing `test_chat.py` tests green without mocking MCP.
- **`close()` method on CLIChat**: Separates MCP teardown from the interactive loop so tests that call `open()` directly (without `start()`) can still close cleanly. `start()` calls `close()` in its finally block.
- **`MCPConfig` in `AppConfig`**: Per-server enable/disable and security settings are now first-class config fields. Defaults mirror `MCPSecurityConfig` safe defaults — strict network isolation, 30s timeout, 100KB cap.
- **Weather server tested in isolation**: `get_forecast` and `get_alerts` are called directly (FastMCP's `@tool()` preserves function identity) with httpx mocked via `patch`. No subprocess is started in tests.

---

## Build Piece MCP-D — MCP Tool Bridge (Security Layer) ✅

**Status:** Complete — on branch `build/mcp-tool-bridge`, PR pending review

### Files Created / Modified

- `openrattler/mcp/bridge.py` — `MCPToolBridge` + `SecurityError` exception + `_MCP_RESPONSE_SUSPICIOUS_PATTERNS`
- `openrattler/tools/executor.py` — `mcp_bridge: Optional[MCPToolBridge]` param + MCP routing after permission check
- `tests/test_mcp/test_bridge.py` — 39 tests across 6 test classes

### Test Results

```
1073 passed, 1 skipped in 23.68s  (39 new + 1034 prior)
```

- `black --check .` — all files pass ✅
- `mypy openrattler/mcp/bridge.py openrattler/tools/executor.py` — no issues ✅
- `pytest` — 1073 collected (+1 skipped), 1073 passed ✅

### Design Decisions

- **`execute()` never raises**: Like `ToolExecutor.execute()`, the bridge catches all exceptions (including `SecurityError`) and returns an error `ToolResult`. The caller always receives a result, never a traceback.
- **`finally` block for audit logging**: The `MCPCallRecord` audit event is written in a `finally` block so it fires on every code path — success, approval denial, permission error, connection error, and size violation. State variables (`success`, `error`, `approval_result_str`, etc.) are updated before each `return`-equivalent path so the record is always accurate.
- **`trace_id` doubles as `call_id`**: The `trace_id` passed to `execute()` is used as the `ToolResult.call_id`. This lets the calling `ToolExecutor` correlate bridge results with original `ToolCall` objects by passing `uuid.uuid4().hex` from the executor's routing step.
- **Financial check always runs for financial servers**: `_check_financial_limits` is called with `Optional[MCPToolManifestEntry]` for every call to a server with `permissions.financial=True`, even for undeclared tools. Undeclared tools on financial servers should still respect the limit.
- **Sensitive prefix allowlist**: Parameters are stripped based on three known prefixes (`user.`, `payment.`, `credentials.`). Non-sensitive keys always pass through. Only keys explicitly listed in `data_access.read` bypass the strip. This is defence-in-depth — the agent shouldn't send undeclared sensitive data, but the bridge catches it if it does.
- **MCP routing in executor is backward-compatible**: The `mcp_bridge` param defaults to `None`. If not set, MCP tools fall through to the existing handler lookup (which returns `handler=None` → error), maintaining the existing behaviour for deployments not yet wired with a bridge.
- **Trust level enforced in bridge, not just registry**: Even though `check_permission` in the executor already filters by trust level, the bridge re-checks `agent_config.trust_level == TrustLevel.mcp`. Defence-in-depth: the bridge never trusts that permission checks upstream were applied correctly.

---

## Build Piece MCP-C — MCP Manager (Registry and Lifecycle) ✅

**Status:** Complete — on branch `build/mcp-manager`, PR pending review

### Files Created / Modified

- `openrattler/mcp/manager.py` — `MCPManager`: `load_manifest`, `load_manifests_from_directory`, `connect_server`, `disconnect_server`, `connect_all_bundled`, `disconnect_all`, `get_connection`, `get_manifest`, `list_servers`, `_cross_validate_tools`, `_register_mcp_tools`, `_audit_log`
- `openrattler/tools/registry.py` — `register` handler made `Optional`; `unregister()` method added
- `tests/test_mcp/test_manager.py` — 40 tests across 6 test classes

### Test Results

```
1034 passed, 1 skipped in 15.13s  (40 new + 994 prior)
```

- `black --check .` — all files pass ✅
- `mypy openrattler/` — no issues in 57 source files ✅
- `pytest` — 1034 collected (+1 skipped), 1034 passed ✅

### Design Decisions

- **`ToolRegistry.register` handler made `Optional[Callable]`**: MCP tools register with `handler=None` because `MCPToolBridge` (Build Piece D) routes execution through `MCPServerConnection` rather than a local Python callable. The `ToolExecutor` already handles `handler is None` gracefully — MCP tools take a different execution path.
- **`ToolRegistry.unregister(name)`**: New method to remove tools on disconnect. Tracks which tools belong to each server via `_registered_tools: dict[str, list[str]]` so cleanup is O(n) in tool count with no stale entries.
- **Trust-tier enforcement at `load_manifest` time**: Permission checks are done when manifests are registered, not at connect time. This separates policy enforcement from transport lifecycle.
- **Cross-validation per trust tier**: Undeclared tools on `auto_discovered` servers are filtered entirely; on `user_installed` servers they're registered with `requires_approval=True` forced; on `bundled` servers they're logged as warning but allowed. Tools in the manifest but absent from the server are logged as info only (optional tools are valid).
- **Undeclared tools always default to `requires_approval=True`**: Defence-in-depth. If a server reports a tool that wasn't declared in the manifest, the safest assumption is that it needs a human in the loop.
- **`MCPServerConnection` patched at manager module level in tests**: Since Piece B tests cover the connection layer, Piece C tests mock `MCPServerConnection` entirely to isolate manager logic. This keeps tests fast, deterministic, and focused.

---

## Build Piece MCP-B — MCP Server Connection Layer ✅

**Status:** Complete — on branch `build/mcp-server-connection`, PR pending review

### Files Created / Modified

- `openrattler/mcp/connection.py` — `MCPServerConnection`: `connect`, `disconnect`, `list_tools`, `call_tool`, `_run_stdio`, `_run_http`, `_build_safe_env`
- `tests/test_mcp/__init__.py` — new test package
- `tests/test_mcp/test_connection.py` — 34 tests across 6 test classes

### Test Results

```
994 passed, 1 skipped in 14.35s  (34 new + 960 prior)
```

- `black --check .` — all files pass ✅
- `mypy openrattler/` — no issues in 56 source files ✅
- `pytest` — 994 collected (+1 skipped), 994 passed ✅

### Design Decisions

- **Background task (`_run_stdio` / `_run_http`) holds context managers open**: The MCP SDK uses `async with` context managers for both transports. By running the `async with` block in a background `asyncio.Task`, we can expose `connect()` / `disconnect()` as clean method boundaries while keeping the context managers alive across the connection lifetime. `asyncio.Event` (`_initialized`, `_disconnect_event`) coordinates the lifecycle.
- **`asyncio.wait_for` on `_initialized.wait()` for connect timeout**: If the SDK handshake hangs, we cancel the background task (propagating `CancelledError` into the SDK's context managers for clean teardown) and raise `TimeoutError` to the caller.
- **Exception isolation in `_run_*`**: `except Exception` (not `BaseException`) catches SDK errors and stores them in `_init_error` for re-raising as `ConnectionError` from `connect()`. `CancelledError` (a `BaseException` in Python 3.8+) propagates through the except clause cleanly to the task's cancellation handler.
- **`_build_safe_env` starts from an allowlist, not a denylist**: The subprocess inherits only 11 named vars from the parent environment. Everything else — including `OPENAI_API_KEY`, `ANTHROPIC_API_KEY`, `DATABASE_PASSWORD` — is stripped. Manifest-declared vars are then overlaid.
- **`AsyncMock(side_effect=lambda: coroutine)` does NOT await the coroutine**: Discovered during testing. When `side_effect` is a regular (non-async) function, `AsyncMock` calls it and returns the result as the mock's return value — it does NOT check if the result is a coroutine and await it. Use `async def` side-effects or delay in the transport context manager instead.
- **`call_tool` timeout via `asyncio.wait_for`**: Wraps the session call with the connection's global `_timeout`. On timeout, `asyncio.TimeoutError` is caught and re-raised as `TimeoutError` with a descriptive message. The underlying session may be in an indeterminate state after timeout — callers should `disconnect()` if they hit this.

---

## Build Piece MCP-A — MCP Models and Configuration ✅

**Status:** Complete — merged via PR #24

### Files Created / Modified

- `openrattler/models/mcp.py` — All MCP Pydantic models: `MCPTrustTier`, `MCPNetworkPermissions`, `MCPDataAccessPermissions`, `MCPFileSystemPermissions`, `MCPToolManifestEntry`, `MCPPermissions`, `MCPServerManifest`, `MCPSecurityConfig`, `MCPCallRecord`
- `openrattler/models/__init__.py` — exports added for all 9 new MCP types
- `openrattler/mcp/__init__.py` — package docstring with architecture overview
- `tests/test_models/test_mcp.py` — 51 tests across 5 test classes
- `pyproject.toml` — added `mcp>=1.2.0` dependency

### Test Results

```
960 passed, 1 skipped in 13.42s  (51 new + 909 prior)
```

- `black --check .` — all files pass ✅
- `mypy openrattler/` — no issues in 55 source files ✅
- `pytest` — 960 collected (+1 skipped), 960 passed ✅

### Design Decisions

- **`server_id` regex `^[a-z0-9][a-z0-9_-]*$`**: Restricts to lowercase alphanumerics, hyphens, underscores — keeping it safe for use in `mcp:{server_id}.{tool_name}` prefixes and audit log fields without quoting or escaping concerns. No dots (would collide with tool name separator), no spaces.
- **Defaults are maximally restrictive**: `MCPPermissions` defaults all allowlists to empty, `exec=False`, `financial=False`, `max_cost_per_transaction=None`. Capabilities must be explicitly declared in the manifest — nothing is assumed.
- **`MCPCallRecord.params_keys` stores keys only**: Tool argument values (which may include API keys, addresses, payment tokens) never appear in audit records. Callers are responsible for passing `list(args.keys())`.
- **`MCPSecurityConfig.call_timeout_seconds` bounded `[5, 300]`**: Prevents both spin-loops on misconfiguration (too short) and indefinite hangs (too long). 5s is the minimum meaningful timeout for network round-trips; 300s covers legitimate long-running operations.
- **`MCPNetworkPermissions.allow_domains` path-char validator**: Domain entries containing `/` or `\` are rejected at construction time — a domain is a hostname, not a URL.
- **`MCPSecurityConfig.allow_auto_discovered` defaults to `"deny"`**: Auto-discovered servers are the highest risk (no prior user review). Safe default is to block them; users must explicitly opt-in to `"prompt"` or `"allow"`.

---


## Build Piece 17.3 — Slack Channel Adapter ✅

**Status:** Complete — on branch `build/17.3-slack-channel`, PR pending review

### Files Created / Modified

- `openrattler/channels/slack_adapter.py` — `SlackAdapter(ChannelAdapter)`: `connect`, `disconnect`, `receive`, `send`, `_fetch_new_messages`, `_is_valid_message`, `_build_universal_message`, `get_session_key`, `_audit_log`
- `openrattler/channels/__init__.py` — updated docstring to mention `SlackAdapter`
- `tests/test_channels/test_slack_adapter.py` — 35 tests across 8 test classes

### Test Results

```
909 passed, 1 skipped in 12.98s  (35 new + 874 prior)
```

- `black --check .` — 104 files unchanged ✅
- `mypy openrattler/` — no issues in 54 source files ✅
- `pytest` — 909 collected (+1 skipped), 909 passed ✅

### Design Decisions

- **`_is_valid_message()` helper instead of inline filter**: The bot-message gating logic is complex enough to warrant its own method. It handles four cases cleanly: human message (accepted), bot message (accepted only when `allow_bot_messages=True`), system event (always rejected), human message with subtype (rejected as safest default). This also makes the filtering logic unit-testable without needing a live poll.
- **`allow_bot_messages` config flag (default `False`)**: Extends the BUILD_GUIDE spec. By default only human user messages are delivered; when enabled, messages with a `bot_id` field are also accepted. The sender allowlist still applies — bot IDs must be explicitly listed. This supports team environments where OpenRattler agents need to interact with other bots without opening a security hole by default.
- **`sender_id = user or bot_id` extraction**: `_build_universal_message` extracts the sender ID from whichever field is present (`user` for humans, `bot_id` for bots), unifying the downstream allowlist and session-key logic.
- **Bearer token on session header, not URL/params**: `aiohttp.ClientSession(headers={"Authorization": f"Bearer {bot_token}"})` keeps the token off every individual request call and out of any logs that capture URL or params.
- **`data["ok"]` check, not `raise_for_status()`**: Slack always returns HTTP 200 even for errors. The `"ok"` field is the authoritative success indicator in both `_fetch_new_messages()` and `send()`.
- **`oldest` param bounds the poll window**: `_oldest_ts = str(datetime.now(timezone.utc).timestamp())` set in `connect()` ensures only messages from this session forward are fetched. This keeps response payloads small and prevents replaying pre-session history on reconnect.
- **Error handling in `receive()`, not `_fetch_new_messages()`**: Matching the email/SMS adapter pattern — `receive()` wraps `_fetch_new_messages()` in a `try/except` and logs `slack_fetch_error`. `_fetch_new_messages` itself can raise freely (raises `RuntimeError` on `ok=False`). This design makes tests straightforward: patch `_fetch_new_messages` to raise, assert audit event written by `receive()`.
- **`send()` error is `RuntimeError`, not `aiohttp.ClientResponseError`**: HTTP always 200 means `raise_for_status()` never fires for Slack errors. `RuntimeError` with the Slack `error` field message is the appropriate error type.
- **`json=payload` for send, not `data=form`**: Slack `chat.postMessage` requires a JSON body (unlike Twilio which uses form encoding).

### Notes for 17.4 (or next channel)

- **`_seen_ts` is in-process memory**: A process restart will re-deliver messages received before the restart. For production, persist seen timestamps or use a `oldest` cutoff that advances with each successful delivery.
- **No `mark as read` equivalent in Slack**: Unlike email (IMAP SEEN flag), Slack has no per-message read tracking via REST. Deduplication via `_seen_ts` is the only mechanism.
- **`oldest` filter is timestamp-precise**: Unlike Twilio's date-granular `DateSent>` filter, Slack's `oldest` param accepts a full timestamp string (e.g. `"1234567890.123456"`), so messages sent before `connect()` within the same second are correctly excluded.
- **Thread replies not fetched**: `conversations.history` returns only top-level messages. Fetching thread replies requires a separate `conversations.replies` call. Consider adding thread support in a future piece if needed.

---

## Build Piece 17.2 — SMS Channel Adapter ✅

**Status:** Complete — on branch `build/17.2-sms-channel`, PR pending review

### Files Created / Modified

- `openrattler/channels/sms_adapter.py` — `SMSAdapter(ChannelAdapter)`: `connect`, `disconnect`, `receive`, `send`, `_fetch_new_sms`, `_build_universal_message`, `get_session_key`, `_audit_log`
- `openrattler/channels/__init__.py` — updated docstring to mention `SMSAdapter`
- `tests/test_channels/test_sms_adapter.py` — 33 tests across 8 test classes

### Test Results

```
874 passed, 1 skipped in 12.86s  (33 new + 841 prior)
```

- `black --check .` — 102 files unchanged ✅
- `mypy openrattler/` — no issues in 53 source files ✅
- `pytest` — 874 collected (+1 skipped), 874 passed ✅

### Design Decisions

- **Persistent `aiohttp.ClientSession`, not per-poll**: `connect()` creates one `ClientSession` with `BasicAuth(account_sid, auth_token)` and `ClientTimeout(total=30)`. The session persists until `disconnect()`, unlike `EmailAdapter`'s per-poll IMAP connections. This is appropriate because Twilio's REST API doesn't have idle-timeout issues.
- **Error handling in `receive()`, not `_fetch_new_sms()`**: Matching the email adapter pattern — `receive()` wraps `_fetch_new_sms()` in a `try/except` and logs `sms_fetch_error`. `_fetch_new_sms` itself can raise freely. This design makes tests straightforward: patch `_fetch_new_sms` to raise, assert audit event written by `receive()`.
- **`_seen_sids` for deduplication**: Twilio has no "mark as read" equivalent for the Messages API, so the adapter tracks delivered SIDs in process memory. The set is reset on every `connect()` call, which is acceptable since a reconnect implies a new session.
- **SID marked seen before rate-limit check**: `_seen_sids.add(sid)` happens after the allowlist check but before the rate-limit check. This prevents re-delivery of a rate-limited message on the next poll (which could flood logs). A rate-limited message is effectively discarded for the session.
- **`DateSent>=` query param bounds the result set**: polling uses `DateSent>={YYYY-MM-DD}` (the connection date) so Twilio returns only messages from the current session window, keeping response payloads small.
- **`auth_token` only in `BasicAuth` on the session**: never passed as a URL parameter, query string, or audit detail. The session's `BasicAuth` handles HTTPS Basic Auth entirely inside `aiohttp`.
- **Send errors propagated**: HTTP failures in `send()` propagate to the caller — the adapter never silently swallows delivery failures.

### Notes for 17.3 (or next channel)

- Consider adding an optional `max_message_length` setting to `SMSAdapter.send()` to guard against Twilio's 1600-character SMS limit.
- `_seen_sids` is in-process memory — a process restart will re-deliver messages received before the restart. For production, persist seen SIDs to a fast store (Redis, SQLite) or rely on a `DateSent>=` cutoff that advances with each successful delivery.
- `DateSent>` Twilio filter parameter is date-granular (not datetime), so messages from the same day sent before `connect()` but not yet seen will be re-fetched until their SIDs are in `_seen_sids`.

---

## Build Piece 17.1 — Email Channel Adapter ✅

**Status:** Complete — on branch `build/17.1-email-channel`, PR pending review

### Files Created / Modified

- `openrattler/channels/email_adapter.py` — `EmailAdapter(ChannelAdapter)`, `_fetch_unseen`, `_smtp_send`, `_extract_text`, `_strip_html`, `_TextExtractorParser`
- `openrattler/channels/__init__.py` — updated docstring to mention `EmailAdapter`
- `tests/test_channels/test_email_adapter.py` — 38 tests across 8 test classes

### Test Results

```
841 passed, 1 skipped in 12.91s  (38 new + 803 prior)
```

- `black --check .` — 100 files unchanged ✅
- `mypy openrattler/` — no issues in 52 source files ✅
- `pytest` — 841 collected (+1 skipped), 841 passed ✅

### Design Decisions

- **Per-poll IMAP connections, not persistent**: `connect()` validates config and sets `_connected=True`; `disconnect()` clears it. Actual IMAP connections are opened and closed inside each `_fetch_unseen` call (via `asyncio.to_thread`). This avoids idle-timeout issues with IMAP servers while keeping the lifecycle API clean.
- **Patch sync helpers, not `asyncio.to_thread`**: Tests that also need audit events to be written patch `_fetch_unseen` and `_smtp_send` directly (as sync mocks). Patching `asyncio.to_thread` globally would intercept the audit log's `_sync_append` write, producing false negatives in audit-related assertions.
- **Fail-secure IMAP errors**: `receive()` catches any exception from `_fetch_unseen`, audit-logs it as `email_imap_error`, and treats it as "no messages". The loop continues on the next poll interval rather than propagating the error up and crashing the caller.
- **SMTP errors propagated**: Unlike IMAP errors, SMTP delivery failures in `send()` propagate to the caller. The caller is responsible for deciding whether to retry, queue, or alert — the adapter doesn't silently swallow delivery failures.
- **`_extract_text` prefers `text/plain`**: walks all MIME parts; takes the first `text/plain`, then falls back to `text/html` with `_strip_html`, then returns `"[no text content]"`. Attachments (non-text MIME parts) are silently skipped.
- **`_strip_html` uses stdlib `HTMLParser`**: `_TextExtractorParser` tracks a `_skip` flag that goes `True` on `<script>` / `<style>` opening tags and `False` on the corresponding closing tags. No third-party dependency required.
- **Subject stored as hash in audit log**: `send()` writes `subject_hash=sha256(subject)[:8]` to the audit event instead of the raw subject to limit sensitive data in audit logs.
- **Session key is a SHA-256 hash fragment**: `get_session_key` derives `sha256(from_address)[:12]` — the raw address is never part of the session key, so it can't contain injection characters and doesn't need further sanitisation.

### Notes for 17.2 (SMS Channel Adapter)

- Follow the same pattern: `ChannelConfig.settings` carries all SMS-specific values (Twilio SID, auth token, phone numbers).
- `sender_allowlist` equivalent for SMS would be an allowlist of phone number strings (normalized to E.164 format, e.g. `+15551234567`).
- `asyncio.to_thread` wrapping for Twilio SDK calls (or use `httpx` async client directly).
- Session key derivation: `sha256(phone_number)[:12]` — same pattern as email.
- Test strategy: patch the Twilio client (or HTTP call) directly, not `asyncio.to_thread`, for the same reason as email.

---

## Build Piece 16.1 — Human-in-the-Loop Approval System ✅

**Status:** Complete — on branch `build/16.1-approval-system`, PR pending review

### Files Created / Modified

- `openrattler/security/approval.py` — `ApprovalRequest` model, `ApprovalResult` model, `ApprovalManager` class, `CLIApprovalHandler` class
- `openrattler/tools/executor.py` — wired `ApprovalManager` into `ToolExecutor`; Step 3 now routes approval-required tools through the manager
- `tests/test_security/test_approval.py` — 29 tests across 8 test classes

### Test Results

```
803 passed, 1 skipped in 12.75s  (29 new + 774 prior)
```

- `black .` — all files unchanged ✅
- `mypy openrattler/` — no issues in 51 source files ✅
- `pytest` — 803 collected (+1 skipped), 803 passed ✅

### Design Decisions

- **Fail-secure timeout**: `asyncio.wait_for(event.wait(), timeout=...)` auto-denies on expiry. The timeout always results in denial — never in permission.
- **`asyncio.Event` per request**: `request_approval` awaits a per-`approval_id` event. `resolve()` sets it, unblocking the waiter. This keeps concurrency simple — multiple approvals can run simultaneously with no shared state between them.
- **Race prevention via `_decided` set**: if a handler calls `resolve` after a timeout has already auto-denied, `resolve` silently no-ops rather than raising. The set is checked before accessing `_pending` so the window is O(1).
- **Provenance from `AgentConfig`, never from tool arguments**: `_build_approval_request` takes the `AgentConfig` and extracts `trust_level`, `agent_id`, `session_key`, and a UTC timestamp into the `provenance` dict. The agent cannot spoof these values.
- **Backward-compatible executor**: `approval_manager` is `Optional` with default `None`. When `None`, a tool with `requires_approval=True` still executes (matching the previous stub behaviour). Production deployments should always supply a manager.
- **`CLIApprovalHandler._read_input` is a static method**: makes it patchable in tests without blocking on stdin (same pattern as `CLIAdapter._read_line`).
- **`_build_approval_request` takes manager explicitly**: avoids a `union-attr` mypy error; the manager is always non-None at the call site but mypy cannot prove that through the method boundary.
- **Audit trail covers both request and resolution**: `approval_requested` and `approval_resolved` events are always written, even on timeout, so the full decision history is reconstructible.

---

## Build Piece 15.1 — Integration Tests ✅

**Status:** Complete — on branch `build/15.1-integration-tests`, PR pending review

### Files Created / Modified

- `tests/conftest.py` — added `FullStack` dataclass, `make_text_response`, `make_tool_response`, `make_mock_provider` helpers, and `make_stack` fixture
- `tests/test_integration/test_full_flow.py` — 10 tests across 5 test classes covering the complete message flow
- `tests/test_integration/test_security_flow.py` — 11 tests across 5 test classes covering all security boundaries

### Test Results

```
774 passed, 1 skipped in 6.70s  (21 new + 753 prior)
```

- `black .` — 1 file reformatted (test_full_flow.py), all others unchanged ✅
- `mypy openrattler/` — no issues in 50 source files ✅
- `pytest` — 774 collected (+1 skipped), 774 passed ✅

### Coverage

**test_full_flow.py** (10 tests):
1. `TestTextMessageRoundTrip` — response returned, transcript has user+assistant entries, agent_turn audit event written
2. `TestToolCallFlow` — tool executed and final response returned, successful tool_execution audit logged
3. `TestToolPermissionDenied` — denied tool error fed back to LLM, denial audit logged with correct reason
4. `TestSessionIsolation` — transcripts for two sessions never bleed content into each other
5. `TestRateLimitTriggers` — RateLimiter blocks after threshold; independent keys don't interfere

**test_security_flow.py** (11 tests):
1. `TestTrustLevelEnforcement` — public-trust agent denied main-level tool; denial audit-logged with "trust level" in error
2. `TestPathTraversalRejected` — `".."`, absolute path, and non-`agent:` prefix session keys all raise `ValueError`
3. `TestTranscriptSessionIsolation` — unknown session returns empty transcript; two active sessions share no messages
4. `TestMemorySecurityBlocking` — command injection pattern blocks write, blocked write leaves memory unchanged, clean write succeeds
5. `TestSpawnLimitEnforcement` — second `create_agent` raises `SecurityError` after rate limit hit; denied spawn audit logged

### Design Decisions

- **`make_stack` factory pattern**: the `make_stack` fixture returns a callable factory so each test calls `make_stack(provider, ...)` and gets a completely isolated `FullStack` in `tmp_path` directories — no shared state between tests.
- **`FullStack` dataclass**: exposes every component directly (`runtime`, `transcript_store`, `memory_store`, `audit_log`, `tool_registry`, `tool_executor`, `agent_config`) so tests can inspect state without re-wiring.
- **Post-stack tool registration**: tools are registered on `stack.tool_registry` *after* calling `make_stack` — the shared registry reference between `ToolRegistry` and `ToolExecutor` means the tool is immediately available without rebuilding.
- **Rate limit test uses `RateLimiter` directly**: no LLM calls needed; the component is tested in isolation which is faster and more reliable than wiring a full message loop.
- **Spawn limit via `max_spawns_per_minute=1`**: the rate sliding window is the simplest limit to trigger reliably in tests (no registry counting edge cases); `_record_spawn` is called by `create_agent` after a successful spawn, so the second call sees `len(_spawn_times) >= 1` and raises.

---

## Build Piece 14.1 — Channel Adapter Base and CLI Adapter ✅

**Status:** Complete — on branch `build/14.1-channel-adapter-base`, PR pending review

### Files Created / Modified

- `openrattler/channels/__init__.py` — updated package docstring
- `openrattler/channels/base.py` — `ChannelAdapter` ABC: `channel_name`, `connect`, `disconnect`, `receive`, `send`, `get_session_key`
- `openrattler/channels/cli_adapter.py` — `CLIAdapter(ChannelAdapter)`: stdin/stdout with `text_to_message`, `_format_response`, `_read_line`
- `openrattler/cli/chat.py` — refactored: imports `CLIAdapter`, constructs `self._adapter` in `__init__`, `send()` uses `adapter.text_to_message` + `adapter._format_response`, `start()` uses `adapter.receive()` / `adapter.send()`
- `tests/test_channels/__init__.py` — new test package
- `tests/test_channels/test_cli_adapter.py` — 26 tests across 5 test classes

### Test Results

```
753 passed, 1 skipped in 27.34s  (26 new + 727 prior)
```

- `black --check .` — 94 files unchanged ✅
- `mypy openrattler/` — no issues in 50 source files ✅
- `pytest` — 753 collected (+1 skipped), 753 passed ✅

### Design Decisions

- **`text_to_message` is public** (not `_text_to_message`) — it's the canonical way to create a CLI inbound message and tests + `CLIChat` use it directly; exposing it keeps the API clean without blocking I/O.
- **`_format_response` is a static helper** — it takes a `UniversalMessage` and returns a printable string; this keeps `send()` thin and makes the formatting logic independently testable.
- **`receive()` uses `run_in_executor`** — keeps the event loop non-blocking; `_read_line` is the synchronous step so it can be patched in tests without importing asyncio internals.
- **`get_session_key` ignores `peer_info`** — the CLI has exactly one session (`agent:main:main`); ignoring peer_info is intentional and documented as a security note.
- **`start()` uses `connect()`/`disconnect()` lifecycle** — even though they're no-ops for CLI, using them sets the pattern all future channel adapters will follow.
- **`chat.py` refactoring is minimal** — only the message construction and formatting moved into the adapter; `CLIChat`'s component wiring, slash commands, and open/close logic are unchanged.

### Notes for Piece 15.1 (Integration Tests)

- `CLIAdapter.text_to_message(text)` is the standard way to inject CLI messages in integration tests.
- `CLIAdapter` can be subclassed or replaced by a test double that returns pre-canned messages via `receive()`.
- `create_response` requires explicit `from_agent` and `trust_level` args (not inferred from the original message) — test helpers must supply them.

---

## Build Piece 13.1 — Memory Security Agent ✅

**Status:** Complete — on branch `build/13.1-memory-security-agent`, PR pending review

### Files Created / Modified

- `openrattler/security/memory_security.py` — `SecurityResult` (Pydantic model), `MemorySecurityAgent` with `review_memory_change` pipeline
- `openrattler/storage/memory.py` — added `apply_changes_with_review` method to `MemoryStore`
- `tests/test_security/test_memory_security.py` — 25 tests across 5 test classes

### Test Results

```
727 passed, 1 skipped in 14.06s  (25 new + 702 prior)
```

- `black --check .` — 90 files unchanged ✅
- `mypy openrattler/` — no issues in 48 source files ✅
- `pytest` — 727 collected (+1 skipped), 727 passed ✅

### Design Decisions

- **`suspicious_patterns: list[str]` is category names** — not raw regexes. Callers pass category names from `SUSPICIOUS_PATTERNS` (e.g. `["command_injection", "instruction_override"]`). An empty list disables pattern blocking entirely, leaving only the session-level policy check. This mirrors the "tunable security" principle.
- **Never raises** — `review_memory_change` has an outer try/except that returns a `SecurityResult(suspicious=True, confidence=100)` on any unexpected error (fail-secure). The inner `_do_review` does the real work, cleanly separated for testability.
- **`apply_changes_with_review` in `MemoryStore`** — uses `TYPE_CHECKING` import to avoid a circular dependency at module load time (storage → security → storage/audit), while still satisfying mypy strict mode.
- **Confidence levels** — 100 for pattern match hits, 80 for policy-only violations (non-main session touching `instructions`), 0 for clean. The two-tier confidence scale gives callers signal about the threat type without adding complexity.
- **`approved_by = "security_agent"`** — history entries written via `apply_changes_with_review` correctly attribute the authorisation to the automated reviewer, not the requesting session.
- **Audit every review** — both clean and suspicious reviews are logged. This ensures the audit trail shows that security review *occurred* for every write, not only blocked ones.

### Notes for Piece 14.1 (Channel Adapter Base)

- `MemorySecurityAgent` is now available; `AgentRuntime` can wire it in via a new constructor parameter if desired (not required for 14.1).
- The `TYPE_CHECKING` guard in `memory.py` keeps import coupling loose — if `MemorySecurityAgent` is ever moved, only `memory.py` needs updating.
- `audit.query(event_type=...)` is the correct kwarg (not `event=`); document this for future test authors.

---

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

## Build Piece 7.1 — PitchCatch Validator Framework ✅

**Status:** Complete — on branch `build/7.1-pitchcatch-validator`, PR pending review

### Files Created / Modified

- `openrattler/security/rate_limiter.py` — `RateLimiter` with sliding per-minute and per-hour windows
- `openrattler/security/validator.py` — `PitchCatchValidator` with 6-step validation pipeline
- `tests/test_security/test_rate_limiter.py` — 13 tests across 4 test classes
- `tests/test_security/test_validator.py` — 29 tests across 6 test classes

### Test Results

```
467 passed in 5.72s  (42 new + 425 prior)
```

- `black --check .` — all files unchanged ✅
- `mypy openrattler/` — no issues ✅
- `pytest` — 467 collected, 467 passed ✅

### Design Decisions

- **6-step pipeline**: operation check → trust level check → required params check → param stripping → rate limiting → audit log. Failures at any step raise `PermissionError` (policy violation) or `ValueError` (structural problem) and are audit-logged before raising.
- **Trust level comparison via `_TRUST_ORDER`**: reuses the numeric rank table from `openrattler.tools.permissions`. The validator's `trust_level` parameter sets the *minimum acceptable incoming rank*. `security` and `main` share rank 2, so they are interchangeable at `main`-level components.
- **Param stripping (need-to-know)**: `validate_incoming` builds a new message with only required + optional params for the operation; the original message object is never mutated. Unknown params are silently dropped, not rejected — this is intentional (fail-open on unknown params prevents brittle coupling while still preventing data leakage to the component).
- **Two-step rate limiting (`check` then `record`)**: callers can inspect limits before committing; the validator calls `check` then `record` in sequence so the limit is consumed only on valid, non-rate-limited messages.
- **Sliding window, no external storage**: `RateLimiter` uses a per-key `deque` of UTC timestamps with an `asyncio.Lock` per key. Timestamps older than 1 hour are pruned on every access. Process-restart resets all limits — acceptable for the current threat model.
- **`structure_outgoing` takes explicit `session_key` and `trace_id`**: unlike the protocol doc example which uses context globals, the method accepts them as arguments for clarity and testability.

### Notes for Piece 8.1 (Input Sanitization)

- `PitchCatchValidator` currently handles structural and policy validation. Content-level suspicious pattern scanning (prompt injection, exfiltration patterns) belongs in Piece 8.1 (`scan_for_suspicious_content`). The validator can be extended to call the scanner as a step 0 pre-check once 8.1 is in place.
- `RateLimiter` is in-memory only. For multi-process deployments a Redis backend or similar shared store would be needed — mark as a future enhancement.

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
