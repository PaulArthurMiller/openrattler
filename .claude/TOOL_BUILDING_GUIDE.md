# Tool Building Guide

This guide is the authoritative reference for adding new tools to OpenRattler. It exists because two bugs in the same session traced to the same root: no single document explained what "done" means when a tool is built. Follow the checklist in Section 5 and the testing requirements in Section 7 every time.

**Motivating bugs:**
- Google tools invisible to Corvus: `config.google.enabled` defaulted to `False`; tools were coded and registered but the feature flag was never enabled in config, so they never entered the agent's allowlist.
- Weather MCP tools showed "not enabled" in system prompt: a display-sort sentinel rank (4) was accidentally used for the permission-authorization check, producing an empty "authorized:" line that Corvus misread as "no agent can use this."

Both would have been caught by one integration test verifying the full registration-to-visibility chain.

---

## 1. The Two Security Systems

Every tool in OpenRattler is governed by **two independent gates** that serve completely different purposes. Both must pass for a tool call to execute. They are not alternatives — you always set both.

```
Agent calls tool
      │
      ▼
Gate 1: PERMISSION  ──── check_permission()  (permissions.py)
      │                  Q: Does this agent have access at all?
      │                  Inputs: allowed_tools list, denied_tools list, trust_level_required
      │
      ▼ (if allowed)
Gate 2: APPROVAL    ──── needs_approval()    (permissions.py)
      │                  Q: Does this specific call need human sign-off?
      │                  Inputs: action_level, ApprovalThresholdPolicy (from security profile)
      │
      ▼ (if approved or not required)
    Handler executes
```

**Gate 1 — Permission (trust_level_required)**
Controls *who* can call the tool. Set once in ToolDefinition. An agent must appear in the tool's allowed_tools list AND its trust tier must meet or exceed `trust_level_required`.

**Gate 2 — Approval (action_level)**
Controls *how dangerous* this particular call is. Compared against the current security profile's threshold at runtime. A read-only call at level 5 never triggers approval under standard/minimal; a git-push at level 2 always triggers it.

Neither gate knows about the other. You can have a tool that requires `local` trust AND level-1 approval. Or `main` trust AND level-5 (never needs approval). Choose each independently based on the right criterion.

---

## 2. Action Levels (1–5) — The Risk/Approval Gate

**Source:** `openrattler/security/action_levels.py`

The action level expresses the consequence of executing this tool once. **Default is 5 (safest) — every tool must explicitly opt into a lower level.**

| Level | Meaning | Requires approval under… | Real examples |
|-------|---------|--------------------------|---------------|
| **1** | Permanent, irreversible, or financial cost | All profiles (minimal, standard, paranoid) | `cc_promote_request` (merge to main), `send_email` (level 1 in some contexts), `drop_table` |
| **2** | Significant external action — hard to reverse | standard and paranoid | `send_sms`, `send_slack_message`, `send_email`, `cc_run_with_shell`, `cc_git_push_branch`, `gmail_archive` |
| **3** | Moderate — modifies local state | paranoid only | `file_write`, `memory_write`, `cc_write_task`, `cc_git_commit`, `gmail_star_message`, `gmail_apply_label`, `gmail_create_label` |
| **4** | Low impact — accesses sensitive cross-agent state | paranoid only | `sessions_history` (reads other sessions' transcripts) |
| **5** | Minimal — read-only or fully sandboxed | Never (except paranoid) | `file_read`, `file_list`, `gmail_list_threads`, `gmail_read_thread`, `cc_read_analyze`, `memory_read` |

**Profile → threshold mapping:**

| Profile | Threshold | Tools requiring approval |
|---------|-----------|--------------------------|
| `minimal` | 1 | Level 1 only |
| `standard` | 3 | Levels 1, 2, 3 |
| `paranoid` | 5 | All levels (including read-only) |

Formula: `requires_approval = (action_level <= threshold)`

### Choosing the Right Action Level

Ask these questions in order:

1. **Is this operation permanent or does it have a financial cost?** (deletes, external sends you can't recall, billing triggers) → Level 1
2. **Does it reach outside the machine in a hard-to-reverse way?** (send to external API, push to remote git) → Level 2
3. **Does it write to local state?** (files, memory, commits, labels, configuration) → Level 3
4. **Does it read sensitive state across agent boundaries?** (session transcripts, other agents' data) → Level 4
5. **Is it read-only and sandboxed?** → Level 5 (default)

### Special Case: Dead Stop Actions

Some tool names are hardcoded in `DEAD_STOP_ACTIONS` (action_levels.py:77–90) and **may never execute under any circumstances** — no approval flow is triggered, no handler is called, no config can permit them. This check runs before the permission gate:

```python
DEAD_STOP_ACTIONS: frozenset[str] = frozenset({
    "force_push_main",
    "drop_table",
    "rm_workspace_recursive",
    "cc_bypass_permissions",
    "cc_push_main",
})
```

If you are building a tool that would do something in this category, it should not exist as a callable tool at all.

---

## 3. Trust Levels — The Access Control Gate

**Source:** `openrattler/models/agents.py`, `openrattler/tools/permissions.py`

Trust levels are **agent identity tiers**, not risk ratings. `trust_level_required` on a ToolDefinition means: "only agents at this tier or above may call this tool." They answer "who," not "how dangerous."

| Trust Level | Permission Rank | Meaning | When to use as `trust_level_required` |
|-------------|-----------------|---------|---------------------------------------|
| `public` | 0 | Sandboxed agents; externally-facing | Only for genuinely safe, read-only tools with no user data exposure |
| `mcp` | 1 | MCP server agents; also the default for MCP tools | Set this on tools that any trusted agent (main and above) should be able to call — mostly MCP tools themselves |
| `main` | 2 | Personal assistant (Corvus) — standard tier | **Default for all builtin tools.** Use unless there's a specific reason to restrict further or loosen. |
| `security` | 2 | Memory review agent | Set on tools only the security agent should access (memory diff, pattern analysis); same numeric rank as main |
| `local` | 3 | Elevated agent with exec rights | Only for tools that do shell execution, unrestricted file operations, or require explicit escalation |

**Numeric rank is used for the permission check, not the name.** An agent with `trust_level=main` (rank 2) can call tools requiring `trust_level_required=mcp` (rank 1) because 2 ≥ 1. An agent with `trust_level=main` cannot call tools requiring `trust_level_required=local` (rank 3) because 2 < 3.

### Common confusion: `TrustLevel.mcp` on a ToolDefinition

When you see `trust_level_required=TrustLevel.mcp` on a built-in ToolDefinition, it does NOT mean "this is a risky MCP call." It means "any agent at the mcp tier or above can use this." Since `main` (rank 2) is above `mcp` (rank 1), Corvus can call it.

This is the standard for all MCP tool registrations — they're given `TrustLevel.mcp` so they sit just below the main personal-assistant tier and any trusted agent can reach them.

### Choosing the Right Trust Level

| Question | Answer → Level |
|----------|----------------|
| Is this tool for an external-facing, sandboxed use case? | `public` |
| Is this an MCP server tool (registered via MCPManager)? | `mcp` |
| Is this a standard personal assistant tool for Corvus? | `main` (almost always) |
| Should only the security review agent access this? | `security` |
| Does this require elevated permissions (exec, full fs)? | `local` |

---

## 4. How the Two Systems Appear in the System Prompt

The `_build_tools_block()` method in `openrattler/identity/loader.py` generates the tools section Corvus reads at session start. It groups tools by `trust_level_required` and shows:

```
#### `main` trust required — authorized: `main`, `local`, `security`

| Tool | Description | Approval? |
|------|-------------|-----------|
| `gmail_read_thread` | Read the full content... | No |
| `gmail_archive`     | Archive a Gmail thread  | **Yes ⚠️** |
```

- **"Authorized"** lists which agent tiers can call this tool.
- **"Approval?"** reflects `requires_approval` on the ToolDefinition (which the approval gate sets when `action_level <= profile_threshold`).

For MCP tools (trust_level_required=TrustLevel.mcp), the authorized tiers correctly show `main`, `local`, `security` — all tiers with rank ≥ 1. If you see an empty "authorized:" line for MCP tools, it means the display-rank bug has re-appeared (see `_MCP_PERM_RANK` in loader.py:85–88).

---

## 5. The 5-Step Registration Checklist

**All five steps are required.** Every step is necessary; none is sufficient alone.

### Step 1: Write the Tool Code

**For simple stateless tools — use the `@tool` decorator** (`openrattler/tools/registry.py`):

```python
from openrattler.tools.registry import tool
from openrattler.models.agents import TrustLevel

@tool(
    trust_level_required=TrustLevel.main,   # who can call it
    action_level=5,                          # how risky (1=most, 5=least)
    security_notes="Read-only; no side effects.",
)
async def my_new_tool(query: str) -> str:
    """One-line description for Corvus (becomes the tool description)."""
    ...
```

The decorator registers the tool immediately at import time — but only if `configure_default_registry()` has already been called. If the import order is uncertain, use explicit registration instead.

**For stateful tools (bound to handler objects) — use explicit registration** (same pattern as Gmail, Drive, Calendar, Tasks tools):

```python
# In your tool file:
MY_TOOL_DEF = ToolDefinition(
    name="my_tool",
    description="What it does.",
    parameters={"type": "object", "properties": {...}, "required": [...]},
    trust_level_required=TrustLevel.main,
    action_level=3,
    security_notes="Modifies local state.",
)

class MyToolHandler:
    def __init__(self, dependency: SomeDependency) -> None:
        self._dep = dependency
    
    async def handle(self, param: str, *, call_id: str = "") -> ToolResult:
        ...

def register_my_tools(registry: ToolRegistry, handler: MyToolHandler) -> None:
    registry.register(MY_TOOL_DEF, handler.handle)
```

### Step 2: Wire into startup.py

Add the import and registration call to `openrattler/startup.py` in the correct position in the wiring sequence. The order matters — tools must be registered before step 11b (where `_resolve_agent_tools()` runs, at line ~825).

**For always-on tools** — add after step 10 (SocialTools/NarrativeMemoryTools), before step 11:

```python
# startup.py — inside build_application()
from openrattler.tools.builtin.my_tools import MyToolHandler, register_my_tools

my_handler = MyToolHandler(dependency=some_dep)
register_my_tools(registry, my_handler)
```

**For feature-flagged tools** — add inside the appropriate `if config.*.enabled:` block:

```python
if config.my_feature.enabled:
    from openrattler.tools.builtin.my_tools import MyToolHandler, register_my_tools
    my_handler = MyToolHandler(...)
    register_my_tools(registry, my_handler)
    logger.info("My tools registered.")
else:
    logger.debug("My tools disabled (config.my_feature.enabled=False).")
```

### Step 3: Add Tool Names to `~/.openrattler/config.json`

The `tools.trust_defaults.main` list is **manually maintained**. It is the agent's explicit allowlist. `check_permission()` will deny any tool not in this list, regardless of whether it's in the registry.

```json
"tools": {
    "trust_defaults": {
        "main": [
            ...existing tools...,
            "my_new_tool"
        ]
    }
}
```

For MCP tools, use the namespaced name:
```json
"mcp:my-server.tool_name"
```

**This is the step most commonly skipped.** A tool in the registry but absent from this list is effectively invisible to Corvus.

### Step 4: Update ToolsConfig Defaults in loader.py

The `trust_defaults` in `openrattler/config/loader.py` (class `ToolsConfig`, field `trust_defaults`, ~line 552) provides the defaults used for **fresh installations** that have no `config.json` yet. Add your tool name to the appropriate trust level list there too.

```python
# loader.py — inside ToolsConfig.trust_defaults default_factory
"main": [
    ...existing tools...,
    # --- My New Feature ---
    "my_new_tool",
],
```

Both `loader.py` and `config.json` must be updated. Users with existing config files won't pick up loader.py defaults automatically.

### Step 5 (Feature-Flagged Tools Only): Document and Enable the Feature Flag

If the tool is gated behind `config.my_feature.enabled`, three things are needed:

**a) The feature config class** must exist in `openrattler/config/loader.py` with `enabled: bool = Field(default=False)`.

**b) The tool names must be in trust_defaults** regardless of whether the flag is on or off. Names in the allowlist are harmless when the tools aren't registered; they become active when the flag is enabled. This prevents the "tools are in trust_defaults but feature is off → silent failure" problem.

**c) Document the flag** in the config comment and in PROGRESS.md so future developers know to flip it. When the feature is ready for use, the user must add the section to their config.json:

```json
"my_feature": {
    "enabled": true,
    ...other settings...
}
```

**For Google Workspace tools specifically**: the section is `"google"` with `"enabled": true`, and the credentials must be placed at the path specified by `credentials_file` before the auth flow (`openrattler google-auth`).

---

## 6. MCP Tool Specifics

MCP tools follow a slightly different path because they are registered by `MCPManager` at server-connect time, not by startup.py directly.

### Manifest Requirements

Every bundled MCP server needs a manifest at `openrattler/mcp/manifests/{server_id}.json`:

```json
{
    "server_id": "my-server",
    "version": "1.0.0",
    "publisher": "openrattler",
    "verified": true,
    "trust_tier": "bundled",
    "permissions": {
        "network": {
            "allowed_domains": ["api.example.com"],
            "deny_all_others": true
        },
        "data_access": {"read": [], "write": []},
        "file_system": {"read": [], "write": []},
        "exec": false,
        "financial": false
    },
    "tools": [
        {
            "name": "my_tool",
            "description": "What it does.",
            "requires_approval": false,
            "cost_estimate": "none",
            "side_effects": "none"
        }
    ],
    "transport": "stdio",
    "command": "python",
    "args": ["-m", "openrattler.mcp.servers.my_server"],
    "env": {}
}
```

**Key fields:**
- `server_id` — used as the namespace prefix for tool names
- `trust_tier` — `"bundled"` for co-deployed servers; `"user_installed"` for third-party; `"auto_discovered"` is blocked by default
- `permissions.network.allowed_domains` — restrict outbound network access; MCP server subprocesses only see these domains
- `tools[].requires_approval` — per-tool approval flag visible to MCPToolBridge

### MCP Tool Naming

Tools are registered as `mcp:{server_id}.{tool_name}` — for example, `mcp:weather-mcp.get_forecast`. This namespaced name is what goes in `trust_defaults.main` and what Corvus uses in tool calls.

### MCP Tool Trust and Action Levels

`MCPManager._register_mcp_tools()` always sets:
- `trust_level_required = TrustLevel.mcp` (rank 1 — main agents can call it)
- `requires_approval` from the manifest entry (defaults True for undeclared tools)
- `action_level` is **not set from the manifest** — it defaults to 5

If an MCP tool warrants a non-default action level, add a post-registration override or adjust the manifest entry to reflect the approval intent via `requires_approval`.

### MCP Registration Happens at Server Connect

Unlike builtin tools, MCP tools enter the registry when `mcp_manager.connect_all_bundled()` runs (startup step 8), not at startup step 10. This means:
- Step 11b (`_resolve_agent_tools`) runs after MCP connection, so the names are available for the allowlist merge.
- But if MCP connection fails (exception in `connect_all_bundled()`), the tools are silently absent. Startup continues without them — this is intentional (non-fatal).

### MCPToolBridge Security Pipeline

MCP calls go through `openrattler/mcp/bridge.py` instead of a local handler. The bridge adds:
1. **Param sanitization** — strips fields not in `manifest.permissions.data_access.read`
2. **Financial limit check** — rejects if manifest/config financial limits exceeded
3. **Approval gate** — routes to ApprovalManager if `requires_approval=True`
4. **Response size check** — hard blocks if response exceeds `max_response_size_bytes`
5. **Suspicious pattern scan** — flags credential-like strings or injection patterns in response
6. **Audit logging** — records call metadata (param keys, not values; response size; timing)

---

## 7. Required Tests for Every New Tool

Every new tool must pass all four of the following test types before the PR merges. Add them to the appropriate test file in `tests/test_tools/`.

### Test 1: Registration Sanity

Verify the tool is actually in the registry with the correct metadata.

```python
def test_my_tool_registered(registry: ToolRegistry) -> None:
    tool_def = registry.get("my_new_tool")
    assert tool_def is not None
    assert tool_def.trust_level_required == TrustLevel.main
    assert tool_def.action_level == 5          # or whatever you set
    assert tool_def.requires_approval is False  # check your intent
    assert registry.get_handler("my_new_tool") is not None
```

### Test 2: End-to-End Visibility (Registration → System Prompt)

Verify that a correctly configured agent actually sees the tool in its system prompt. This is the test that would have caught both motivating bugs.

```python
async def test_my_tool_visible_to_main_agent(tmp_path: Path) -> None:
    reg = ToolRegistry()
    # Register the tool
    reg.register(MY_TOOL_DEF, handler=some_handler)
    
    # Agent with correct trust level and the tool in allowed_tools
    agent_config = AgentConfig(
        agent_id="agent:main:main",
        name="Main",
        description="Test",
        model="test-model",
        trust_level=TrustLevel.main,
        allowed_tools=["my_new_tool"],
    )
    
    # Verify list_tools_for_agent includes it
    permitted = reg.list_tools_for_agent(agent_config)
    assert any(t.name == "my_new_tool" for t in permitted)
    
    # Verify it appears in the system prompt
    loader = IdentityLoader(
        identity_dir=tmp_path,
        agent_config=agent_config,
        tool_registry=reg,
    )
    prompt = await loader.load_system_prompt()
    assert "my_new_tool" in prompt
```

### Test 3: Permission Boundary

Verify that agents below the required trust level are correctly denied.

```python
def test_my_tool_denied_to_public_agent(registry: ToolRegistry) -> None:
    tool_def = registry.get("my_new_tool")
    assert tool_def is not None
    
    public_agent = AgentConfig(
        agent_id="agent:public:test",
        name="Public",
        description="Test",
        model="test-model",
        trust_level=TrustLevel.public,
        allowed_tools=["my_new_tool"],  # even if explicitly listed
    )
    
    allowed, reason = check_permission(public_agent, "my_new_tool", tool_def)
    assert not allowed
    assert "trust level" in reason  # denied at trust check, not allowlist
```

### Test 4: Callability (Executor Round-Trip)

Verify the full ToolExecutor path succeeds with a mock handler, confirming action_level and approval logic are correct.

```python
async def test_my_tool_executes_under_minimal_profile(
    registry: ToolRegistry,
    agent_config: AgentConfig,
    audit: AuditLog,
) -> None:
    policy = ApprovalThresholdPolicy(threshold=1)  # minimal profile
    executor = ToolExecutor(registry, audit, policy=policy)
    
    call = ToolCall(
        tool_name="my_new_tool",
        arguments={"query": "test"},
        call_id="test-001",
    )
    result = await executor.execute(call, agent_config)
    
    assert result.success is True
    assert result.error is None
```

### Additional Test: Config-Driven Visibility (Feature-Flagged Tools)

For any tool gated behind `config.*.enabled`, add this test pattern:

```python
async def test_my_tool_absent_when_feature_disabled():
    """Tool must NOT appear in agent's allowed_tools when feature is off."""
    config = build_test_config(my_feature_enabled=False)
    # ... build registry without registering the tool (simulates disabled flag)
    agent = build_agent_from_config(config)
    assert "my_new_tool" not in agent.allowed_tools

async def test_my_tool_present_when_feature_enabled():
    """Tool MUST appear in agent's allowed_tools when feature is on."""
    config = build_test_config(my_feature_enabled=True)
    # ... build registry WITH the tool registered
    agent = build_agent_from_config(config)
    assert "my_new_tool" in agent.allowed_tools
```

### Additional Test: MCP-Specific Authorized Tiers

For MCP tools, add a check that the system prompt shows non-empty authorized tiers:

```python
async def test_mcp_tool_shows_authorized_tiers(tmp_path: Path) -> None:
    reg = ToolRegistry()
    reg.register(ToolDefinition(
        name="mcp:my-server.my_tool",
        description="MCP tool",
        parameters={"type": "object", "properties": {}, "required": []},
        trust_level_required=TrustLevel.mcp,
    ))
    
    agent_config = AgentConfig(
        agent_id="agent:main:main",
        name="Main",
        description="Test",
        model="test-model",
        trust_level=TrustLevel.main,
        allowed_tools=["mcp:my-server.my_tool"],
    )
    
    loader = IdentityLoader(identity_dir=tmp_path, agent_config=agent_config, tool_registry=reg)
    prompt = await loader.load_system_prompt()
    
    mcp_section = prompt[prompt.index("`mcp` trust required"):][:200]
    assert "`main`" in mcp_section      # not empty
    assert "`local`" in mcp_section
    assert "`security`" in mcp_section
    assert "`public`" not in mcp_section  # public below mcp rank
```

---

## 8. Diagnostic Checklist — "My Tool Isn't Working"

Work through these in order. Stop at the first failure and fix it.

**1. Is the tool in the registry?**
```python
from openrattler.tools.registry import ToolRegistry
reg = ... # get the live registry
print(reg.get("my_tool_name"))  # None = not registered
```
→ If None: check that the module is imported at startup and `configure_default_registry()` was called first.

**2. Is the tool name in trust_defaults in config.json?**
Check `~/.openrattler/config.json` → `tools.trust_defaults.main`. The exact string must match the tool's registered name (for MCP tools: `mcp:server-id.tool_name`).
→ If missing: add it. Restart the server.

**3. Is the tool in the agent's allowed_tools after startup?**
Add a debug log: `logger.debug("allowed_tools: %s", agent_config.allowed_tools)` and check that the tool name appears after `_resolve_agent_tools()` runs (startup step 11b).
→ If missing despite being in trust_defaults: check that the trust level key matches the agent's trust_level (e.g., if agent is `main`, the tool must be under `trust_defaults["main"]`).

**4. Is the feature flag enabled?**
If the tool is inside `if config.*.enabled:` in startup.py, check that the config section has `"enabled": true`.
→ If missing: add the section to `~/.openrattler/config.json` and restart.

**5. Does the agent's trust level meet trust_level_required?**
Check `tool_def.trust_level_required` vs `agent_config.trust_level`. Use the permission ranks: public=0, mcp=1, main=2, security=2, local=3. Agent rank must be ≥ tool rank.
→ If mismatched: either lower `trust_level_required` (if the tool is genuinely usable at the main tier) or raise the agent's trust level in config.

**6. Does the action level match your intent?**
Check if the tool is unexpectedly asking for approval (or not). Compare `tool_def.action_level` against the current profile's threshold (minimal=1, standard=3, paranoid=5).
→ If the tool is asking for approval when it shouldn't: raise action_level (less dangerous).
→ If the tool is NOT asking for approval when it should: lower action_level (more dangerous).

**7. Does the tool appear in Corvus's system prompt?**
The system prompt is logged at session init (or ask Corvus "what tools do you have?"). Check the tools block. If the tool is in the registry and allowed_tools but absent here, the `list_tools_for_agent()` filter is rejecting it — likely a trust level mismatch.

**8. Does the handler exist?**
`registry.get_handler("my_tool_name")` should return a callable. If it returns None and the tool is not an MCP tool, it will silently fail at execution (ToolExecutor returns an error ToolResult with "no handler").

---

## Quick Reference

```
ToolDefinition fields checklist:
  name: str                           ← must match trust_defaults entry exactly
  description: str                    ← first sentence is what Corvus reads
  parameters: dict                    ← JSON Schema for arguments
  trust_level_required: TrustLevel    ← WHO can call (usually TrustLevel.main)
  action_level: int                   ← HOW RISKY (default 5 = safest; 1 = always approve)
  requires_approval: bool             ← legacy; prefer action_level
  security_notes: str                 ← document the risk, not the "what"

Registration pipeline (5 steps, all required):
  1. Write tool code with correct trust_level_required + action_level
  2. Wire into startup.py at correct position (before step 11b)
  3. Add name to ~/.openrattler/config.json → tools.trust_defaults.main
  4. Add name to openrattler/config/loader.py → ToolsConfig.trust_defaults["main"]
  5. [Feature-flagged] Enable flag in config.json; document the requirement

Approval trigger: action_level <= profile_threshold
  minimal  (threshold 1): only level 1 → approve
  standard (threshold 3): levels 1–3 → approve
  paranoid (threshold 5): all levels → approve

MCP tool name format: mcp:{server_id}.{tool_name}
MCP trust_level_required: TrustLevel.mcp (main and above can call it)
```
