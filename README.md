# OpenRattler

**A security-first, multi-agent AI assistant that treats every message as potentially adversarial — including the ones from your own agents.**

---

## Why Security-First?

Most AI assistants are built to be helpful first and secured later, if at all. ChatGPT, Claude.ai, and OpenClaw all assume that messages arriving from agents can be trusted, that session context is private by default, and that a well-crafted system prompt is sufficient protection against injection attacks.

OpenRattler makes different assumptions:

- **Every message is adversarial until validated.** Inputs from public channels, user-provided memory, tool responses, and even stored session history are all treated with the same skepticism as untrusted network data.
- **The LLM is not a trust boundary.** An agent that has been manipulated cannot be trusted to report its own compromise. Security controls live in the infrastructure, not in the model's judgment.
- **Defense-in-depth is non-negotiable.** Ten independent security layers mean a single bypass does not compromise the system.
- **Approval prompts show provenance, not just reasons.** An agent can fabricate a plausible reason for any action. OpenRattler shows the *system-recorded origin* of the request — channel, trust level, timestamp, and turns-since-trigger — independently of whatever the agent claims.

The [Clinejection attack (February 2025)](https://www.wired.com/story/claude-ai-agent-prompt-injection/) demonstrated that an injected agent can travel from a GitHub issue through an AI triage bot into CI/CD credentials and out as a compromised package. OpenRattler's architecture was designed with that threat class in mind.

---

## What Is OpenRattler?

OpenRattler is a personal AI assistant that:

- Runs across multiple channels (SMS, Slack, email, CLI — add your own via `ChannelAdapter`)
- Routes each conversation to an isolated session so a compromise in a public Discord channel cannot reach your personal DMs
- Gives the agent tools (file ops, memory, outbound messaging, MCP servers) under explicit per-trust-level allowlists
- Schedules a heartbeat that runs the agent on a timer, sanitizing stored history before each scheduled turn
- Maintains a persistent identity and memory that the agent can read and update, subject to security review
- Dispatches security alerts and heartbeat outputs to configured channels in real time

---

## Security Architecture

### Ten Independent Layers

Each layer can be enabled, disabled, or tuned independently. Disabling one does not weaken the others.

| Layer | What it does |
|---|---|
| **1. Session Isolation** | Deterministic routing: `(channel, account, peer) → session_key`. Each public server channel gets its own isolated session. |
| **2. Channel Isolation** | Different trust levels per channel type. Public Discord gets `public`; personal SMS gets `main`. |
| **3. Agent Trust Levels** | Per-agent tool allowlists. An agent at trust level `public` cannot call `file_read`. Allowlist is explicit — empty list = deny all. |
| **4. Pitch-Catch Handoffs** | Security-critical data (tokens, paths, credentials) never passes directly between untrusted components. Brokers validate and strip before forwarding. |
| **5. Need-to-Know Isolation** | Each component sees the minimum required. The main agent sees `file_id`, not the path. The LIA sees no tokens. |
| **6. Input/Output Filtering** | Pydantic schema validation at every boundary. `sanitize.py` and `command_filter.py` run at ingestion. |
| **7. Approval Gates** | High-risk operations require human approval. The prompt shows the agent's stated reason *and* the system-recorded provenance — independently. |
| **8. Rate Limiting** | Per-connection and per-operation rate limiting. WebSocket gateway enforces connection limits. |
| **9. Audit Logging** | Immutable `AuditLog` with append-only semantics. Every tool call, permission check, and security event is logged. |
| **10. Memory Security Review** | `MemorySecurityAgent` scans writes to persistent memory for injection patterns before committing. |

### Security Profiles

```json
{
  "security": {
    "profile": "standard"
  }
}
```

Three pre-configured profiles let you dial security vs. convenience:

| Profile | Use case |
|---|---|
| `minimal` | Local development and testing |
| `standard` | Personal daily use (default) |
| `paranoid` | High-security environments; startup integrity check enabled |

### Heartbeat History Sanitization

This is an OpenRattler-specific pattern not found in standard AI assistants.

Scheduled heartbeat turns do not trust stored session history. Every history entry carries origin metadata (channel, trust level, timestamp). The heartbeat prompt builder wraps entries from public or untrusted channels in explicit adversarial framing before sending them to the model. Heartbeat turns also run under a restricted tool allowlist — `exec`, `file_delete`, `sessions_send`, and `memory_update` are denied.

This prevents the "dormant injection" class of attack: a message injected via a public channel that sits in session history, waiting to be triggered by a scheduled reprompt while the user is away.

### Approval Provenance

```
Approval required for: file_delete

Reason stated by agent: "Cleaning up old backups per user request"

Origin (system-recorded — cannot be fabricated by agent):
  Channel:         discord:public-server
  Trust level:     public
  Triggered:       4 hours, 23 minutes ago
  Turns since:     17

[A]pprove  [D]eny  [V]iew originating message
```

The agent's stated reason is LLM-generated and can be fabricated. The provenance block is recorded by the infrastructure when the message first arrives, before any agent processing. These are shown side by side so mismatches are immediately visible.

### Supply Chain Hygiene

- All Python dependencies pinned with hash verification
- No AI automation with shell access on externally-triggered workflow events
- OIDC-only for any future publishing; no legacy tokens
- No postinstall hooks or auto-executing build scripts
- Startup integrity check (paranoid profile) verifies tool module hashes before accepting connections

---

## UniversalMessage

Every component in OpenRattler — channel adapters, agents, tools, MCP servers — communicates using a single message format: `UniversalMessage`.

```python
class UniversalMessage(BaseModel):
    # Identity
    message_id: str          # UUID
    from_agent: str          # e.g. "channel:slack", "agent:main:main", "mcp:weather"
    to_agent: str

    # Routing
    session_key: str         # Determines isolation scope
    channel: Optional[str]   # "sms", "slack", "email", etc.

    # Content
    type: Literal["request", "response", "event", "error", "alert"]
    operation: str           # e.g. "user_message", "send_sms", "file_read"

    # Payload
    params: dict[str, Any]   # Required/expected data for the operation
    metadata: dict[str, Any] # Optional context, hints, ancillary data

    # Security
    trust_level: Literal["public", "main", "local", "security", "mcp"]
    requires_approval: bool

    # Tracking
    timestamp: datetime
    parent_message_id: Optional[str]  # For replies/continuations
    trace_id: str            # Shared across all messages in a single request chain

    # Errors
    error: Optional[dict[str, Any]]
```

### Why one protocol?

Most multi-agent systems use different formats for different hops: raw strings to the LLM, JSON-RPC to MCP servers, custom dicts between internal components. This makes it hard to enforce security uniformly — each boundary has different validation logic, or none.

UniversalMessage puts a **PitchCatch validator** at every boundary. The validator checks operation allowance, trust level, required params, rate limits, and approval gates — identically, regardless of where the message came from. A channel adapter speaking to the main agent goes through the same validation as the main agent speaking to an MCP server.

### Trace IDs

Every message in a request chain shares the same `trace_id`. A user SMS that triggers a weather lookup that sends an email response produces four messages, all with `trace_id="trace-abc123"`. This enables end-to-end latency tracking, multi-hop debugging, and audit log correlation.

### params vs. metadata

**Rule**: if removing it would break the operation → `params`. If it is helpful context → `metadata`.

```python
# Weather forecast request
params = {
    "location": "Asheville, NC",   # Required
    "days": 7,                     # Required
}
metadata = {
    "user_intent": "vacation planning",          # Context
    "deadline": "respond within 30 seconds",     # Hint
    "user_timezone": "America/New_York",          # Context
}
```

### MCP compatibility

UniversalMessage translates cleanly to and from MCP JSON-RPC 2.0. The `MCPAdapter` handles both directions. MCP-specific fields (`mcp_method`, `mcp_jsonrpc_id`) are stashed in `metadata` so the rest of the system never needs to know about the underlying protocol.

---

## Getting Started

### Requirements

- Python 3.11+
- An Anthropic or OpenAI API key (or both)

### Installation

```bash
git clone https://github.com/PaulArthurMiller/openrattler.git
cd openrattler

# Create and activate virtual environment
python3.11 -m venv .venv

# Linux/macOS:
source .venv/bin/activate

# Windows (bash):
source .venv/Scripts/activate

# Install
pip install -e ".[dev]"
```

### Configure

OpenRattler reads its config from `~/.openrattler/config.json`. Create that file:

```bash
mkdir -p ~/.openrattler
```

Minimal config (CLI-only, Anthropic):

```json
{
  "agents": {
    "main": {
      "model": "anthropic/claude-sonnet-4-5",
      "trust_level": "main",
      "allowed_tools": [
        "memory_narrative_update",
        "memory_user_profile_update",
        "memory_read_context",
        "memory_read",
        "memory_write",
        "update_identity",
        "send_slack_message",
        "send_sms",
        "send_email"
      ]
    }
  },
  "providers": {
    "anthropic": {
      "api_key": "sk-ant-..."
    }
  },
  "security": {
    "profile": "standard"
  }
}
```

### Run the CLI

```bash
openrattler chat
```

This starts an interactive session with the OpenRattler assistant in your terminal. No network server is started.

### Run the full server (with Slack)

```bash
PYTHONUTF8=1 .venv/Scripts/python -m openrattler run
```

This starts the WebSocket gateway and begins polling all configured channels.

**Windows note**: the `PYTHONUTF8=1` prefix ensures the terminal handles Unicode correctly.

### Slack setup

Add a `channels.slack` block to `~/.openrattler/config.json`:

```json
{
  "channels": {
    "slack": {
      "settings": {
        "bot_token": "xoxb-...",
        "channel_id": "C...",
        "sender_allowlist": ["U..."]
      }
    }
  }
}
```

`sender_allowlist` is a list of Slack user IDs. Only messages from these users are processed. Find your own user ID in Slack under Profile → More → Copy Member ID.

### SMS setup (Twilio)

```json
{
  "channels": {
    "sms": {
      "settings": {
        "account_sid": "AC...",
        "auth_token": "...",
        "from_number": "+15551234567",
        "to_number": "+15559876543"
      }
    }
  }
}
```

### Email setup

```json
{
  "channels": {
    "email": {
      "settings": {
        "smtp_host": "smtp.gmail.com",
        "smtp_port": 587,
        "username": "you@gmail.com",
        "password": "...",
        "default_to_address": "you@gmail.com"
      }
    }
  }
}
```

---

## Running Tests

```bash
# All tests
.venv/Scripts/pytest

# With coverage
.venv/Scripts/pytest --cov=openrattler

# A specific module
.venv/Scripts/pytest tests/test_tools/test_channel_tools.py -v
```

The test suite runs 1511 tests. All pass. `mypy --strict` and `black` are clean.

---

## Project Structure

```
openrattler/
  agents/           # AgentRuntime, AgentCreator, LLM providers (Anthropic, OpenAI)
  channels/         # ChannelAdapter base + CLI, Slack, SMS, Email adapters
  cli/              # `openrattler chat` and `openrattler run` entry points
  config/           # Config loader, security profiles (minimal/standard/paranoid)
  gateway/          # WebSocket server, session router, HMAC-SHA256 auth, scheduler
  identity/         # Identity file loader (IDENTITY.md, MEMORY.md, HEARTBEAT.md)
  mcp/              # MCP connection, manager, bridge, and example server (weather)
  models/           # Pydantic models: UniversalMessage, Session, AuditEvent, AgentConfig
  processors/       # Background processors: HeartbeatProcessor, SocialSecretaryProcessor
  security/         # Input sanitization, command filtering, suspicious pattern detection,
                    #   rate limiter, memory security agent, approval gate
  storage/          # Session transcripts, MemoryStore, AuditLog
  tools/            # ToolRegistry, executor, permissions; builtins: file_ops, memory_tools,
                    #   session_tools, channel_tools
  startup.py        # Application wiring (all components assembled here)

.claude/            # Developer documentation (architecture, security, build guides)
tests/              # Test suite mirroring the package structure
```

---

## What's Built

OpenRattler is in active development. The following are complete and merged to `main`:

| Build | Component |
|---|---|
| 0.1 | Project skeleton, pyproject.toml, CI tooling |
| 8.1 | Input validation: sanitize, command_filter, pattern detection |
| 9.1 | Config system: loader, security profiles |
| 10.1 | CLI chat, session init, `openrattler` entry point |
| 11.1 | WebSocket Gateway, HMAC-SHA256 token auth, connection rate limiter |
| 12.1 | Agent Creator: task templates, security validator, subagent spawning |
| 13.1 | Memory Security Agent: pattern scanning, persistent memory review |
| 14–17 | Memory store, narrative memory tools, identity loader, tool permissions |
| 18.1 | Alert dispatch to channel adapters (security and urgent alerts) |
| 18.2 | Outbound channel tools: `send_sms`, `send_slack_message`, `send_email` |
| 35.2+36.x | Heartbeat processor, scheduled turns, live alert surfacing |

---

## Architecture: How a Request Flows

```
User (Slack/SMS/CLI)
        │
   ChannelAdapter         ← translates channel format → UniversalMessage
        │
   Gateway (WebSocket)    ← HMAC auth, rate limiting, session routing
        │
   AgentRuntime           ← loads session history + identity files
        │
   LLM Provider           ← Anthropic or OpenAI
        │ (tool calls)
   ToolExecutor           ← checks allowlist, approval gate, rate limit
        │
   Tool / MCP Server      ← executes; response wrapped in UniversalMessage
        │
   AgentRuntime           ← appends to transcript
        │
   ChannelAdapter         ← translates UniversalMessage → channel format
        │
User receives response
```

Every arrow is a trust boundary. Every trust boundary has a PitchCatch validator.

---

## Deep Dives

- `.claude/SECURITY_PHILOSOPHY.md` — why each security decision was made
- `.claude/SECURITY.md` — complete threat model and mitigation catalog
- `.claude/ARCHITECTURE.md` — detailed system design
- `.claude/UNIVERSAL_MESSAGE_PROTOCOL.md` — full message protocol spec
- `.claude/AGENTS.md` — development guidelines and security checklist
- `PROGRESS.md` — complete build log

---

## License

MIT
