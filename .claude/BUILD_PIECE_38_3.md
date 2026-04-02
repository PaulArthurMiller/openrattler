# Build Piece 38.3 — Real LLM Synthesis in ResearchAgent

**Goal:** Replace `ResearchAgent._synthesize()` stub with a real async LLM call via
an injected `LLMProvider`. The research pipeline currently returns a flat title/URL
list; after this piece it will return a genuine synthesized summary from the LLM.

This synthesis must be operational in all runtime modes:
- **`openrattler run`** — full server with SMS, Slack, email, and WebSocket channels
  (wired through `startup.py`)
- **`openrattler chat`** — CLI-only mode (wired through `cli/chat.py`)

---

## What the stub does (current state)

```python
def _synthesize(self, request, fetched) -> str:
    parts = [f"Research results for: {request.query!r}."]
    for i, page in enumerate(fetched[:request.max_results]):
        parts.append(f"[{i + 1}] {page['title']} — {page['url']}")
    return " ".join(parts)[:2000]
```

No LLM call. No content analysis. The sanitizer and UM construction run on this
placeholder, so the full security pipeline is exercised — only synthesis is missing.

---

## Architecture changes

```
ResearchAgent pipeline (before)
────────────────────────────────────────────────────────
_web_search → _web_fetch → _synthesize (stub) → sanitize → UM

ResearchAgent pipeline (after)
────────────────────────────────────────────────────────
_web_search → _web_fetch → _synthesize (LLM call) → sanitize → UM
                                    ↑
                              LLMProvider (injected)
                              model stripped of "anthropic/" prefix
                              tools=None (no tool loop — synthesis is one LLM call)
                              max_tokens=1024
```

The sanitizer still runs on every synthesis output — unchanged.
The UM is still not constructed until the sanitizer returns — unchanged.

---

## Provider injection path

```
openrattler run (startup.py)                openrattler chat (cli/chat.py)
─────────────────────────────               ─────────────────────────────
build_provider_from_env()                   _build_provider_from_env()
       │                                           │
       │ llm_provider (line 686)                   │ provider (reordered to before
       │                                           │ AgentCreator construction)
       ▼                                           ▼
AgentCreator(provider=llm_provider, ...)    AgentCreator(provider=provider, ...)
       │                                           │
       └────────────────────┬──────────────────────┘
                            │
                    create_research_agent()
                            │
                            ▼
             ResearchAgent(config=config,
                           audit=audit,
                           provider=self._provider)
                            │
                    _synthesize(request, fetched)
                            │
                            ▼
             provider.complete(messages, tools=None,
                               model=stripped_model,
                               max_tokens=1024)
```

### Why inject at `AgentCreator` rather than constructing a new provider inside `ResearchAgent`?

`AgentCreator` is the single authorised spawn pathway for all subagents. It already
receives all dependency config; adding the provider keeps the pattern consistent and
avoids constructing a second API client with a second connection pool per-spawn.

### Where `AgentCreator` is constructed (exhaustive list)

A grep confirms there are exactly two construction sites:

| File | Mode |
|------|------|
| `openrattler/startup.py` line 705 | `openrattler run` — full channel server |
| `openrattler/cli/chat.py` line 276 | `openrattler chat` — CLI-only mode |

`gateway/operations.py` and `ws_client.py` do not construct `AgentCreator`.

---

## Synthesis prompt structure

```
[system]
{self._skill_prompt}                 ← The SKILL.md loaded at instantiation

[user]
Research query: {request.query}

Fetched sources:

[1] {title} ({url})
{content[:5000]}

[2] ...

Provide a concise synthesis of the research findings. Cover the key facts,
note any conflicting information, and flag any significant gaps.
```

**Security note:** Content is already capped to 5 000 chars per page by `_web_fetch`.
At 5 pages × 5 000 chars ≈ 6 250 tokens of content — within Haiku's limit.

---

## Model ID normalisation

`ResearchAgentConfig.model` carries the `"anthropic/"` provider-routing prefix
(e.g. `"anthropic/claude-haiku-4-5-20251001"`). `AnthropicProvider.complete()`
expects the bare model ID. Strip the prefix at call time:

```python
model = self._config.model.removeprefix("anthropic/")
response = await self._provider.complete(
    messages=messages,
    tools=None,
    model=model,
    max_tokens=1024,
)
```

---

## Fallback behaviour

If `provider` is `None` (e.g., existing unit tests that don't exercise synthesis),
`_synthesize` falls back to the current stub — no behavioural change for those tests.

If the provider raises (network error, API error), `_synthesize` logs a warning and
falls back to the stub — the pipeline continues and returns a degraded but valid UM.

```
provider=None         → stub output (no LLM call)
provider raises       → warning logged, stub output
provider returns text → text[:2000] forwarded to sanitizer
```

---

## Files to change

### 1. `openrattler/agents/research/agent.py`

- **`__init__`**: Add `provider: Optional[LLMProvider] = None`. Store as `self._provider`.
- **`_synthesize`**: Change to `async def _synthesize(...)`.
  - If `self._provider is None`: call `self._stub_synthesize(request, fetched)`.
  - Otherwise: call `_build_synthesis_messages`, call `provider.complete()`, return
    `response.content[:2000]`.
  - Catch any `Exception`, log warning, fall back to `_stub_synthesize`.
- **`_build_synthesis_messages`**: New private method returning
  `[{role:system, content:skill_prompt}, {role:user, content:...}]`.
- **`_stub_synthesize`**: Extract current stub body here (clean git diff).
- **`_run_pipeline`**: Change `raw_summary = self._synthesize(...)` to
  `raw_summary = await self._synthesize(...)`.
- Add `from openrattler.agents.providers.base import LLMProvider` import.

### 2. `openrattler/agents/creator.py`

- **`__init__`**: Add `provider: Optional[LLMProvider] = None`. Store as `self._provider`.
- **`create_research_agent`**: Pass `provider=self._provider` to `ResearchAgent(...)`.
- Add `from openrattler.agents.providers.base import LLMProvider` import.

### 3. `openrattler/startup.py`

`llm_provider` is already built at line 686; `AgentCreator` is constructed at line 705.
No reorder needed — just add `provider=llm_provider` to the constructor call.

### 4. `openrattler/cli/chat.py`

`AgentCreator` (line 276) is constructed BEFORE `provider` (line 288).
Reorder: move the `provider = ...` line to before `AgentCreator(...)`, then add
`provider=provider` to the constructor call.

---

## Tests to write

**File:** `tests/test_agents/test_research_agent_synthesize.py`

| Test | What it verifies |
|------|-----------------|
| `test_synthesize_calls_provider` | `provider.complete()` is called once when fetched content is present |
| `test_synthesize_system_message_is_skill_prompt` | System message content equals loaded SKILL.md text |
| `test_synthesize_user_message_contains_query` | User message includes `request.query` |
| `test_synthesize_user_message_contains_page_content` | User message contains a page content snippet |
| `test_synthesize_returns_provider_response` | `response.content` becomes the raw_summary |
| `test_synthesize_caps_response_at_2000_chars` | Long `response.content` is truncated to 2000 |
| `test_synthesize_no_provider_uses_stub` | `provider=None` → stub output, no LLM call |
| `test_synthesize_provider_exception_falls_back` | Provider raises → stub output, warning logged |
| `test_synthesize_empty_fetched_list` | Empty fetch list → graceful no-sources message |
| `test_synthesize_strips_anthropic_prefix_from_model` | `model="anthropic/claude-haiku-..."` → provider called with `"claude-haiku-..."` |
| `test_run_pipeline_uses_real_synthesis` | Full `run()` call with mock provider returns synthesized text in UM params |
| `test_sanitizer_runs_after_synthesis` | Sanitizer is always called even when LLM synthesis is used |

Minimum 12 tests.

---

## Acceptance criteria

- `_synthesize` makes a real LLM call via the injected `LLMProvider`.
- Synthesis is operational in both `openrattler run` (full channel server) and
  `openrattler chat` (CLI mode).
- `provider=None` works without error (backward compat for existing tests).
- Provider exceptions fall back gracefully to the stub — pipeline never crashes.
- `run()` returns a UM where `params["summary"]` contains the LLM-generated text
  (after sanitization).
- All existing tests pass (1 751 + ≥12 new = ≥1 763 total).
- `black --check .` clean.
- `mypy openrattler/` — no new issues.

---

## What this piece does NOT change

- The sanitizer and UM construction — unchanged.
- The tool allowlist (`web_search`, `web_fetch` only) — unchanged.
- Serper search integration — unchanged.
- `AppConfig.search.serper` → `ResearchAgentConfig.serper_config` wiring — still future.
- Serper credit state persistence — still backlog.
