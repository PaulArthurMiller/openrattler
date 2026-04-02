# Build Piece 38.4 — ResearchAgent Search Planning Step

**Branch:** `build/38.4-research-search-planning`
**Depends on:** Build Pieces 38.2 (Serper integration), 38.3 (LLM synthesis)
**Reference Documents:** ARCHITECTURE.md, SECURITY.md, PROGRESS.md (38.x entries)

---

## Goal

Replace the hardcoded Serper query parameters in `ResearchAgent._web_search()` with a
lightweight LLM planning step. The ResearchAgent reads the incoming query, consults the
list of currently-enabled search endpoints, and constructs a full `WebSearchParams` object
(endpoint, time filter, location, country, etc.) before any network call is made.

The planner uses a dedicated prompt file — `SEARCH_PLAN.md` — that is separate from the
synthesis prompt in `SKILL.md`. It is loaded, used once to build the search parameters,
then dropped. The synthesizer never sees it and never sees the available endpoint options.

---

## Background and Motivation

After Build 38.3, the pipeline looks like this:

```
_run_pipeline()
  → _web_search(query)           ← hardcoded: endpoint="news", no filters
  → _web_fetch(url, ...) × N
  → _synthesize(request, fetched)
  → sanitize → UM
```

The search step is fully deterministic. The agent has no input into how the search is
constructed — it cannot choose a more appropriate endpoint for a query about academic
research, or add a time filter for a query about last week's news, or add a location
constraint for a regional query.

This build piece adds a planning step before the search:

```
_run_pipeline()
  → _plan_search(request)        ← NEW: LLM call with SEARCH_PLAN.md
  → _web_search(params)          ← changed: takes full WebSearchParams
  → _web_fetch(url, ...) × N     ← unchanged
  → _synthesize(request, fetched) ← unchanged
  → sanitize → UM                ← unchanged
```

The planner is a single `provider.complete()` call — no tools, no loop, text in / JSON
out. It is cheap (Haiku, short prompt, ~256 tokens max response). The enabled endpoint
list comes directly from `self._config.serper_config.enabled_endpoints`, so the agent
can only plan what is actually available in the current deployment.

---

## Why a Separate SEARCH_PLAN.md

SKILL.md is the synthesis prompt. It tells the agent how to evaluate source quality,
handle thin results, write a weighted summary, and defend against prompt injection in
fetched content. That guidance is irrelevant — and potentially confusing — during the
search planning step, which is a narrow classification task.

SEARCH_PLAN.md is the planner prompt. It tells the agent what each endpoint type is good
for, what filters are available and when to use them, and how to format its output as
JSON. That guidance is irrelevant during synthesis.

Keeping them separate means each LLM call receives only the instructions it needs. The
planner file is loaded at `ResearchAgent.__init__` alongside SKILL.md and held in
`self._search_plan_prompt`.

---

## SEARCH_PLAN.md Content

**File:** `openrattler/agents/research/SEARCH_PLAN.md`

```markdown
# Search Planner

## Role

You are the search parameter planner for a research agent. Your only job is to
read an incoming research query and output a JSON object specifying how to search
for it. You do not summarize, analyze, or explain. You produce one JSON object and
nothing else.

---

## Available Search Endpoints

The enabled endpoints for this deployment are provided in the user message. Choose
the most appropriate one from that list. Never specify an endpoint that is not in
the enabled list.

Endpoint reference — when each type is appropriate:

- **search** — general web search; use for factual background, "how does X work",
  company/product information, reference material, anything that is not primarily
  news or specialized content
- **news** — Google News index; use for current events, breaking news, protests,
  political developments, announcements, anything that happened recently or where
  recency is the core of the query
- **images** — Google Images; use when the query is explicitly about visual content
  (logos, photographs, charts, product images)
- **videos** — Google Videos; use for video content, speeches, tutorials, recorded
  events
- **shopping** — Google Shopping; use for product prices, availability, comparison
- **places** — Google Maps / Places; use for local businesses, venues, addresses,
  "near me" style queries
- **maps** — Google Maps directions; use for routing or transit queries
- **scholar** — Google Scholar; use for academic research, scientific studies,
  peer-reviewed papers, citations
- **patents** — Google Patents; use for patent searches, prior art, inventor lookups

---

## Available Filters

Include only the filters that genuinely improve this specific query. Omit the rest.

- **tbs** — time-based filter (string):
  - `"qdr:h"` — past hour
  - `"qdr:d"` — past day
  - `"qdr:w"` — past week
  - `"qdr:m"` — past month
  - `"qdr:y"` — past year
  Use when the query specifies or implies a time window ("last week", "March 2026",
  "recent", "breaking").

- **location** — geographic location string (e.g. `"Columbus, Ohio"`).
  Use when the query explicitly targets a place.

- **gl** — two-letter country code (e.g. `"us"`, `"gb"`).
  Use when results should be scoped to a specific country.

- **hl** — language code (e.g. `"en"`, `"es"`).
  Use when results should be in a specific language.

- **num** — integer 1–20. Use only if the default result count (10) is clearly
  wrong for the query. Most queries do not need this.

---

## Query Refinement

You may reword the query string for better search results — for example, expanding
abbreviations, adding a year for disambiguation, or tightening keywords. Do not
change the meaning or drop any core concept from the original query.

---

## Output Format

Output a single valid JSON object. No explanation. No markdown code fences. No
wrapper text. Only the JSON object.

Required fields: `endpoint`, `query`
All other fields are optional — include only what adds value.

Example outputs:

{"endpoint": "news", "query": "No Kings protests Ohio March 2026", "tbs": "qdr:m", "gl": "us"}

{"endpoint": "scholar", "query": "CRISPR gene editing off-target effects meta-analysis"}

{"endpoint": "search", "query": "Python asyncio event loop internals", "hl": "en"}

{"endpoint": "places", "query": "urgent care clinics", "location": "Columbus, Ohio"}
```

---

## Architecture Changes

### Pipeline flow (updated)

```
_run_pipeline(request, trace_id, ...)
  │
  ├─ Phase 0 (NEW): _plan_search(request)
  │      │  Calls provider.complete() with SEARCH_PLAN.md as system prompt.
  │      │  User message: query text + list of enabled endpoints.
  │      │  Returns WebSearchParams (validated). Falls back to defaults on any failure.
  │      │
  ├─ Phase 1: _web_search(params)          ← signature changed, was _web_search(query)
  │      │  Passes full WebSearchParams to web_search(). No longer hardcodes endpoint.
  │      │
  ├─ Phase 2: _web_fetch(url, ...) × N     ← unchanged
  │
  ├─ Phase 3: _synthesize(request, fetched) ← unchanged
  │
  ├─ Phase 4: _build_raw_citations(fetched) ← unchanged
  │
  └─ Phase 5: sanitize → UM               ← unchanged
```

### `__init__` change

Load `SEARCH_PLAN.md` alongside `SKILL.md`:

```python
search_plan_path = config.skill_prompt_path.parent / "SEARCH_PLAN.md"
if not search_plan_path.exists():
    raise FileNotFoundError(
        f"ResearchAgent requires SEARCH_PLAN.md at {search_plan_path!r}; file not found."
    )
self._search_plan_prompt: str = search_plan_path.read_text(encoding="utf-8")
```

The same hard-fail policy as SKILL.md — a ResearchAgent without its planner prompt
must not run silently degraded.

### `_plan_search` — new method

```python
async def _plan_search(self, request: ResearchRequest) -> WebSearchParams:
```

1. If `self._provider is None`, return default `WebSearchParams` — backward compat for
   tests that do not inject a provider.
2. Build planning messages:
   - system: `self._search_plan_prompt`
   - user: query text + enabled endpoints list (from
     `sorted(self._config.serper_config.enabled_endpoints)`)
3. Call `provider.complete(messages, tools=None, model=stripped_model, max_tokens=256)`.
4. Strip any markdown code fences from the response (` ```json ... ``` `).
5. Parse as JSON with `json.loads()`.
6. Validate with `WebSearchParams.model_validate(parsed)`.
7. If the planned endpoint is not in `enabled_endpoints`, replace it with the fallback.
8. On any exception (provider error, JSON parse error, Pydantic validation error): log
   a warning with the failure reason and return the default `WebSearchParams`.

Default `WebSearchParams` for fallback:
```python
WebSearchParams(query=request.query, endpoint="news")
```

### `_web_search` — signature change

```python
# Before
async def _web_search(self, query: str) -> list[dict[str, Any]]:
    result = await web_search(
        params={"query": query, "endpoint": "news"},
        ...
    )

# After
async def _web_search(self, params: WebSearchParams) -> list[dict[str, Any]]:
    result = await web_search(
        params=params.model_dump(exclude_none=True),
        ...
    )
```

`WebSearchParams.model_dump(exclude_none=True)` produces a clean dict with only the
fields the planner set — the client fills the rest from `SerperConfig` defaults.

### `_run_pipeline` call sites

```python
# Phase 0 (new)
search_params = await self._plan_search(request)

# Phase 1 (updated)
search_hits = await self._web_search(search_params)
```

---

## `ResearchAgentConfig` change

Add `search_plan_path` alongside `skill_prompt_path`:

```python
search_plan_path: Path = field(
    default_factory=lambda: Path(__file__).parent / "SEARCH_PLAN.md"
)
```

This keeps both prompt paths in config so they can be overridden in tests.

---

## Planning prompt — user message format

```
Research query: {request.query}

Enabled search endpoints: search, news, images

Construct the search parameters as a JSON object.
```

Short and directive. The endpoint list comes from `sorted(enabled_endpoints)` at call
time — the planner only sees what is currently available.

---

## Security Notes

- The planning call uses `tools=None` — no tool loop is possible during planning.
- The query forwarded to the planner has already been validated by `ResearchRequest`
  (max 300 chars, Pydantic). The planner cannot expand it beyond `WebSearchParams.query`
  field limits (max 500 chars).
- The planned endpoint is re-validated against `enabled_endpoints` before `_web_search`
  is called. The LLM cannot enable an endpoint that is not in the allowlist.
- All other planned parameters (`tbs`, `location`, etc.) are validated by
  `WebSearchParams.model_validate()` with Pydantic field constraints before they reach
  the Serper client. The client enforces its own allowlist layer on top.
- `SEARCH_PLAN.md` does not expose fetched web content to the planner — it receives only
  the user's original query. There is no prompt injection surface at this stage.

---

## Files to Create

### 1. `openrattler/agents/research/SEARCH_PLAN.md`

The planner system prompt. Content specified in the "SEARCH_PLAN.md Content" section
above.

---

## Files to Change

### 2. `openrattler/agents/research/agent.py`

- **`__init__`**: Load `SEARCH_PLAN.md` from `config.search_plan_path`. Hard-fail
  `FileNotFoundError` if missing. Store as `self._search_plan_prompt`.
- **`_plan_search`** (new async method): Build planning messages, call
  `provider.complete()`, strip markdown fences, parse JSON, validate with
  `WebSearchParams`, return result or fallback default.
- **`_web_search`**: Change signature from `_web_search(self, query: str)` to
  `_web_search(self, params: WebSearchParams)`. Pass
  `params.model_dump(exclude_none=True)` to `web_search()`.
- **`_run_pipeline`**: Insert `search_params = await self._plan_search(request)` before
  Phase 1. Change Phase 1 call from `_web_search(request.query)` to
  `_web_search(search_params)`.
- Add import: `from openrattler.tools.search.web_search_tool import WebSearchParams`
  (already imported indirectly — make it explicit at top of file).

### 3. `openrattler/agents/research/config.py`

- Add `search_plan_path: Path` field with default pointing to
  `Path(__file__).parent / "SEARCH_PLAN.md"`.

---

## Tests to Write

**File:** `tests/test_agents/test_research_search_planning.py`

| Test | What it verifies |
|------|-----------------|
| `test_plan_search_calls_provider` | `provider.complete()` called once with `tools=None` |
| `test_plan_search_system_message_is_search_plan_prompt` | System message equals `SEARCH_PLAN.md` content |
| `test_plan_search_user_message_contains_query` | User message includes `request.query` |
| `test_plan_search_user_message_contains_enabled_endpoints` | User message lists `enabled_endpoints` |
| `test_plan_search_returns_websearchparams` | Valid JSON from LLM → correct `WebSearchParams` |
| `test_plan_search_passes_tbs_filter` | JSON with `tbs` → `WebSearchParams.tbs` set correctly |
| `test_plan_search_passes_location_filter` | JSON with `location` → `WebSearchParams.location` set |
| `test_plan_search_rejects_disabled_endpoint` | LLM returns endpoint not in `enabled_endpoints` → fallback used |
| `test_plan_search_no_provider_returns_default` | `provider=None` → default `WebSearchParams(query=..., endpoint="news")` |
| `test_plan_search_provider_exception_returns_default` | Provider raises → default returned, warning logged |
| `test_plan_search_invalid_json_returns_default` | Malformed JSON from LLM → default returned, warning logged |
| `test_plan_search_strips_markdown_fences` | LLM wraps output in ` ```json ``` ` → still parsed correctly |
| `test_web_search_receives_full_params` | `_web_search` passes all planned params to `web_search()` |
| `test_run_pipeline_uses_planned_endpoint` | Full `run()` with mock provider: planned endpoint reaches `web_search` call |

Minimum 14 tests.

**Existing tests to update:**

Any test that calls `_web_search(query_string)` directly must be updated to pass a
`WebSearchParams` instance. Any test that mocks `_plan_search` with a string must be
updated to return a `WebSearchParams`. Check
`tests/test_agents/test_research_agent_pipeline.py` — likely needs a mock for
`_plan_search` that returns a default `WebSearchParams`.

---

## Acceptance Criteria

- `_plan_search` makes a real LLM call when a provider is injected, returning a
  `WebSearchParams` with the planned endpoint and any applicable filters.
- The planned endpoint is always validated against `enabled_endpoints` — the LLM
  cannot specify an endpoint outside the allowlist.
- `provider=None` falls back cleanly to default `WebSearchParams` (no crash,
  backward compat for existing tests).
- Any provider/parse/validation failure falls back cleanly to defaults with a
  logged warning — the pipeline never crashes.
- `SEARCH_PLAN.md` missing at instantiation raises `FileNotFoundError` immediately.
- All existing tests pass (1 765 + ≥14 new = ≥1 779 total).
- `black --check .` clean.
- `mypy openrattler/` — no new issues.

---

## What This Piece Does NOT Change

- The synthesis prompt (`SKILL.md`) and `_synthesize()` — unchanged.
- The sanitizer and UM construction — unchanged.
- The tool allowlist (`web_search`, `web_fetch` only) — unchanged.
- Serper client, sanitizer, or model layers — unchanged.
- `AppConfig.search.serper` → `ResearchAgentConfig.serper_config` wiring — still future.
- Multi-step search (follow-up queries, pagination) — still backlog.
- Serper credit state persistence — still backlog.
