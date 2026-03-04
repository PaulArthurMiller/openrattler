"""Built-in task templates for Agent Creator subagent specialisation.

Templates define the system prompt, required tools, suggested model, and cost /
complexity guidance for each specialist agent type.  The Agent Creator combines
a template with an ``AgentCreationRequest`` to build a concrete ``AgentConfig``.

Templates are intentionally minimal and generic so they work across tasks.
System prompts are kept short — the actual task instructions are injected at
runtime by the creator.

SECURITY NOTE
-------------
Templates define the **maximum** tool surface for a given agent type.  The
Agent Creator's security validator still checks tool-task alignment and
dangerous-tool approval for every spawn request; templates are not a bypass
of those checks.
"""

from __future__ import annotations

from openrattler.models.agents import TaskTemplate

# ---------------------------------------------------------------------------
# Built-in task templates
# ---------------------------------------------------------------------------

TASK_TEMPLATES: dict[str, TaskTemplate] = {
    "research": TaskTemplate(
        name="research",
        description="Search and synthesise information from web sources",
        system_prompt=(
            "You are a research specialist. Your job is to:\n"
            "1. Search for relevant information using web_search\n"
            "2. Fetch and read full documents using web_fetch\n"
            "3. Synthesise findings into clear, cited summaries\n"
            "4. Note confidence levels and source quality\n\n"
            "Always cite sources and be explicit about uncertainties."
        ),
        required_tools=["web_search", "web_fetch"],
        suggested_model="openai/gpt-4o-mini",
        typical_complexity_range=(3, 7),
        suggested_cost_limit=0.05,
        workflow=["Search", "Fetch", "Read", "Synthesise"],
    ),
    "coding": TaskTemplate(
        name="coding",
        description="Generate, analyse, or debug code",
        system_prompt=(
            "You are a coding specialist. Your job is to:\n"
            "1. Understand requirements clearly\n"
            "2. Generate clean, well-documented code\n"
            "3. Include error handling and validation\n"
            "4. Provide usage examples\n"
            "5. Use type hints and follow best practices\n\n"
            "Always explain your design decisions."
        ),
        required_tools=["code_generation", "code_analysis"],
        suggested_model="anthropic/claude-sonnet-4-6",
        typical_complexity_range=(5, 9),
        suggested_cost_limit=0.15,
        workflow=["Analyse", "Design", "Implement", "Document"],
    ),
    "execution": TaskTemplate(
        name="execution",
        description="Execute API calls or structured operations",
        system_prompt=(
            "You are an execution specialist. Your job is to:\n"
            "1. Parse instructions carefully\n"
            "2. Validate inputs before execution\n"
            "3. Execute API calls or scripts exactly as specified\n"
            "4. Handle errors gracefully\n"
            "5. Return structured results\n\n"
            "Always confirm what you are about to execute before doing it."
        ),
        required_tools=["api_call", "http_request"],
        suggested_model="openai/gpt-4o",
        typical_complexity_range=(2, 5),
        suggested_cost_limit=0.08,
        workflow=["Validate", "Execute", "Check", "Return"],
    ),
    "analysis": TaskTemplate(
        name="analysis",
        description="Analyse data, documents, or patterns",
        system_prompt=(
            "You are an analysis specialist. Your job is to:\n"
            "1. Load and examine data carefully\n"
            "2. Identify patterns and anomalies\n"
            "3. Apply appropriate analytical methods\n"
            "4. Present findings clearly\n"
            "5. Highlight key insights and recommendations\n\n"
            "Always show your reasoning."
        ),
        required_tools=["file_read", "data_processing"],
        suggested_model="anthropic/claude-sonnet-4-6",
        typical_complexity_range=(4, 8),
        suggested_cost_limit=0.12,
        workflow=["Load", "Explore", "Analyse", "Summarise"],
    ),
}
