"""Tool registry — registration, lookup, and per-agent filtering.

Tools are registered once at startup (via ``ToolRegistry.register`` or the
``@tool`` decorator) and looked up by name at runtime.  The registry is the
single source of truth for which tools exist and what their metadata is.
"""

from __future__ import annotations

import inspect
from typing import Any, Callable, Optional, TypeVar, overload

_F = TypeVar("_F", bound=Callable[..., Any])

from openrattler.models.agents import AgentConfig, TrustLevel
from openrattler.models.tools import ToolDefinition
from openrattler.tools.permissions import check_permission

# ---------------------------------------------------------------------------
# Parameter inference helper
# ---------------------------------------------------------------------------

_PY_TO_JSON_TYPE: dict[type, str] = {
    int: "integer",
    float: "number",
    str: "string",
    bool: "boolean",
}

#: Parameter names that are injected by the runtime, not supplied by the LLM.
_RUNTIME_PARAMS: frozenset[str] = frozenset({"self", "session", "context", "agent_config"})


def _infer_parameters(fn: Callable[..., Any]) -> dict[str, Any]:
    """Build a minimal JSON Schema ``object`` from *fn*'s signature.

    Only positional / keyword parameters that are not in ``_RUNTIME_PARAMS``
    are included.  Required parameters (those without a default) are listed
    under ``"required"``.
    """
    sig = inspect.signature(fn)
    properties: dict[str, Any] = {}
    required: list[str] = []

    for param_name, param in sig.parameters.items():
        if param_name in _RUNTIME_PARAMS:
            continue
        hint = param.annotation
        json_type = _PY_TO_JSON_TYPE.get(hint, "string")
        properties[param_name] = {"type": json_type}
        if param.default is inspect.Parameter.empty:
            required.append(param_name)

    return {"type": "object", "properties": properties, "required": required}


def _first_doc_line(fn: Callable[..., Any]) -> str:
    """Return the first non-empty line of *fn*'s docstring, or ``""``."""
    doc = fn.__doc__ or ""
    for line in doc.splitlines():
        stripped = line.strip()
        if stripped:
            return stripped
    return ""


# ---------------------------------------------------------------------------
# ToolRegistry
# ---------------------------------------------------------------------------


class ToolRegistry:
    """Central store for all registered tools.

    Each tool is identified by a unique name.  Re-registering an existing name
    silently overwrites the previous entry — this supports hot-reload in
    development but should not happen in production.

    Security notes:
    - ``list_tools_for_agent`` respects the full permission model (allowlist,
      denylist, trust level) so an agent only ever sees tools it is permitted
      to use.
    - Handlers are stored separately from definitions so the LLM never has
      direct access to Python callables.
    """

    def __init__(self) -> None:
        self._tools: dict[str, ToolDefinition] = {}
        self._handlers: dict[str, Optional[Callable[..., Any]]] = {}

    def register(
        self,
        tool: ToolDefinition,
        handler: Optional[Callable[..., Any]] = None,
    ) -> None:
        """Register *tool* and its *handler* callable.

        Args:
            tool:    Metadata describing the tool.
            handler: Async or sync callable that implements the tool.
                     May be ``None`` for MCP tools — MCPToolBridge handles
                     execution for those by routing through MCPServerConnection
                     rather than a local Python handler.
        """
        self._tools[tool.name] = tool
        self._handlers[tool.name] = handler

    def unregister(self, name: str) -> None:
        """Remove a tool and its handler from the registry.

        No-op if *name* is not registered.
        """
        self._tools.pop(name, None)
        self._handlers.pop(name, None)

    def get(self, name: str) -> Optional[ToolDefinition]:
        """Return the ``ToolDefinition`` for *name*, or ``None`` if not found."""
        return self._tools.get(name)

    def get_handler(self, name: str) -> Optional[Callable[..., Any]]:
        """Return the handler callable for *name*, or ``None`` if not found."""
        return self._handlers.get(name)

    def list_tools(self) -> list[ToolDefinition]:
        """Return all registered tool definitions in insertion order."""
        return list(self._tools.values())

    def list_tools_for_agent(self, agent_config: AgentConfig) -> list[ToolDefinition]:
        """Return only the tools that *agent_config* is permitted to invoke.

        Applies the full permission model (allowlist, denylist, trust level)
        via ``check_permission``.  The returned list is safe to send to the
        LLM as the available tool set for a given agent.
        """
        result: list[ToolDefinition] = []
        for tool_def in self._tools.values():
            allowed, _ = check_permission(agent_config, tool_def.name, tool_def)
            if allowed:
                result.append(tool_def)
        return result


# ---------------------------------------------------------------------------
# @tool decorator
# ---------------------------------------------------------------------------

#: Module-level default registry used by the ``@tool`` decorator when no
#: explicit ``registry=`` is passed.  Set via ``configure_default_registry()``.
_default_registry: Optional[ToolRegistry] = None


def configure_default_registry(registry: ToolRegistry) -> None:
    """Set the module-level default registry used by the ``@tool`` decorator."""
    global _default_registry
    _default_registry = registry


@overload
def tool(fn: _F) -> _F: ...


@overload
def tool(
    fn: None = ...,
    *,
    name: Optional[str] = ...,
    description: Optional[str] = ...,
    trust_level_required: TrustLevel = ...,
    requires_approval: bool = ...,
    security_notes: str = ...,
    registry: Optional[ToolRegistry] = ...,
) -> Callable[[_F], _F]: ...


def tool(
    fn: Optional[Callable[..., Any]] = None,
    *,
    name: Optional[str] = None,
    description: Optional[str] = None,
    trust_level_required: TrustLevel = TrustLevel.main,
    requires_approval: bool = False,
    security_notes: str = "",
    registry: Optional[ToolRegistry] = None,
) -> Any:
    """Decorator that registers a function as a tool with inferred metadata.

    Can be used with or without arguments::

        @tool
        async def web_search(query: str) -> str:
            "Search the web."
            ...

        @tool(name="search", trust_level_required=TrustLevel.public)
        async def web_search(query: str) -> str:
            ...

        @tool(registry=my_registry)
        async def my_tool(x: int) -> str:
            ...

    Metadata inferred automatically:

    - **name**: function name (``__name__``)
    - **description**: first line of the docstring
    - **parameters**: JSON Schema built from the function's type annotations

    Args:
        fn:                   Function being decorated (when used without args).
        name:                 Override the inferred tool name.
        description:          Override the inferred description.
        trust_level_required: Minimum agent trust level; defaults to ``main``.
        requires_approval:    Whether this tool pauses for human approval.
        security_notes:       Free-text security documentation.
        registry:             Explicit registry to register into; falls back to
                              the module-level default set by
                              ``configure_default_registry()``.

    Security notes:
    - ``trust_level_required`` defaults to ``main`` — never lower than ``public``
      unless the tool is genuinely safe for sandboxed agents.
    - Always document known risks in ``security_notes``.
    """

    def _make_definition(f: Callable[..., Any]) -> ToolDefinition:
        return ToolDefinition(
            name=name or f.__name__,
            description=description or _first_doc_line(f) or (name or f.__name__),
            parameters=_infer_parameters(f),
            requires_approval=requires_approval,
            trust_level_required=trust_level_required,
            security_notes=security_notes,
        )

    def decorator(f: Callable[..., Any]) -> Callable[..., Any]:
        tool_def = _make_definition(f)
        target = registry or _default_registry
        if target is not None:
            target.register(tool_def, f)
        # Attach definition to function for introspection / testing.
        f._tool_definition = tool_def  # type: ignore[attr-defined]
        return f

    if fn is not None:
        # Used as @tool (no parentheses) — fn is the decorated function.
        return decorator(fn)

    # Used as @tool(...) (with parentheses) — return the decorator.
    return decorator
