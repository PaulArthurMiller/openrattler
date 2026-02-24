"""Tool models — definitions, call requests, and execution results.

These models flow through the tool framework: a ToolDefinition is registered
once, a ToolCall is produced by the LLM, and a ToolResult is returned to the
LLM after execution.
"""

from __future__ import annotations

from typing import Any, Optional

from pydantic import BaseModel, Field

from openrattler.models.agents import TrustLevel


class ToolDefinition(BaseModel):
    """Metadata describing a registered tool.

    Used by the permission layer to decide whether an agent may invoke this
    tool, and by the LLM provider to generate the tool schema sent to the
    model.

    Security notes:
    - ``trust_level_required`` is checked against the calling agent's trust
      level before execution — never skip this check.
    - ``requires_approval`` triggers the human-in-the-loop approval flow.
    - ``security_notes`` documents known risks and should be reviewed for
      every new tool registration.
    """

    name: str = Field(description="Unique tool identifier (snake_case)")
    description: str = Field(description="Human and LLM-readable description of what the tool does")
    parameters: dict[str, Any] = Field(
        description="JSON Schema object describing the tool's parameters"
    )
    requires_approval: bool = Field(
        default=False,
        description="Whether this tool must pause for human approval before execution",
    )
    trust_level_required: TrustLevel = Field(
        description="Minimum agent trust level required to call this tool"
    )
    security_notes: str = Field(
        default="",
        description="Known security risks and mitigations for this tool",
    )


class ToolCall(BaseModel):
    """A single tool invocation as produced by the LLM.

    Security notes:
    - ``arguments`` come directly from the LLM and must be validated against
      the tool's parameter schema before use.
    - ``call_id`` is used to correlate calls with results in multi-tool turns.
    """

    tool_name: str = Field(description="Name of the tool to invoke")
    arguments: dict[str, Any] = Field(
        default_factory=dict,
        description="Arguments to pass to the tool handler",
    )
    call_id: str = Field(description="Unique identifier for this call within a turn")


class ToolResult(BaseModel):
    """The outcome of a tool execution returned to the LLM.

    Always produced — even on failure.  The agent runtime must never let
    an unhandled exception propagate out of tool execution.
    """

    call_id: str = Field(description="Matches the ToolCall.call_id this result belongs to")
    success: bool = Field(description="True if the tool executed without error")
    result: Any = Field(
        default=None,
        description="Tool output on success; None on failure",
    )
    error: Optional[str] = Field(
        default=None,
        description="Error message on failure; None on success",
    )
