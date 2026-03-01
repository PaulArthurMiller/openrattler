"""Agent turn loop — the core of OpenRattler's LLM orchestration.

``AgentRuntime.process_message()`` is the single entry point for processing
a user message.  It executes the full agent turn:

1. Append user message to the session transcript.
2. Build the LLM messages list (system prompt + history).
3. Call the LLM provider.
4. If the response contains tool calls, execute them via ``ToolExecutor`` and
   feed results back to the LLM (repeat up to ``_MAX_TOOL_LOOPS`` times).
5. Build the assistant ``UniversalMessage`` response.
6. Append it to the transcript.
7. Audit-log the turn.
8. Return the response.

SAFETY GUARANTEES
-----------------
- The tool loop is bounded by ``_MAX_TOOL_LOOPS`` (10 iterations).  If the
  limit is hit, the runtime returns an error ``UniversalMessage`` rather than
  looping forever.
- ``process_message`` never raises — all errors are returned as error-typed
  ``UniversalMessage`` objects so the caller always receives a structured reply.
"""

from __future__ import annotations

import json
from typing import Any, Optional

from openrattler.agents.providers.base import LLMProvider, LLMResponse
from openrattler.models.agents import AgentConfig
from openrattler.models.audit import AuditEvent
from openrattler.models.messages import UniversalMessage, create_message
from openrattler.models.sessions import Session
from openrattler.models.tools import ToolDefinition
from openrattler.storage.audit import AuditLog
from openrattler.storage.memory import MemoryStore
from openrattler.storage.transcripts import TranscriptStore
from openrattler.tools.executor import ToolExecutor

# Maximum number of tool-execution iterations per turn.  After this many
# loops the runtime breaks out and returns an error to the caller.
_MAX_TOOL_LOOPS: int = 10


class AgentRuntime:
    """Orchestrates a single agent's interaction with an LLM and its tools.

    One ``AgentRuntime`` instance is created per agent (not per turn).
    ``initialize_session`` is called once per session; ``process_message`` is
    called once per user turn.

    Security notes:
    - Tool permission checks are performed by ``ToolExecutor`` on every tool
      call — they are never bypassed here.
    - The tool loop hard-limits at ``_MAX_TOOL_LOOPS`` to prevent prompt-
      injection attacks that try to trigger infinite tool chains.
    - All turns (success and error) are audit-logged.
    """

    def __init__(
        self,
        config: AgentConfig,
        provider: LLMProvider,
        tool_executor: ToolExecutor,
        transcript_store: TranscriptStore,
        memory_store: MemoryStore,
        audit_log: AuditLog,
    ) -> None:
        self._config = config
        self._provider = provider
        self._tool_executor = tool_executor
        self._transcript_store = transcript_store
        self._memory_store = memory_store
        self._audit = audit_log

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    async def initialize_session(self, session_key: str) -> Session:
        """Load session state and return a ``Session`` ready for ``process_message``.

        Args:
            session_key: Validated session key (e.g. ``"agent:main:main"``).

        Returns:
            A ``Session`` with history loaded from the transcript store and
            a fully-rendered system prompt.
        """
        agent_id = self._config.agent_id
        # MemoryStore only accepts colon-free names; the session key encodes
        # the bare agent name as the second colon-delimited component.
        memory_id = session_key.split(":")[1]
        history = await self._transcript_store.load(session_key)
        memory = await self._memory_store.load(memory_id)
        system_prompt = self._build_system_prompt(memory)
        return Session(
            key=session_key,
            agent_id=agent_id,
            history=history,
            system_prompt=system_prompt,
        )

    async def process_message(
        self,
        session: Session,
        user_message: UniversalMessage,
    ) -> UniversalMessage:
        """Process one user turn and return the assistant's response.

        This method never raises.  Tool-loop overflow, unexpected provider
        errors, or other failures are returned as ``type="error"``
        ``UniversalMessage`` objects.

        Args:
            session:      Live session object (mutated in place — history is
                          appended for both the user message and the response).
            user_message: The incoming user ``UniversalMessage``.

        Returns:
            The assistant's ``UniversalMessage`` (``type="response"`` on
            success, ``type="error"`` if the tool-loop limit is exceeded).
        """
        session_key = session.key
        tool_loop_count = 0
        last_response: Optional[LLMResponse] = None

        try:
            # 1. Persist user message
            session.history.append(user_message)
            await self._transcript_store.append(session_key, user_message)

            # 2. Build initial LLM input
            messages = self._build_messages(session)
            tool_defs = self._build_tool_defs()
            tools_arg = tool_defs if tool_defs else None

            # 3. Initial LLM call
            last_response = await self._provider.complete(
                messages=messages,
                tools=tools_arg,
            )

            # 4. Tool loop
            while last_response.tool_calls and tool_loop_count < _MAX_TOOL_LOOPS:
                tool_loop_count += 1

                # Add assistant tool-call turn to the in-memory message list
                messages.append(self._assistant_tool_call_message(last_response))

                # Execute each tool call and add results
                for tc in last_response.tool_calls:
                    tool_result = await self._tool_executor.execute(self._config, tc)
                    result_content = (
                        str(tool_result.result)
                        if tool_result.success
                        else f"Error: {tool_result.error}"
                    )
                    messages.append(
                        {
                            "role": "tool",
                            "tool_call_id": tc.call_id,
                            "content": result_content,
                        }
                    )

                # Continue the conversation with tool results
                last_response = await self._provider.complete(
                    messages=messages,
                    tools=tools_arg,
                )

            # 5. Detect loop-limit overflow
            exceeded = bool(last_response.tool_calls) and tool_loop_count >= _MAX_TOOL_LOOPS
            if exceeded:
                assistant_msg = create_message(
                    from_agent=self._config.agent_id,
                    to_agent=user_message.from_agent,
                    session_key=session_key,
                    type="error",
                    operation=user_message.operation,
                    trust_level=self._config.trust_level.value,
                    trace_id=user_message.trace_id,
                    error={
                        "code": "tool_loop_limit",
                        "message": (
                            f"Tool execution loop exceeded the maximum of "
                            f"{_MAX_TOOL_LOOPS} iterations."
                        ),
                    },
                )
            else:
                assistant_msg = create_message(
                    from_agent=self._config.agent_id,
                    to_agent=user_message.from_agent,
                    session_key=session_key,
                    type="response",
                    operation=user_message.operation,
                    trust_level=self._config.trust_level.value,
                    trace_id=user_message.trace_id,
                    params={"content": last_response.content},
                )

        except Exception as exc:
            # Unexpected error (provider failure, etc.) — return structured error
            assistant_msg = create_message(
                from_agent=self._config.agent_id,
                to_agent=user_message.from_agent,
                session_key=session_key,
                type="error",
                operation=user_message.operation,
                trust_level=self._config.trust_level.value,
                trace_id=user_message.trace_id,
                error={"code": "runtime_error", "message": str(exc)},
            )

        # 6. Persist assistant message
        session.history.append(assistant_msg)
        await self._transcript_store.append(session_key, assistant_msg)

        # 7. Audit log the turn
        await self._audit.log(
            AuditEvent(
                event="agent_turn",
                agent_id=self._config.agent_id,
                session_key=session_key,
                trace_id=user_message.trace_id,
                details={
                    "operation": user_message.operation,
                    "tool_loops": tool_loop_count,
                    "finish_reason": last_response.finish_reason if last_response else "error",
                    "exceeded_loop_limit": bool(
                        last_response
                        and last_response.tool_calls
                        and tool_loop_count >= _MAX_TOOL_LOOPS
                    ),
                },
            )
        )

        # 8. Return response
        return assistant_msg

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _build_system_prompt(self, memory: dict[str, Any]) -> str:
        """Combine the agent's base system prompt with any loaded memory.

        The base prompt is taken from ``config.system_prompt``.  If the memory
        dict is non-empty, a ``## Memory`` section is appended so the LLM has
        access to persistent state.
        """
        parts = [self._config.system_prompt] if self._config.system_prompt else []
        if memory:
            mem_lines = "\n".join(f"- {k}: {v}" for k, v in memory.items())
            parts.append(f"## Memory\n{mem_lines}")
        return "\n\n".join(parts)

    def _build_messages(self, session: Session) -> list[dict[str, Any]]:
        """Convert session history to OpenAI-format message dicts.

        The system prompt (if any) is prepended as a ``system`` role message.
        Only ``request`` (user) and ``response`` (assistant) messages from the
        transcript are included; tool-loop messages are ephemeral and live only
        in the in-memory list built during a single turn.
        """
        messages: list[dict[str, Any]] = []

        if session.system_prompt:
            messages.append({"role": "system", "content": session.system_prompt})

        for msg in session.history:
            if msg.type == "request":
                messages.append({"role": "user", "content": msg.params.get("content", "")})
            elif msg.type == "response":
                messages.append({"role": "assistant", "content": msg.params.get("content", "")})
            # Other types (error, event) are not forwarded to the LLM.

        return messages

    def _build_tool_defs(self) -> list[dict[str, Any]]:
        """Return the agent's permitted tools in OpenAI function-calling format."""
        # Access the registry via the executor to avoid exposing it as a separate
        # constructor parameter — ToolExecutor already holds a reference to it.
        permitted: list[ToolDefinition] = self._tool_executor._registry.list_tools_for_agent(
            self._config
        )
        return [
            {
                "type": "function",
                "function": {
                    "name": td.name,
                    "description": td.description,
                    "parameters": td.parameters,
                },
            }
            for td in permitted
        ]

    @staticmethod
    def _assistant_tool_call_message(response: LLMResponse) -> dict[str, Any]:
        """Build the OpenAI-format assistant message that carries tool calls."""
        return {
            "role": "assistant",
            "content": response.content,
            "tool_calls": [
                {
                    "id": tc.call_id,
                    "type": "function",
                    "function": {
                        "name": tc.tool_name,
                        "arguments": json.dumps(tc.arguments),
                    },
                }
                for tc in response.tool_calls
            ],
        }
