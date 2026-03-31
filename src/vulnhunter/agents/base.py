"""Base agent with ReAct-style tool calling loop, supervision, and context management."""
from __future__ import annotations

import json
import logging
from collections import Counter
from typing import TYPE_CHECKING, Any, Callable

from vulnhunter.ai.provider import LLMProvider
from vulnhunter.models import AgentAction, AgentRole, ToolResult
from vulnhunter.tools.base import BaseTool

if TYPE_CHECKING:
    from vulnhunter.agents.monitor import ExecutionMonitor

logger = logging.getLogger("vulnhunter.agents")

SAME_TOOL_LIMIT = 4
TOTAL_TOOL_LIMIT_WARN = 15
CONTEXT_SUMMARIZE_THRESHOLD = 40


class BaseAgent:
    """Base agent with ReAct-style tool-calling loop.

    Includes:
    - Loop detection: stops if same tool called N times consecutively
    - Stuck recovery: injects guidance when agent appears stuck
    - Context summarization: compresses old messages to stay within token limits
    """

    def __init__(
        self,
        role: AgentRole,
        system_prompt: str,
        tools: list[BaseTool],
        llm: LLMProvider,
        max_iterations: int = 30,
        on_action: Callable[[AgentAction], None] | None = None,
        monitor: ExecutionMonitor | None = None,
    ):
        self.role = role
        self.system_prompt = system_prompt
        self.tools = {t.name: t for t in tools}
        self.llm = llm
        self.max_iterations = max_iterations
        self.on_action = on_action
        self.monitor = monitor
        self.actions: list[AgentAction] = []
        self.all_tool_results: list[ToolResult] = []

    def _emit(self, action: AgentAction) -> None:
        self.actions.append(action)
        if self.monitor:
            self.monitor.record_action(action)
        if self.on_action:
            self.on_action(action)

    async def run(self, task: str) -> str:
        tool_defs = [t.to_openai_function() for t in self.tools.values()]

        messages: list[dict[str, Any]] = [
            {"role": "system", "content": self.system_prompt},
            {"role": "user", "content": task},
        ]

        self._emit(AgentAction(
            agent=self.role, action_type="thinking",
            thought=f"Starting task: {task[:200]}",
        ))

        tool_call_history: list[str] = []
        consecutive_same: int = 0
        last_tool: str = ""
        total_tool_calls: int = 0
        no_progress_count: int = 0

        for iteration in range(self.max_iterations):
            if self.monitor and self.monitor.is_cancelled:
                return "Scan cancelled by user."

            logger.info(f"[{self.role.value}] Iteration {iteration + 1}/{self.max_iterations}")

            if len(messages) > CONTEXT_SUMMARIZE_THRESHOLD:
                messages = self._summarize_context(messages)

            try:
                response = await self.llm.chat(
                    messages=messages,
                    tools=tool_defs if tool_defs else None,
                )
            except Exception as e:
                logger.error(f"[{self.role.value}] LLM error: {e}")
                self._emit(AgentAction(agent=self.role, action_type="error", thought=f"LLM error: {e}"))
                if "context_length" in str(e).lower() or "token" in str(e).lower():
                    messages = self._summarize_context(messages, aggressive=True)
                    continue
                return f"Error communicating with AI: {e}"

            if not response["tool_calls"]:
                final_text = response["content"]
                self._emit(AgentAction(agent=self.role, action_type="result", thought=final_text[:500]))
                return final_text

            assistant_msg: dict[str, Any] = {
                "role": "assistant",
                "content": response["content"] or None,
                "tool_calls": [
                    {"id": tc["id"], "type": "function",
                     "function": {"name": tc["name"], "arguments": json.dumps(tc["arguments"])}}
                    for tc in response["tool_calls"]
                ],
            }
            messages.append(assistant_msg)

            for tc in response["tool_calls"]:
                tool_name = tc["name"]
                tool_args = tc["arguments"]
                call_id = tc["id"]
                total_tool_calls += 1

                if tool_name == last_tool:
                    consecutive_same += 1
                else:
                    consecutive_same = 1
                    last_tool = tool_name
                tool_call_history.append(tool_name)

                if consecutive_same >= SAME_TOOL_LIMIT:
                    self._emit(AgentAction(
                        agent=self.role, action_type="thinking",
                        thought=f"Loop detected: {tool_name} called {consecutive_same} times. Trying different approach.",
                    ))
                    messages.append({
                        "role": "tool", "tool_call_id": call_id,
                        "content": (
                            f"SUPERVISOR WARNING: You have called {tool_name} {consecutive_same} times "
                            f"consecutively with similar arguments. This appears to be a loop. "
                            f"STOP calling {tool_name} and either: (1) try a DIFFERENT tool, "
                            f"(2) move on to the next subtask, or (3) provide your final analysis. "
                            f"Tools you haven't tried: {', '.join(set(self.tools.keys()) - set(tool_call_history[-10:]))}"
                        ),
                    })
                    consecutive_same = 0
                    continue

                if total_tool_calls >= TOTAL_TOOL_LIMIT_WARN and total_tool_calls % 5 == 0:
                    counts = Counter(tool_call_history)
                    top = counts.most_common(3)
                    logger.warning(f"[{self.role.value}] High tool usage ({total_tool_calls}): {top}")

                self._emit(AgentAction(
                    agent=self.role, action_type="tool_call",
                    tool_name=tool_name, tool_input=tool_args,
                ))

                tool = self.tools.get(tool_name)
                if tool:
                    try:
                        result = await tool.execute(**tool_args)
                    except Exception as e:
                        logger.error(f"Tool {tool_name} crashed: {e}")
                        result = ToolResult(tool_name=tool_name, success=False, error=str(e), raw_output=f"Tool error: {e}")

                    self.all_tool_results.append(result)
                    self._emit(AgentAction(
                        agent=self.role, action_type="tool_result",
                        tool_name=tool_name, tool_output=result.raw_output[:500],
                    ))

                    tool_response = result.raw_output[:4000]
                    if result.vulnerabilities:
                        tool_response += f"\n\nVulnerabilities found: {len(result.vulnerabilities)}"
                        for v in result.vulnerabilities[:10]:
                            tool_response += f"\n  [{v.severity.value.upper()}] {v.title}: {v.description}"
                    if result.error:
                        tool_response = f"Error: {result.error}"

                    messages.append({"role": "tool", "tool_call_id": call_id, "content": tool_response})
                else:
                    messages.append({
                        "role": "tool", "tool_call_id": call_id,
                        "content": f"Error: Tool '{tool_name}' not found. Available: {', '.join(self.tools.keys())}",
                    })

        self._emit(AgentAction(
            agent=self.role, action_type="thinking",
            thought=f"Reached {self.max_iterations} iterations. Wrapping up with available findings.",
        ))
        messages.append({"role": "user", "content": (
            "You have reached the maximum number of tool calls. "
            "Please provide your final analysis and findings NOW based on everything collected so far."
        )})
        try:
            final = await self.llm.chat(messages=messages)
            return final["content"] or "Maximum iterations reached."
        except Exception:
            return "Maximum iterations reached. Returning partial results."

    def _summarize_context(self, messages: list[dict[str, Any]], aggressive: bool = False) -> list[dict[str, Any]]:
        """Compress conversation history to stay within token limits."""
        if len(messages) < 8:
            return messages

        system = messages[0]
        user_task = messages[1]
        keep_recent = 6 if aggressive else 12
        recent = messages[-keep_recent:]

        middle = messages[2:-keep_recent]
        if not middle:
            return messages

        tool_names = []
        findings = []
        for msg in middle:
            if msg.get("role") == "assistant" and msg.get("tool_calls"):
                for tc in msg["tool_calls"]:
                    fn = tc.get("function", {})
                    tool_names.append(fn.get("name", "unknown"))
            elif msg.get("role") == "tool":
                content = msg.get("content", "")
                if "Vulnerabilities found" in content or "Error:" in content:
                    findings.append(content[:200])

        summary_text = (
            f"[CONTEXT SUMMARY: Previous {len(middle)} messages compressed]\n"
            f"Tools called: {', '.join(dict.fromkeys(tool_names))}\n"
        )
        if findings:
            summary_text += f"Key findings:\n" + "\n".join(findings[:10])

        summary_msg = {"role": "user", "content": summary_text}
        result = [system, user_task, summary_msg] + recent

        logger.info(f"[{self.role.value}] Context summarized: {len(messages)} → {len(result)} messages")
        self._emit(AgentAction(
            agent=self.role, action_type="thinking",
            thought=f"Context compressed: {len(messages)} → {len(result)} messages to stay within limits",
        ))
        return result
