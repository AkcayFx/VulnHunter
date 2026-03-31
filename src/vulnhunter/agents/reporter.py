"""Reporter agent — compiles all findings into a structured report."""
from __future__ import annotations

from typing import Callable

from vulnhunter.ai.provider import LLMProvider
from vulnhunter.ai.prompts import REPORTER_PROMPT
from vulnhunter.models import AgentAction, AgentRole, ToolResult, Vulnerability


class ReporterAgent:
    """Compiles recon + exploit results into a final JSON assessment via LLM."""

    def __init__(
        self,
        llm: LLMProvider,
        on_action: Callable[[AgentAction], None] | None = None,
    ):
        self.llm = llm
        self.on_action = on_action

    async def run(
        self,
        target_host: str,
        recon_summary: str,
        exploit_summary: str,
        vulnerabilities: list[Vulnerability],
        tool_results: list[ToolResult],
    ) -> str:
        self._emit(AgentAction(agent=AgentRole.REPORTER, action_type="thinking", thought="Compiling final report"))

        vuln_text = ""
        for v in vulnerabilities:
            vuln_text += f"  [{v.severity.value.upper()}] {v.title} (tool: {v.tool}): {v.description}\n"
        if not vuln_text:
            vuln_text = "  No vulnerabilities detected by automated tools.\n"

        tool_text = ""
        for tr in tool_results:
            status = "OK" if tr.success else "FAIL"
            tool_text += f"  {tr.tool_name}: {status} ({tr.duration_seconds:.1f}s)"
            if tr.vulnerabilities:
                tool_text += f" — {len(tr.vulnerabilities)} findings"
            tool_text += "\n"

        prompt = (
            f"Target: {target_host}\n\n"
            f"## Reconnaissance Summary\n{recon_summary[:3000]}\n\n"
            f"## Vulnerability Analysis Summary\n{exploit_summary[:3000]}\n\n"
            f"## Detected Vulnerabilities ({len(vulnerabilities)} total)\n{vuln_text}\n"
            f"## Tool Execution Summary\n{tool_text}\n"
            f"Generate the final security assessment as JSON."
        )

        result = await self.llm.simple_chat(REPORTER_PROMPT, prompt)
        self._emit(AgentAction(agent=AgentRole.REPORTER, action_type="result", thought="Report generated"))
        return result

    def _emit(self, action: AgentAction) -> None:
        if self.on_action:
            self.on_action(action)
