"""Reconnaissance agent — handles all information-gathering subtasks."""
from __future__ import annotations

from typing import Callable

from vulnhunter.agents.base import BaseAgent
from vulnhunter.ai.provider import LLMProvider
from vulnhunter.ai.prompts import RECON_PROMPT
from vulnhunter.models import AgentAction, AgentRole, SubTask, ToolResult
from vulnhunter.tools.base import BaseTool


RECON_TOOL_NAMES = {
    # Core recon
    "port_scanner", "header_analyzer", "ssl_checker", "dns_enum", "whois_lookup",
    "web_scraper", "shodan_search", "search_engine", "subdomain_enum", "tech_fingerprint",
    # Bug bounty recon pipeline
    "url_harvester", "js_analyzer", "param_discovery", "takeover_check",
    # Pro tools (available when sandbox is active)
    "nmap_scan", "httpx_probe", "subfinder_enum", "katana_crawl",
}


class ReconAgent:
    """Runs reconnaissance subtasks using the recon tool set."""

    def __init__(
        self,
        tools: list[BaseTool],
        llm: LLMProvider,
        max_iterations: int = 20,
        on_action: Callable[[AgentAction], None] | None = None,
    ):
        recon_tools = [t for t in tools if t.name in RECON_TOOL_NAMES]
        self.agent = BaseAgent(
            role=AgentRole.RECON,
            system_prompt=RECON_PROMPT,
            tools=recon_tools,
            llm=llm,
            max_iterations=max_iterations,
            on_action=on_action,
        )

    async def run(self, subtask: SubTask, target_host: str) -> str:
        task_prompt = (
            f"Execute reconnaissance subtask: {subtask.name}\n"
            f"Description: {subtask.description}\n"
            f"Target: {target_host}\n\n"
            f"Use all available recon tools to gather information about this target. "
            f"Follow the bug bounty recon methodology:\n"
            f"1. Subdomain discovery (subdomain_enum, subfinder_enum)\n"
            f"2. Check for subdomain takeovers (takeover_check)\n"
            f"3. Port & service discovery (port_scanner, nmap_scan)\n"
            f"4. Technology fingerprinting (tech_fingerprint, header_analyzer)\n"
            f"5. URL harvesting from Wayback Machine (url_harvester)\n"
            f"6. JavaScript analysis for endpoints/secrets (js_analyzer)\n"
            f"7. Parameter discovery for injection points (param_discovery)\n"
        )
        return await self.agent.run(task_prompt)

    @property
    def all_tool_results(self) -> list[ToolResult]:
        return self.agent.all_tool_results
