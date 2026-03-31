"""Task planner — decomposes a pentest target into structured subtasks."""
from __future__ import annotations

import json
import logging
import re
from typing import Any

from vulnhunter.ai.provider import LLMProvider
from vulnhunter.ai.prompts import PLANNER_PROMPT
from vulnhunter.models import AgentRole, ScanTarget, SubTask

logger = logging.getLogger("vulnhunter.agents.planner")


class TaskPlanner:
    """Uses the LLM to decompose a scan target into a structured list of subtasks."""

    def __init__(self, llm: LLMProvider):
        self.llm = llm

    async def plan(self, target: ScanTarget, stealth_mode: str = "normal") -> list[SubTask]:
        prompt = f"Target: {target.host}\n"
        if target.ports:
            prompt += f"Ports: {target.ports}\n"
        prompt += f"Stealth mode: {stealth_mode}\n"

        if target.custom_task:
            prompt += (
                f"\nUSER INSTRUCTIONS: {target.custom_task}\n\n"
                f"CRITICAL RULES FOR FOCUSED TASKS:\n"
                f"- Create ONLY 2-4 subtasks total\n"
                f"- Recon subtask (if needed) must ONLY discover what's needed for the specific test\n"
                f"  For SQLi: only find parameters (param_discovery, web_scraper for forms)\n"
                f"  For CORS: only find API endpoints (js_analyzer, web_scraper)\n"
                f"  For XSS: only find input fields (param_discovery, web_scraper)\n"
                f"- Do NOT enumerate subdomains, do NOT port scan, do NOT whois, do NOT tech fingerprint\n"
                f"- In each subtask description, write EXACTLY which tools to use and which to SKIP\n"
                f"- Keep the exploit subtask focused on the SPECIFIC vulnerability class requested\n"
            )
        else:
            prompt += "\nNo specific instructions — run a full bug bounty pipeline scan.\n"

        raw = await self.llm.simple_chat(PLANNER_PROMPT, prompt)
        return self._parse_plan(raw)

    def _parse_plan(self, text: str) -> list[SubTask]:
        json_match = re.search(r"```(?:json)?\s*(\[.*?\])\s*```", text, re.DOTALL)
        if json_match:
            json_str = json_match.group(1)
        else:
            json_match = re.search(r"\[.*\]", text, re.DOTALL)
            json_str = json_match.group(0) if json_match else "[]"

        try:
            items: list[dict[str, Any]] = json.loads(json_str)
        except json.JSONDecodeError:
            logger.warning("Failed to parse plan JSON, falling back to defaults")
            return self._default_plan()

        subtasks: list[SubTask] = []
        for item in items:
            role_str = item.get("agent", "orchestrator").lower()
            try:
                role = AgentRole(role_str)
            except ValueError:
                role = AgentRole.ORCHESTRATOR
            subtasks.append(SubTask(
                name=item.get("name", "Unnamed task"),
                agent=role,
                description=item.get("description", ""),
            ))

        if not subtasks:
            return self._default_plan()
        return subtasks

    @staticmethod
    def _default_plan() -> list[SubTask]:
        return [
            SubTask(name="Reconnaissance", agent=AgentRole.RECON,
                    description="Port scanning, DNS enumeration, WHOIS lookup, HTTP header analysis, SSL/TLS check"),
            SubTask(name="Vulnerability Analysis", agent=AgentRole.EXPLOIT,
                    description="Web vulnerability scanning, CVE lookup, directory brute-forcing"),
            SubTask(name="Report Generation", agent=AgentRole.REPORTER,
                    description="Compile all findings into a structured security assessment"),
        ]
