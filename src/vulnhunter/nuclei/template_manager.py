"""AI-driven Nuclei template selection and custom template generation.

Instead of blasting all 8000+ templates blindly, this module:
1. Analyzes recon data (tech stack, open ports, discovered endpoints)
2. Selects the most relevant template directories and tags
3. Can generate custom Nuclei templates via LLM for novel hypotheses

This keeps scans efficient: intelligent, targeted template selection instead of blind full runs.
"""
from __future__ import annotations

import json
import logging
from typing import Any

from vulnhunter.ai.provider import LLMProvider
from vulnhunter.nuclei.profiles import (
    SCAN_PROFILES,
    ScanProfile,
    get_profile,
    get_tags_for_tech,
    get_templates_for_tech,
)

logger = logging.getLogger("vulnhunter.nuclei")

TEMPLATE_SELECTION_PROMPT = """\
You are a Nuclei template selection expert for bug bounty hunting.

Given the reconnaissance data below, select the optimal Nuclei scan strategy.

## Available Profiles:
- quick: critical/high HTTP vulns only (fast)
- web-full: medium+ HTTP vulnerabilities (thorough)
- cves-only: known CVEs only
- misconfig: misconfigurations and exposed services
- takeover: subdomain takeover detection
- default-creds: default login credentials
- exposed-panels: exposed admin panels
- tokens: exposed API keys and secrets
- full: everything (slow, use only when needed)

## Instructions:
1. Analyze the tech stack, open ports, and discovered endpoints
2. Choose 1-3 profiles that are most relevant
3. List any specific template directories to add beyond the profiles
4. Suggest a severity filter
5. If you see something unusual that standard templates won't catch, describe it

Output as JSON:
```json
{
  "profiles": ["profile1", "profile2"],
  "extra_templates": ["/path/to/template/dir/"],
  "severity": "medium,high,critical",
  "custom_checks": ["description of anything unusual to check"],
  "reasoning": "brief explanation"
}
```\
"""

CUSTOM_TEMPLATE_PROMPT = """\
You are a Nuclei template author. Generate a valid Nuclei YAML template to detect the described vulnerability.

Rules:
- Use Nuclei v3 template syntax
- Include proper info block with name, author, severity, description, tags
- Use appropriate matchers (word, regex, status, dsl)
- Include proper request definition
- Keep it focused on one specific check

Output ONLY the YAML template content, no markdown fences or explanation.\
"""


class NucleiTemplateManager:
    """Manages intelligent Nuclei template selection and generation."""

    def __init__(self, llm: LLMProvider | None = None):
        self._llm = llm

    def select_templates_static(
        self,
        technologies: list[str],
        open_ports: list[int] | None = None,
        endpoints: list[str] | None = None,
    ) -> NucleiScanPlan:
        """Rule-based template selection from discovered tech stack.

        Fast, no LLM call required. Good for automated pipelines.
        """
        templates = get_templates_for_tech(technologies)
        tags = get_tags_for_tech(technologies)

        profiles: list[str] = []
        extra_templates: list[str] = list(templates)

        # Always include misconfig check
        profiles.append("misconfig")

        # If we found web endpoints, do full web scan
        if endpoints:
            profiles.append("web-full")

        # If admin panels or login pages found, try default creds
        if endpoints and any(
            kw in ep.lower()
            for ep in endpoints
            for kw in ("/admin", "/login", "/dashboard", "/panel", "/manager")
        ):
            profiles.append("default-creds")
            profiles.append("exposed-panels")

        # If we found interesting ports, add relevant templates
        if open_ports:
            port_techs = _ports_to_tech(open_ports)
            extra_templates.extend(get_templates_for_tech(port_techs))

        # Determine severity based on what we found
        severity = "medium,high,critical"
        if any(
            tech.lower() in ("wordpress", "joomla", "drupal")
            for tech in technologies
        ):
            severity = "low,medium,high,critical"

        # Deduplicate
        profiles = list(dict.fromkeys(profiles))
        extra_templates = list(dict.fromkeys(extra_templates))

        return NucleiScanPlan(
            profiles=profiles,
            extra_templates=extra_templates,
            tags=tags,
            severity=severity,
            reasoning=f"Static selection for: {', '.join(technologies[:10]) or 'generic target'}",
        )

    async def select_templates_ai(
        self,
        technologies: list[str],
        open_ports: list[int] | None = None,
        endpoints: list[str] | None = None,
        recon_summary: str = "",
    ) -> NucleiScanPlan:
        """AI-powered template selection using LLM analysis of recon data.

        Falls back to static selection if LLM is unavailable.
        """
        if not self._llm:
            return self.select_templates_static(technologies, open_ports, endpoints)

        context = "## Recon Data\n\n"
        if technologies:
            context += f"**Technologies:** {', '.join(technologies)}\n"
        if open_ports:
            context += f"**Open Ports:** {', '.join(str(p) for p in open_ports[:30])}\n"
        if endpoints:
            context += f"**Discovered Endpoints ({len(endpoints)} total):**\n"
            for ep in endpoints[:30]:
                context += f"  - {ep}\n"
        if recon_summary:
            context += f"\n**Recon Summary:**\n{recon_summary[:2000]}\n"

        try:
            response = await self._llm.simple_chat(TEMPLATE_SELECTION_PROMPT, context)
            return self._parse_ai_selection(response, technologies, open_ports, endpoints)
        except Exception as e:
            logger.warning(f"AI template selection failed ({e}), using static fallback")
            return self.select_templates_static(technologies, open_ports, endpoints)

    async def generate_custom_template(self, hypothesis: str) -> str | None:
        """Use LLM to generate a custom Nuclei template for a specific vulnerability hypothesis.

        This is something no other tool does — AI writes new detection rules on the fly.
        Returns the YAML template string, or None on failure.
        """
        if not self._llm:
            return None

        try:
            template_yaml = await self._llm.simple_chat(CUSTOM_TEMPLATE_PROMPT, hypothesis)
            template_yaml = template_yaml.strip()
            # Strip markdown fences if the LLM wrapped it
            if template_yaml.startswith("```"):
                lines = template_yaml.splitlines()
                lines = [l for l in lines if not l.strip().startswith("```")]
                template_yaml = "\n".join(lines)

            if "id:" in template_yaml and "requests:" in template_yaml or "http:" in template_yaml:
                return template_yaml

            logger.warning("Generated template missing required fields")
            return None
        except Exception as e:
            logger.warning(f"Custom template generation failed: {e}")
            return None

    def build_command(self, plan: NucleiScanPlan, target: str) -> list[str]:
        """Build the final nuclei CLI command from a scan plan."""
        cmd = ["nuclei", "-u", target, "-json", "-silent"]

        # Collect all args from profiles
        seen_args: set[str] = set()
        for profile_name in plan.profiles:
            profile = get_profile(profile_name)
            for arg in profile.args:
                if arg not in seen_args:
                    cmd.append(arg)
                    seen_args.add(arg)

        # Add extra template paths
        for tpl in plan.extra_templates:
            cmd.extend(["-t", tpl])

        # Add tags
        if plan.tags:
            cmd.extend(["-tags", ",".join(plan.tags)])

        # Add severity filter (if not already set by profiles)
        if plan.severity and "-severity" not in seen_args:
            cmd.extend(["-severity", plan.severity])

        return cmd

    def estimate_duration(self, plan: NucleiScanPlan) -> int:
        """Estimate scan duration in seconds based on the plan."""
        total = 0
        for profile_name in plan.profiles:
            profile = get_profile(profile_name)
            total += profile.max_duration_seconds

        extra_count = len(plan.extra_templates)
        total += extra_count * 30

        return min(total, 1800)

    def _parse_ai_selection(
        self,
        response: str,
        technologies: list[str],
        open_ports: list[int] | None,
        endpoints: list[str] | None,
    ) -> NucleiScanPlan:
        """Parse LLM response into a NucleiScanPlan."""
        json_str = _extract_json(response)
        if not json_str:
            return self.select_templates_static(technologies, open_ports, endpoints)

        try:
            data = json.loads(json_str)
        except json.JSONDecodeError:
            return self.select_templates_static(technologies, open_ports, endpoints)

        profiles = data.get("profiles", ["web-full"])
        if not isinstance(profiles, list):
            profiles = [str(profiles)]
        # Validate profile names
        profiles = [p for p in profiles if p in SCAN_PROFILES]
        if not profiles:
            profiles = ["web-full"]

        extra = data.get("extra_templates", [])
        if not isinstance(extra, list):
            extra = []

        # Merge static tech templates with AI suggestions
        static_templates = get_templates_for_tech(technologies)
        all_templates = list(dict.fromkeys(static_templates + extra))

        tags = get_tags_for_tech(technologies)
        severity = data.get("severity", "medium,high,critical")
        custom_checks = data.get("custom_checks", [])
        reasoning = data.get("reasoning", "AI-selected")

        return NucleiScanPlan(
            profiles=profiles,
            extra_templates=all_templates,
            tags=tags,
            severity=severity,
            custom_checks=custom_checks,
            reasoning=reasoning,
        )


class NucleiScanPlan:
    """The output of template selection — everything needed to run a targeted scan."""

    __slots__ = (
        "profiles", "extra_templates", "tags", "severity",
        "custom_checks", "reasoning",
    )

    def __init__(
        self,
        profiles: list[str] | None = None,
        extra_templates: list[str] | None = None,
        tags: list[str] | None = None,
        severity: str = "medium,high,critical",
        custom_checks: list[str] | None = None,
        reasoning: str = "",
    ):
        self.profiles = profiles or ["web-full"]
        self.extra_templates = extra_templates or []
        self.tags = tags or []
        self.severity = severity
        self.custom_checks = custom_checks or []
        self.reasoning = reasoning

    def summary(self) -> str:
        """Human-readable summary of the scan plan."""
        lines = [f"Nuclei Scan Plan: {self.reasoning}"]
        lines.append(f"  Profiles: {', '.join(self.profiles)}")
        if self.extra_templates:
            lines.append(f"  Extra templates: {len(self.extra_templates)} directories")
        if self.tags:
            lines.append(f"  Tags: {', '.join(self.tags)}")
        lines.append(f"  Severity: {self.severity}")
        if self.custom_checks:
            lines.append(f"  Custom checks: {len(self.custom_checks)}")
        return "\n".join(lines)


def _ports_to_tech(ports: list[int]) -> list[str]:
    """Infer technology names from open port numbers."""
    port_tech: dict[int, str] = {
        21: "ftp", 22: "ssh", 25: "smtp", 53: "dns",
        80: "http", 443: "https", 445: "smb",
        1433: "mssql", 1521: "oracle", 3306: "mysql",
        3389: "rdp", 5432: "postgresql", 5900: "vnc",
        6379: "redis", 8080: "tomcat", 8443: "tomcat",
        9200: "elasticsearch", 27017: "mongodb",
        5601: "kibana", 9090: "prometheus", 3000: "grafana",
        8888: "jupyter", 15672: "rabbitmq",
    }
    return [port_tech[p] for p in ports if p in port_tech]


def _extract_json(text: str) -> str:
    """Extract JSON from LLM response (handles markdown fences)."""
    import re
    json_match = re.search(r"```(?:json)?\s*(\{.*?\})\s*```", text, re.DOTALL)
    if json_match:
        return json_match.group(1)

    brace_match = re.search(r"\{.*\}", text, re.DOTALL)
    if brace_match:
        return brace_match.group(0)

    return ""
