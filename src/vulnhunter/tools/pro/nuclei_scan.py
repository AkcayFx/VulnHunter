"""Nuclei scan wrapper — AI-driven template selection + execution inside Docker sandbox."""
from __future__ import annotations

import logging
from typing import Any

from vulnhunter.models import ToolResult
from vulnhunter.nuclei.parser import parse_and_convert
from vulnhunter.nuclei.template_manager import NucleiScanPlan, NucleiTemplateManager
from vulnhunter.tools.base import BaseTool

logger = logging.getLogger("vulnhunter.tools.nuclei")


class NucleiScanTool(BaseTool):
    """Vulnerability scanner using ProjectDiscovery Nuclei with 8000+ templates.

    Supports two modes:
    - **Smart mode**: AI analyzes recon data to select the most relevant templates.
      Pass ``technologies``, ``open_ports``, or ``endpoints`` from previous recon.
    - **Manual mode**: Specify a ``profile`` or ``templates`` directly.

    Smart mode goes beyond running nuclei manually: instead of blasting all templates,
    we target exactly what the recon discovered.
    """

    @property
    def name(self) -> str:
        return "nuclei_scan"

    @property
    def description(self) -> str:
        return (
            "Run Nuclei vulnerability scanner with 8000+ community templates inside Docker sandbox. "
            "Detects CVEs, misconfigurations, exposed panels, default credentials, and more. "
            "For best results, pass technologies/endpoints from recon so templates are auto-selected. "
            "Profiles: quick, web-full, cves-only, misconfig, takeover, default-creds, exposed-panels, tokens, full."
        )

    @property
    def parameters(self) -> dict[str, Any]:
        return {
            "type": "object",
            "properties": {
                "target": {
                    "type": "string",
                    "description": "Target URL (e.g., https://example.com)",
                },
                "profile": {
                    "type": "string",
                    "enum": ["quick", "web-full", "cves-only", "misconfig", "takeover",
                             "default-creds", "exposed-panels", "tokens", "full"],
                    "description": "Predefined scan profile. Use 'quick' for fast results, 'web-full' for thorough testing.",
                    "default": "quick",
                },
                "templates": {
                    "type": "string",
                    "description": "Manual template directory filter (e.g., 'http/cves/wordpress/'). Overrides smart selection.",
                    "default": "",
                },
                "severity": {
                    "type": "string",
                    "description": "Comma-separated severity filter (critical,high,medium,low,info)",
                    "default": "medium,high,critical",
                },
                "technologies": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "Technologies discovered during recon (e.g., ['wordpress', 'nginx', 'php']). Enables smart template selection.",
                    "default": [],
                },
                "open_ports": {
                    "type": "array",
                    "items": {"type": "integer"},
                    "description": "Open ports from port scanning. Helps select relevant templates.",
                    "default": [],
                },
                "endpoints": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "API endpoints discovered during recon (from js_analyzer, url_harvester).",
                    "default": [],
                },
            },
            "required": ["target"],
        }

    async def _execute(self, **kwargs: Any) -> ToolResult:
        if self.sandbox is None:
            raise RuntimeError("nuclei_scan requires Docker sandbox mode")

        target = kwargs["target"]
        profile = kwargs.get("profile", "quick")
        manual_templates = kwargs.get("templates", "")
        severity = kwargs.get("severity", "medium,high,critical")
        technologies = kwargs.get("technologies", [])
        open_ports = kwargs.get("open_ports", [])
        endpoints = kwargs.get("endpoints", [])

        manager = NucleiTemplateManager()

        if manual_templates:
            # Manual mode — user specified exact templates
            cmd = ["nuclei", "-u", target, "-json", "-silent",
                   "-t", manual_templates, "-severity", severity]
            plan_summary = f"Manual template selection: {manual_templates}"
        elif technologies or open_ports or endpoints:
            # Smart mode — select templates based on recon data
            plan = manager.select_templates_static(
                technologies=technologies,
                open_ports=open_ports,
                endpoints=endpoints,
            )
            cmd = manager.build_command(plan, target)
            plan_summary = plan.summary()
            logger.info(f"Smart scan plan:\n{plan_summary}")
        else:
            # Profile mode — use predefined profile
            plan = NucleiScanPlan(profiles=[profile], severity=severity)
            cmd = manager.build_command(plan, target)
            plan_summary = f"Profile: {profile}"

        timeout = manager.estimate_duration(
            NucleiScanPlan(profiles=[profile])
        ) if not (technologies or open_ports or endpoints) else 600

        exit_code, output = await self.sandbox.manager.exec_command(cmd, timeout=timeout)

        vulns = parse_and_convert(output)

        raw = f"Nuclei scan complete — {len(vulns)} findings\n"
        raw += f"Strategy: {plan_summary}\n"
        raw += f"Command: {' '.join(cmd[:10])}{'...' if len(cmd) > 10 else ''}\n\n"

        for v in vulns:
            evidence_line = v.evidence.split("\n")[0] if v.evidence else ""
            raw += f"  [{v.severity.value.upper()}] {v.title}"
            if evidence_line:
                raw += f" — {evidence_line}"
            raw += "\n"

        if not vulns:
            raw += "  No vulnerabilities found with selected templates.\n"

        return ToolResult(
            tool_name=self.name,
            success=True,
            data={
                "finding_count": len(vulns),
                "profile": profile,
                "technologies_matched": technologies,
                "plan_summary": plan_summary,
            },
            raw_output=raw,
            vulnerabilities=vulns,
        )
