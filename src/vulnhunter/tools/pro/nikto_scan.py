"""Nikto scan wrapper — web server scanner inside Docker sandbox."""
from __future__ import annotations

from typing import Any

from vulnhunter.models import ToolResult
from vulnhunter.tools.base import BaseTool
from vulnhunter.tools.pro.constants import SANDBOX_REQUIRED_MSG
from vulnhunter.tools.pro.parsers import parse_nikto_json


class NiktoScanTool(BaseTool):
    """Web server vulnerability scanner using Nikto (requires Docker sandbox)."""

    @property
    def name(self) -> str:
        return "nikto_scan"

    @property
    def description(self) -> str:
        return (
            "Run Nikto web server scanner inside Docker sandbox. "
            "Checks for outdated software, dangerous files, server misconfigurations, "
            "and known vulnerabilities. Comprehensive but slow."
        )

    @property
    def parameters(self) -> dict[str, Any]:
        return {
            "type": "object",
            "properties": {
                "target": {
                    "type": "string",
                    "description": "Target URL or hostname (e.g., https://example.com)",
                },
                "tuning": {
                    "type": "string",
                    "description": "Nikto tuning options (e.g., '123' for interesting files, misconfigs, info disclosure)",
                    "default": "",
                },
            },
            "required": ["target"],
        }

    async def _execute(self, **kwargs: Any) -> ToolResult:
        if self.sandbox is None:
            raise RuntimeError(SANDBOX_REQUIRED_MSG)

        target = kwargs["target"]
        tuning = kwargs.get("tuning", "")

        cmd = ["nikto", "-h", target, "-Format", "json", "-output", "/tmp/nikto_out.json"]
        if tuning:
            cmd.extend(["-Tuning", tuning])

        exit_code, raw_output = await self.sandbox.manager.exec_command(cmd, timeout=600)

        # Read JSON output
        _, json_output = await self.sandbox.manager.exec_command(["cat", "/tmp/nikto_out.json"], timeout=10)

        vulns = parse_nikto_json(json_output)

        raw = f"Nikto scan complete — {len(vulns)} findings\n"
        for v in vulns[:20]:
            raw += f"  [{v.severity.value.upper()}] {v.title[:100]}\n"

        return ToolResult(
            tool_name=self.name,
            success=True,
            data={"finding_count": len(vulns)},
            raw_output=raw,
            vulnerabilities=vulns,
        )
