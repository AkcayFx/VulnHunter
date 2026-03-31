"""subfinder wrapper — subdomain enumeration inside Docker sandbox."""
from __future__ import annotations

from typing import Any

from vulnhunter.models import ToolResult
from vulnhunter.tools.base import BaseTool
from vulnhunter.tools.pro.parsers import parse_subfinder_jsonl


class SubfinderEnumTool(BaseTool):
    """Subdomain discovery tool using ProjectDiscovery subfinder (requires Docker sandbox)."""

    @property
    def name(self) -> str:
        return "subfinder_enum"

    @property
    def description(self) -> str:
        return (
            "Run subfinder inside Docker sandbox for passive subdomain enumeration. "
            "Uses multiple data sources (Shodan, VirusTotal, SecurityTrails, etc.) "
            "for comprehensive subdomain discovery. More thorough than crt.sh alone."
        )

    @property
    def parameters(self) -> dict[str, Any]:
        return {
            "type": "object",
            "properties": {
                "domain": {
                    "type": "string",
                    "description": "Target domain (e.g., example.com)",
                },
                "recursive": {
                    "type": "boolean",
                    "description": "Enable recursive subdomain enumeration",
                    "default": False,
                },
            },
            "required": ["domain"],
        }

    async def _execute(self, **kwargs: Any) -> ToolResult:
        if self.sandbox is None:
            raise RuntimeError("subfinder_enum requires Docker sandbox mode")

        domain = kwargs["domain"]
        recursive = kwargs.get("recursive", False)

        cmd = ["subfinder", "-d", domain, "-json", "-silent"]
        if recursive:
            cmd.append("-recursive")

        exit_code, output = await self.sandbox.manager.exec_command(cmd, timeout=300)

        subdomains = parse_subfinder_jsonl(output)

        raw = f"subfinder found {len(subdomains)} subdomains for {domain}:\n"
        for sd in subdomains[:50]:
            raw += f"  {sd}\n"
        if len(subdomains) > 50:
            raw += f"  ... and {len(subdomains) - 50} more\n"

        return ToolResult(
            tool_name=self.name,
            success=True,
            data={"subdomains": subdomains, "total": len(subdomains)},
            raw_output=raw,
        )
