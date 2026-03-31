"""httpx probe wrapper — live host detection inside Docker sandbox."""
from __future__ import annotations

from typing import Any

from vulnhunter.models import ToolResult
from vulnhunter.tools.base import BaseTool
from vulnhunter.tools.pro.parsers import parse_httpx_jsonl


class HttpxProbeTool(BaseTool):
    """HTTP probing tool using ProjectDiscovery httpx (requires Docker sandbox)."""

    @property
    def name(self) -> str:
        return "httpx_probe"

    @property
    def description(self) -> str:
        return (
            "Run httpx inside Docker sandbox to probe a list of hosts/subdomains for live HTTP services. "
            "Returns status codes, titles, technologies, and web server info. "
            "Essential for filtering live targets from subdomain enumeration results."
        )

    @property
    def parameters(self) -> dict[str, Any]:
        return {
            "type": "object",
            "properties": {
                "hosts": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "List of hostnames/URLs to probe",
                },
                "ports": {
                    "type": "string",
                    "description": "Ports to probe (e.g., '80,443,8080,8443')",
                    "default": "80,443,8080,8443",
                },
            },
            "required": ["hosts"],
        }

    async def _execute(self, **kwargs: Any) -> ToolResult:
        if self.sandbox is None:
            raise RuntimeError("httpx_probe requires Docker sandbox mode")

        hosts = kwargs["hosts"]
        ports = kwargs.get("ports", "80,443,8080,8443")

        # Write hosts to a temp file inside container
        host_list = "\n".join(hosts)
        await self.sandbox.manager.exec_command(
            ["bash", "-c", f"echo '{host_list}' > /tmp/hosts.txt"], timeout=10,
        )

        cmd = ["httpx", "-l", "/tmp/hosts.txt", "-json", "-silent",
               "-ports", ports, "-title", "-tech-detect", "-status-code", "-server"]

        exit_code, output = await self.sandbox.manager.exec_command(cmd, timeout=300)

        live_hosts = parse_httpx_jsonl(output)

        raw = f"httpx found {len(live_hosts)} live hosts:\n"
        for h in live_hosts:
            raw += f"  [{h['status_code']}] {h['url']} — {h['title']} ({h['webserver']})\n"

        return ToolResult(
            tool_name=self.name,
            success=True,
            data={"live_hosts": live_hosts, "total": len(live_hosts)},
            raw_output=raw,
        )
