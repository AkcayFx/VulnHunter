"""Shodan search tool — queries Shodan's public API for host intelligence."""
from __future__ import annotations

import os
from typing import Any

import aiohttp

from vulnhunter.models import ToolResult, Vulnerability, Severity
from vulnhunter.tools.base import BaseTool


class ShodanSearchTool(BaseTool):
    @property
    def name(self) -> str:
        return "shodan_search"

    @property
    def description(self) -> str:
        return (
            "Query Shodan for information about a host IP — open ports, services, "
            "banners, OS, vulns. Requires SHODAN_API_KEY env var."
        )

    @property
    def parameters(self) -> dict[str, Any]:
        return {
            "type": "object",
            "properties": {
                "target": {
                    "type": "string",
                    "description": "IP address or hostname to look up on Shodan",
                },
            },
            "required": ["target"],
        }

    async def _execute(self, **kwargs: Any) -> ToolResult:
        target: str = kwargs["target"]
        api_key = os.environ.get("SHODAN_API_KEY", "")

        if not api_key:
            return ToolResult(
                tool_name=self.name,
                success=False,
                error="SHODAN_API_KEY not set — skipping Shodan lookup",
                raw_output="Shodan API key not configured.",
            )

        url = f"https://api.shodan.io/shodan/host/{target}?key={api_key}"

        async with aiohttp.ClientSession() as session:
            async with session.get(url, timeout=aiohttp.ClientTimeout(total=15)) as resp:
                if resp.status != 200:
                    body = await resp.text()
                    return ToolResult(
                        tool_name=self.name,
                        success=False,
                        error=f"Shodan API returned {resp.status}: {body[:300]}",
                    )
                data: dict[str, Any] = await resp.json()

        ports = data.get("ports", [])
        vulns = data.get("vulns", [])
        os_name = data.get("os", "Unknown")
        org = data.get("org", "Unknown")
        hostnames = data.get("hostnames", [])

        services: list[dict[str, Any]] = []
        for item in data.get("data", [])[:20]:
            services.append({
                "port": item.get("port"),
                "transport": item.get("transport", "tcp"),
                "product": item.get("product", ""),
                "version": item.get("version", ""),
                "banner": (item.get("data", "") or "")[:200],
            })

        result_data: dict[str, Any] = {
            "ip": target,
            "os": os_name,
            "org": org,
            "hostnames": hostnames,
            "ports": ports,
            "vulns": vulns,
            "services": services,
        }

        lines = [
            f"Shodan results for {target}",
            f"Organization: {org}",
            f"OS: {os_name}",
            f"Hostnames: {', '.join(hostnames) if hostnames else 'N/A'}",
            f"Open ports: {', '.join(map(str, ports))}",
        ]
        if vulns:
            lines.append(f"Known CVEs: {', '.join(vulns[:15])}")
        for svc in services[:10]:
            lines.append(
                f"  Port {svc['port']}/{svc['transport']}: "
                f"{svc['product']} {svc['version']}".strip()
            )

        found_vulns: list[Vulnerability] = []
        for cve_id in vulns[:20]:
            found_vulns.append(Vulnerability(
                title=f"Shodan CVE: {cve_id}",
                severity=Severity.HIGH,
                tool=self.name,
                description=f"Shodan reports {target} is affected by {cve_id}",
                cwe_id="",
                cvss_score=0.0,
                remediation=f"Investigate and patch {cve_id}",
            ))

        return ToolResult(
            tool_name=self.name,
            success=True,
            data=result_data,
            raw_output="\n".join(lines),
            vulnerabilities=found_vulns,
        )
