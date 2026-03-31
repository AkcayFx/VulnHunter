"""Subdomain enumeration tool — queries crt.sh certificate transparency logs."""
from __future__ import annotations

from typing import Any

import aiohttp

from vulnhunter.models import ToolResult
from vulnhunter.tools.base import BaseTool


class SubdomainEnumTool(BaseTool):
    @property
    def name(self) -> str:
        return "subdomain_enum"

    @property
    def description(self) -> str:
        return (
            "Discover subdomains of a domain using Certificate Transparency logs (crt.sh). "
            "Returns a deduplicated list of known subdomains."
        )

    @property
    def parameters(self) -> dict[str, Any]:
        return {
            "type": "object",
            "properties": {
                "domain": {
                    "type": "string",
                    "description": "Base domain to enumerate subdomains for (e.g. example.com)",
                },
            },
            "required": ["domain"],
        }

    async def _execute(self, **kwargs: Any) -> ToolResult:
        domain: str = kwargs["domain"]

        url = f"https://crt.sh/?q=%25.{domain}&output=json"

        async with aiohttp.ClientSession() as session:
            async with session.get(url, timeout=aiohttp.ClientTimeout(total=20)) as resp:
                if resp.status != 200:
                    return ToolResult(
                        tool_name=self.name,
                        success=False,
                        error=f"crt.sh returned HTTP {resp.status}",
                    )
                try:
                    data = await resp.json(content_type=None)
                except Exception:
                    text = await resp.text()
                    return ToolResult(
                        tool_name=self.name,
                        success=False,
                        error=f"Failed to parse crt.sh response: {text[:200]}",
                    )

        subdomains: set[str] = set()
        for entry in data:
            name_value = entry.get("name_value", "")
            for name in name_value.split("\n"):
                name = name.strip().lower()
                if name and "*" not in name:
                    subdomains.add(name)

        sorted_subs = sorted(subdomains)

        lines = [
            f"Subdomain enumeration for {domain}",
            f"Found {len(sorted_subs)} unique subdomains via crt.sh\n",
        ]
        for sub in sorted_subs[:100]:
            lines.append(f"  {sub}")
        if len(sorted_subs) > 100:
            lines.append(f"  ... and {len(sorted_subs) - 100} more")

        return ToolResult(
            tool_name=self.name,
            success=True,
            data={"domain": domain, "subdomains": sorted_subs[:200]},
            raw_output="\n".join(lines),
        )
