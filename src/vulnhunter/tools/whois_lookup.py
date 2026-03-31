"""WHOIS lookup tool for domain registration information."""
from __future__ import annotations

from typing import Any

from vulnhunter.models import ToolResult
from vulnhunter.tools.base import BaseTool

try:
    import whois
    HAS_WHOIS = True
except ImportError:
    HAS_WHOIS = False


class WhoisLookupTool(BaseTool):
    @property
    def name(self) -> str:
        return "whois_lookup"

    @property
    def description(self) -> str:
        return (
            "Performs WHOIS lookup to get domain registration details including "
            "registrar, creation date, expiry date, and nameservers."
        )

    @property
    def parameters(self) -> dict[str, Any]:
        return {
            "type": "object",
            "properties": {
                "domain": {
                    "type": "string",
                    "description": "Target domain for WHOIS lookup (e.g., example.com)",
                },
            },
            "required": ["domain"],
        }

    async def _execute(self, **kwargs: Any) -> ToolResult:
        domain = kwargs["domain"]

        if not HAS_WHOIS:
            return ToolResult(
                tool_name=self.name, success=False,
                error="python-whois library not installed",
            )

        try:
            w = whois.whois(domain)
        except Exception as e:
            return ToolResult(
                tool_name=self.name, success=False,
                error=f"WHOIS lookup failed for {domain}: {e}",
            )

        def safe_str(val: Any) -> str:
            if isinstance(val, list):
                return ", ".join(str(v) for v in val)
            return str(val) if val else "N/A"

        data = {
            "domain": domain,
            "registrar": safe_str(w.registrar),
            "creation_date": safe_str(w.creation_date),
            "expiration_date": safe_str(w.expiration_date),
            "updated_date": safe_str(w.updated_date),
            "name_servers": safe_str(w.name_servers),
            "status": safe_str(w.status),
            "org": safe_str(w.org),
            "country": safe_str(w.country),
        }

        lines = [
            f"WHOIS for {domain}",
            f"  Registrar: {data['registrar']}",
            f"  Created: {data['creation_date']}",
            f"  Expires: {data['expiration_date']}",
            f"  Nameservers: {data['name_servers']}",
            f"  Organization: {data['org']}",
            f"  Country: {data['country']}",
        ]

        return ToolResult(
            tool_name=self.name, success=True,
            data=data, raw_output="\n".join(lines),
        )
