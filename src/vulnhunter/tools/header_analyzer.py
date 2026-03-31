"""HTTP security header analyzer — checks for missing security headers."""
from __future__ import annotations

from typing import Any

import aiohttp

from vulnhunter.models import ToolResult, Vulnerability, Severity
from vulnhunter.tools.base import BaseTool

SECURITY_HEADERS = {
    "Strict-Transport-Security": {
        "severity": Severity.HIGH,
        "description": "Missing HSTS header allows downgrade attacks and cookie hijacking",
        "cwe": "CWE-319",
        "remediation": "Add 'Strict-Transport-Security: max-age=31536000; includeSubDomains' header",
    },
    "Content-Security-Policy": {
        "severity": Severity.MEDIUM,
        "description": "Missing CSP allows XSS and data injection attacks",
        "cwe": "CWE-79",
        "remediation": "Implement Content-Security-Policy header with strict directives",
    },
    "X-Frame-Options": {
        "severity": Severity.MEDIUM,
        "description": "Missing X-Frame-Options allows clickjacking attacks",
        "cwe": "CWE-1021",
        "remediation": "Add 'X-Frame-Options: DENY' or 'SAMEORIGIN' header",
    },
    "X-Content-Type-Options": {
        "severity": Severity.LOW,
        "description": "Missing X-Content-Type-Options allows MIME-type sniffing",
        "cwe": "CWE-16",
        "remediation": "Add 'X-Content-Type-Options: nosniff' header",
    },
    "X-XSS-Protection": {
        "severity": Severity.LOW,
        "description": "Missing X-XSS-Protection header (legacy but still useful)",
        "cwe": "CWE-79",
        "remediation": "Add 'X-XSS-Protection: 1; mode=block' header",
    },
    "Referrer-Policy": {
        "severity": Severity.LOW,
        "description": "Missing Referrer-Policy can leak sensitive URLs to third parties",
        "cwe": "CWE-200",
        "remediation": "Add 'Referrer-Policy: strict-origin-when-cross-origin' header",
    },
    "Permissions-Policy": {
        "severity": Severity.LOW,
        "description": "Missing Permissions-Policy allows unrestricted browser feature access",
        "cwe": "CWE-16",
        "remediation": "Add Permissions-Policy header to restrict browser features",
    },
}

INFO_HEADERS = ["Server", "X-Powered-By", "X-AspNet-Version", "X-AspNetMvc-Version"]


class HeaderAnalyzerTool(BaseTool):
    @property
    def name(self) -> str:
        return "header_analyzer"

    @property
    def description(self) -> str:
        return (
            "Analyzes HTTP response headers for security misconfigurations. "
            "Checks for missing security headers and information disclosure."
        )

    @property
    def parameters(self) -> dict[str, Any]:
        return {
            "type": "object",
            "properties": {
                "url": {
                    "type": "string",
                    "description": "Target URL to analyze (e.g., https://example.com)",
                },
            },
            "required": ["url"],
        }

    async def _execute(self, **kwargs: Any) -> ToolResult:
        url = kwargs["url"]
        if not url.startswith(("http://", "https://")):
            url = f"https://{url}"

        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(url, timeout=aiohttp.ClientTimeout(total=15),
                                       ssl=False, allow_redirects=True) as resp:
                    headers = dict(resp.headers)
                    status = resp.status
        except Exception as e:
            return ToolResult(
                tool_name=self.name, success=False,
                error=f"Failed to connect to {url}: {e}",
            )

        # Check missing security headers
        vulns: list[Vulnerability] = []
        missing: list[str] = []
        present: list[str] = []

        for header_name, info in SECURITY_HEADERS.items():
            if header_name.lower() not in {k.lower() for k in headers}:
                missing.append(header_name)
                vulns.append(Vulnerability(
                    title=f"Missing {header_name} header",
                    severity=info["severity"],
                    tool=self.name,
                    description=info["description"],
                    evidence=f"Header '{header_name}' not found in response from {url}",
                    cwe_id=info["cwe"],
                    remediation=info["remediation"],
                ))
            else:
                present.append(header_name)

        # Check information disclosure
        disclosed: dict[str, str] = {}
        for h in INFO_HEADERS:
            val = headers.get(h, "")
            if val:
                disclosed[h] = val
                vulns.append(Vulnerability(
                    title=f"Information disclosure via {h} header",
                    severity=Severity.LOW,
                    tool=self.name,
                    description=f"Server reveals technology info: {h}: {val}",
                    evidence=f"{h}: {val}",
                    cwe_id="CWE-200",
                    remediation=f"Remove or suppress the '{h}' header",
                ))

        lines = [f"Header analysis for {url} (HTTP {status})"]
        lines.append(f"  Security headers present: {len(present)}/{len(SECURITY_HEADERS)}")
        lines.append(f"  Missing headers: {', '.join(missing) if missing else 'None'}")
        if disclosed:
            lines.append(f"  Info disclosed: {disclosed}")

        return ToolResult(
            tool_name=self.name,
            success=True,
            data={
                "url": url,
                "status_code": status,
                "headers": headers,
                "missing_security_headers": missing,
                "present_security_headers": present,
                "info_disclosure": disclosed,
            },
            raw_output="\n".join(lines),
            vulnerabilities=vulns,
        )
