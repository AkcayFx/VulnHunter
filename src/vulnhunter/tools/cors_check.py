"""CORS misconfiguration tester — detects insecure cross-origin resource sharing."""
from __future__ import annotations

from typing import Any
from urllib.parse import urlparse

import aiohttp

from vulnhunter.models import Severity, ToolResult, Vulnerability
from vulnhunter.tools.base import BaseTool


class CORSCheckTool(BaseTool):
    """Test for CORS misconfiguration vulnerabilities."""

    @property
    def name(self) -> str:
        return "cors_check"

    @property
    def description(self) -> str:
        return (
            "Test a URL for CORS (Cross-Origin Resource Sharing) misconfiguration. "
            "Checks if the target reflects arbitrary Origin headers, allows null origin, "
            "uses wildcard with credentials, or reflects subdomain patterns. "
            "CORS misconfiguration is one of the most common and highest-paid bounty findings."
        )

    @property
    def parameters(self) -> dict[str, Any]:
        return {
            "type": "object",
            "properties": {
                "url": {
                    "type": "string",
                    "description": "Target URL to test (e.g., https://api.example.com/user)",
                },
                "urls": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "Optional list of URLs to test (batch mode)",
                    "default": [],
                },
            },
            "required": ["url"],
        }

    async def _execute(self, **kwargs: Any) -> ToolResult:
        url = kwargs["url"]
        urls = kwargs.get("urls", [])
        if url not in urls:
            urls = [url] + urls

        vulns: list[Vulnerability] = []
        findings: list[dict[str, Any]] = []

        for test_url in urls[:20]:
            result = await self._test_cors(test_url)
            if result:
                findings.append(result)
                vulns.append(Vulnerability(
                    title=f"CORS Misconfiguration: {result['type']}",
                    severity=result["severity"],
                    tool=self.name,
                    description=result["description"],
                    evidence=f"URL: {test_url}, ACAO: {result['acao']}, ACAC: {result['acac']}",
                    cwe_id="CWE-942",
                    remediation="Configure CORS to only allow trusted origins. Never reflect arbitrary Origin headers.",
                ))

        raw = f"CORS tests on {len(urls)} URL(s):\n"
        if findings:
            for f in findings:
                raw += f"  [{f['severity'].value.upper()}] {f['type']} — {f['url']}\n"
        else:
            raw += "  No CORS misconfigurations found.\n"

        return ToolResult(
            tool_name=self.name,
            success=True,
            data={"findings": [{"type": f["type"], "url": f["url"]} for f in findings]},
            raw_output=raw,
            vulnerabilities=vulns,
        )

    async def _test_cors(self, url: str) -> dict[str, Any] | None:
        """Run CORS tests against a single URL."""
        parsed = urlparse(url)
        base_domain = parsed.hostname or ""

        tests = [
            ("Arbitrary Origin Reflection", f"https://evil.com", Severity.CRITICAL),
            ("Null Origin Allowed", None, Severity.HIGH),
            ("Subdomain Reflection", f"https://evil.{base_domain}", Severity.MEDIUM),
            ("HTTP Origin Reflection", url.replace("https://", "http://"), Severity.MEDIUM),
        ]

        for test_name, origin_val, severity in tests:
            headers: dict[str, str] = {}
            if origin_val is None:
                headers["Origin"] = "null"
            else:
                headers["Origin"] = origin_val

            try:
                async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=10)) as session:
                    async with session.get(url, headers=headers, ssl=False) as resp:
                        acao = resp.headers.get("Access-Control-Allow-Origin", "")
                        acac = resp.headers.get("Access-Control-Allow-Credentials", "")

                        vulnerable = False
                        if origin_val is None and acao == "null":
                            vulnerable = True
                        elif origin_val and acao == origin_val:
                            vulnerable = True
                        elif acao == "*" and acac.lower() == "true":
                            vulnerable = True
                            test_name = "Wildcard with Credentials"
                            severity = Severity.HIGH

                        if vulnerable:
                            return {
                                "type": test_name,
                                "url": url,
                                "severity": severity,
                                "acao": acao,
                                "acac": acac,
                                "description": (
                                    f"The server at {url} reflects the Origin header '{origin_val or 'null'}' "
                                    f"in Access-Control-Allow-Origin ({acao}). "
                                    f"Credentials allowed: {acac}. "
                                    f"This allows an attacker to read authenticated responses cross-origin."
                                ),
                            }
            except Exception:
                continue

        return None
