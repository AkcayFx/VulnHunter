"""Web vulnerability scanner — tests for common web vulnerabilities."""
from __future__ import annotations

import re
from typing import Any
from urllib.parse import urlencode, urlparse, parse_qs, urljoin

import aiohttp

from vulnhunter.models import ToolResult, Vulnerability, Severity
from vulnhunter.tools.base import BaseTool

SQLI_PAYLOADS = ["'", "' OR '1'='1", "1; DROP TABLE users--", "' UNION SELECT NULL--"]
XSS_PAYLOADS = ['<script>alert(1)</script>', '"><img src=x onerror=alert(1)>', "'-alert(1)-'"]
OPEN_REDIRECT_PAYLOADS = ["//evil.com", "https://evil.com", "/\\evil.com"]


class WebVulnScannerTool(BaseTool):
    @property
    def name(self) -> str:
        return "web_vuln_scanner"

    @property
    def description(self) -> str:
        return (
            "Tests a URL for common web vulnerabilities including SQL injection, "
            "cross-site scripting (XSS), and open redirects. Sends safe payloads "
            "and analyzes responses for vulnerability indicators."
        )

    @property
    def parameters(self) -> dict[str, Any]:
        return {
            "type": "object",
            "properties": {
                "url": {
                    "type": "string",
                    "description": "Target URL to test (e.g., https://example.com/search?q=test)",
                },
                "test_sqli": {
                    "type": "boolean",
                    "description": "Test for SQL injection",
                    "default": True,
                },
                "test_xss": {
                    "type": "boolean",
                    "description": "Test for cross-site scripting",
                    "default": True,
                },
                "test_redirect": {
                    "type": "boolean",
                    "description": "Test for open redirects",
                    "default": True,
                },
            },
            "required": ["url"],
        }

    async def _execute(self, **kwargs: Any) -> ToolResult:
        url = kwargs["url"]
        test_sqli = kwargs.get("test_sqli", True)
        test_xss = kwargs.get("test_xss", True)
        test_redirect = kwargs.get("test_redirect", True)

        if not url.startswith(("http://", "https://")):
            url = f"https://{url}"

        vulns: list[Vulnerability] = []
        findings: list[str] = []

        try:
            async with aiohttp.ClientSession(
                headers={"User-Agent": "Mozilla/5.0 (compatible; VulnHunter/1.0)"},
                cookie_jar=aiohttp.CookieJar(unsafe=True),
            ) as session:
                # Get baseline response
                try:
                    async with session.get(url, timeout=aiohttp.ClientTimeout(total=10),
                                           ssl=False) as resp:
                        baseline_status = resp.status
                        baseline_body = await resp.text()
                except Exception:
                    baseline_status = 0
                    baseline_body = ""

                parsed = urlparse(url)
                params = parse_qs(parsed.query)

                # If URL has parameters, test each one
                if params and test_sqli:
                    for param_name in params:
                        for payload in SQLI_PAYLOADS:
                            test_params = {k: v[0] for k, v in params.items()}
                            test_params[param_name] = payload
                            test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{urlencode(test_params)}"
                            try:
                                async with session.get(test_url, timeout=aiohttp.ClientTimeout(total=8),
                                                       ssl=False) as resp:
                                    body = await resp.text()
                                    if self._detect_sqli(body, resp.status, baseline_status):
                                        vulns.append(Vulnerability(
                                            title=f"Potential SQL Injection in '{param_name}' parameter",
                                            severity=Severity.CRITICAL,
                                            tool=self.name,
                                            description=f"SQL injection indicators detected when injecting payload into '{param_name}'",
                                            evidence=f"Payload: {payload}\nURL: {test_url}\nResponse contained SQL error indicators",
                                            cwe_id="CWE-89",
                                            remediation="Use parameterized queries/prepared statements. Never concatenate user input into SQL.",
                                        ))
                                        findings.append(f"SQLi: {param_name} ({payload})")
                                        break
                            except Exception:
                                pass

                if params and test_xss:
                    for param_name in params:
                        for payload in XSS_PAYLOADS:
                            test_params = {k: v[0] for k, v in params.items()}
                            test_params[param_name] = payload
                            test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{urlencode(test_params)}"
                            try:
                                async with session.get(test_url, timeout=aiohttp.ClientTimeout(total=8),
                                                       ssl=False) as resp:
                                    body = await resp.text()
                                    if payload in body:
                                        vulns.append(Vulnerability(
                                            title=f"Reflected XSS in '{param_name}' parameter",
                                            severity=Severity.HIGH,
                                            tool=self.name,
                                            description=f"Input is reflected without sanitization in '{param_name}'",
                                            evidence=f"Payload '{payload}' reflected in response body",
                                            cwe_id="CWE-79",
                                            remediation="Sanitize and encode all user input before reflecting in HTML.",
                                        ))
                                        findings.append(f"XSS: {param_name}")
                                        break
                            except Exception:
                                pass

                # Test common redirect parameters
                if test_redirect:
                    redirect_params = ["url", "redirect", "next", "return", "returnTo", "goto", "target", "rurl"]
                    for rp in redirect_params:
                        for payload in OPEN_REDIRECT_PAYLOADS:
                            test_url = f"{url}{'&' if '?' in url else '?'}{rp}={payload}"
                            try:
                                async with session.get(test_url, timeout=aiohttp.ClientTimeout(total=8),
                                                       ssl=False, allow_redirects=False) as resp:
                                    location = resp.headers.get("Location", "")
                                    if location and ("evil.com" in location):
                                        vulns.append(Vulnerability(
                                            title=f"Open Redirect via '{rp}' parameter",
                                            severity=Severity.MEDIUM,
                                            tool=self.name,
                                            description=f"Server redirects to attacker-controlled URL via '{rp}' parameter",
                                            evidence=f"Redirect to: {location}",
                                            cwe_id="CWE-601",
                                            remediation="Validate redirect URLs against a whitelist of allowed domains.",
                                        ))
                                        findings.append(f"Open Redirect: {rp}")
                                        break
                            except Exception:
                                pass

        except Exception as e:
            return ToolResult(
                tool_name=self.name, success=False,
                error=f"Web vulnerability scan failed: {e}",
            )

        lines = [f"Web vulnerability scan of {url}"]
        if vulns:
            lines.append(f"  Potential vulnerabilities found: {len(vulns)}")
            for v in vulns:
                lines.append(f"  [{v.severity.value.upper()}] {v.title}")
        else:
            lines.append("  No vulnerabilities detected with automated payloads")
            lines.append("  Note: Manual testing may reveal additional issues")

        return ToolResult(
            tool_name=self.name, success=True,
            data={"url": url, "findings": findings, "total_vulns": len(vulns)},
            raw_output="\n".join(lines),
            vulnerabilities=vulns,
        )

    @staticmethod
    def _detect_sqli(body: str, status: int, baseline_status: int) -> bool:
        """Detect SQL injection indicators in response."""
        sql_errors = [
            "sql syntax", "mysql", "sqlite", "postgresql", "oracle",
            "syntax error", "unclosed quotation", "unterminated string",
            "ODBC", "OLE DB", "Microsoft SQL", "Warning: mysql_",
            "Warning: pg_", "Warning: sqlite_", "You have an error",
            "supplied argument is not a valid", "Division by zero",
        ]
        body_lower = body.lower()
        return any(err.lower() in body_lower for err in sql_errors)
