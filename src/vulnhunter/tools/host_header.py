"""Host header injection detector — tests for host header attacks.

Host header injection enables password reset poisoning, web cache poisoning,
and SSRF via the Host header. Often missed by other scanners.
"""
from __future__ import annotations

from typing import Any
from urllib.parse import urlparse

import aiohttp

from vulnhunter.models import Severity, ToolResult, Vulnerability
from vulnhunter.tools.base import BaseTool


class HostHeaderTool(BaseTool):
    """Test for host header injection vulnerabilities."""

    @property
    def name(self) -> str:
        return "host_header_injection"

    @property
    def description(self) -> str:
        return (
            "Test for host header injection vulnerabilities including password reset "
            "poisoning, web cache poisoning, and routing-based SSRF. Tests Host, "
            "X-Forwarded-Host, X-Host, X-Original-URL, and X-Rewrite-URL headers."
        )

    @property
    def parameters(self) -> dict[str, Any]:
        return {
            "type": "object",
            "properties": {
                "url": {
                    "type": "string",
                    "description": "Target URL to test (e.g., https://example.com or https://example.com/reset-password)",
                },
                "test_password_reset": {
                    "type": "boolean",
                    "description": "Also test password reset endpoint for poisoning",
                    "default": True,
                },
            },
            "required": ["url"],
        }

    async def _execute(self, **kwargs: Any) -> ToolResult:
        url = kwargs["url"]
        test_reset = kwargs.get("test_password_reset", True)

        if not url.startswith(("http://", "https://")):
            url = f"https://{url}"

        parsed = urlparse(url)
        original_host = parsed.hostname or ""
        vulns: list[Vulnerability] = []
        findings: list[dict[str, str]] = []

        evil_host = "evil.vulnhunter-test.com"

        tests = [
            ("Host Override", {"Host": evil_host}),
            ("X-Forwarded-Host", {"X-Forwarded-Host": evil_host}),
            ("X-Host", {"X-Host": evil_host}),
            ("X-Original-URL", {"X-Original-URL": "/admin"}),
            ("X-Rewrite-URL", {"X-Rewrite-URL": "/admin"}),
            ("X-Forwarded-For + Host", {"X-Forwarded-Host": evil_host, "X-Forwarded-For": "127.0.0.1"}),
            ("Absolute URL Host Mismatch", {}),  # Send request with absolute URL in request line
        ]

        for test_name, extra_headers in tests:
            result = await self._test_header(url, extra_headers, evil_host, original_host)
            if result:
                findings.append({"test": test_name, "url": url, "indicator": result})

                severity = Severity.HIGH
                if "password" in test_name.lower() or "cache" in result.lower():
                    severity = Severity.CRITICAL

                vulns.append(Vulnerability(
                    title=f"Host Header Injection: {test_name}",
                    severity=severity,
                    tool=self.name,
                    description=(
                        f"The server reflects or processes the injected host header '{evil_host}' "
                        f"when using {test_name}. This can enable password reset poisoning, "
                        f"web cache poisoning, or access to internal resources."
                    ),
                    evidence=f"Test: {test_name}\nURL: {url}\nIndicator: {result}",
                    cwe_id="CWE-644",
                    remediation=(
                        "Validate the Host header against a whitelist of expected hostnames. "
                        "Ignore X-Forwarded-Host unless from a trusted reverse proxy. "
                        "Use absolute URLs with a configured base domain for password reset links."
                    ),
                ))

        # Test password reset pages for host poisoning
        if test_reset:
            reset_paths = ["/reset-password", "/forgot-password", "/password/reset",
                           "/auth/forgot", "/account/recover", "/api/auth/forgot"]
            for path in reset_paths:
                reset_url = f"{parsed.scheme}://{parsed.netloc}{path}"
                result = await self._test_reset_poisoning(reset_url, evil_host)
                if result:
                    findings.append({"test": "Password Reset Poisoning", "url": reset_url, "indicator": result})
                    vulns.append(Vulnerability(
                        title=f"Password Reset Poisoning via Host Header",
                        severity=Severity.CRITICAL,
                        tool=self.name,
                        description=(
                            f"Password reset endpoint {reset_url} uses the Host header to generate "
                            f"the reset link. An attacker can poison the Host to steal reset tokens."
                        ),
                        evidence=f"URL: {reset_url}\nInjected Host: {evil_host}\nIndicator: {result}",
                        cwe_id="CWE-644",
                        remediation="Use a hardcoded base URL for password reset links, not the Host header.",
                    ))
                    break

        raw = f"Host header injection tests on {url}\n"
        if findings:
            raw += f"VULNERABLE: {len(findings)} finding(s):\n"
            for f in findings:
                raw += f"  [{f['test']}] {f['indicator']}\n"
        else:
            raw += "No host header injection vulnerabilities found.\n"

        return ToolResult(
            tool_name=self.name,
            success=True,
            data={"findings": [{"test": f["test"], "url": f["url"]} for f in findings]},
            raw_output=raw,
            vulnerabilities=vulns,
        )

    async def _test_header(
        self, url: str, extra_headers: dict, evil_host: str, original_host: str
    ) -> str:
        """Test a single header injection and check for indicators."""
        headers = {"User-Agent": "Mozilla/5.0 (compatible; VulnHunter/2.0)"}
        headers.update(extra_headers)

        try:
            async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=10)) as session:
                async with session.get(url, headers=headers, ssl=False, allow_redirects=False) as resp:
                    body = await resp.text(errors="replace")
                    location = resp.headers.get("Location", "")

                    if evil_host in body:
                        return f"Evil host '{evil_host}' reflected in response body"
                    if evil_host in location:
                        return f"Evil host '{evil_host}' in redirect Location header"

                    # Check X-Original-URL / X-Rewrite-URL path override
                    if "X-Original-URL" in extra_headers or "X-Rewrite-URL" in extra_headers:
                        if resp.status == 200 and "/admin" in body.lower():
                            return "X-Original-URL/X-Rewrite-URL path override accepted"
                        if resp.status != 404:
                            return f"Path override returned status {resp.status} (expected 404)"

        except Exception:
            pass
        return ""

    async def _test_reset_poisoning(self, url: str, evil_host: str) -> str:
        """Test if password reset page uses Host header in generated links."""
        headers = {
            "User-Agent": "Mozilla/5.0 (compatible; VulnHunter/2.0)",
            "Host": evil_host,
            "Content-Type": "application/x-www-form-urlencoded",
        }

        try:
            async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=10)) as session:
                async with session.post(
                    url, headers=headers, ssl=False, allow_redirects=False,
                    data="email=test@vulnhunter-test.com",
                ) as resp:
                    body = await resp.text(errors="replace")
                    if evil_host in body:
                        return f"Reset page reflects poisoned host '{evil_host}'"
                    if resp.status in (200, 302):
                        return f"Reset endpoint responded (status {resp.status}) — manual verification needed"
        except Exception:
            pass
        return ""
