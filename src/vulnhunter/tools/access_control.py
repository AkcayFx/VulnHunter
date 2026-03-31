"""Broken access control tester — finds authorization bypass vulnerabilities.

Broken access control is OWASP #1 and covers accessing admin routes
without auth, method override attacks, and path traversal to restricted endpoints.
"""
from __future__ import annotations

import asyncio
from typing import Any
from urllib.parse import urljoin

import aiohttp

from vulnhunter.models import Severity, ToolResult, Vulnerability
from vulnhunter.tools.base import BaseTool

ADMIN_PATHS = [
    "/admin", "/admin/", "/dashboard", "/panel",
    "/api/admin", "/api/v1/admin", "/api/internal",
    "/manage", "/management", "/settings",
    "/admin/users", "/api/users", "/api/v1/users",
    "/admin/config", "/api/config", "/internal",
    "/api/admin/users", "/api/admin/settings",
    "/graphql",
    "/actuator", "/actuator/env", "/actuator/health",
    "/_debug", "/debug", "/trace", "/console",
    "/swagger-ui.html", "/api-docs", "/swagger.json",
]

METHOD_OVERRIDES = [
    ("X-HTTP-Method-Override", "GET"),
    ("X-HTTP-Method", "GET"),
    ("X-Method-Override", "GET"),
    ("_method", "GET"),  # Used as query param
]

PATH_TRAVERSALS = [
    ("/..;/admin", "Semicolon path traversal"),
    ("/%2e%2e/admin", "URL-encoded traversal"),
    ("/./admin", "Dot segment"),
    ("/admin%00", "Null byte"),
    ("/ADMIN", "Case variation"),
    ("/Admin", "Case variation"),
    ("//admin", "Double slash"),
]


class AccessControlTool(BaseTool):
    """Test for broken access control and authorization bypass."""

    @property
    def name(self) -> str:
        return "access_control_test"

    @property
    def description(self) -> str:
        return (
            "Test for broken access control vulnerabilities: unauthenticated access to "
            "admin endpoints, HTTP method override bypass, path traversal to restricted "
            "routes, and 403 bypass techniques. OWASP #1 vulnerability class."
        )

    @property
    def parameters(self) -> dict[str, Any]:
        return {
            "type": "object",
            "properties": {
                "url": {
                    "type": "string",
                    "description": "Base URL to test (e.g., https://example.com)",
                },
                "endpoints": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "Known admin/API endpoints from recon to test directly",
                    "default": [],
                },
                "auth_header": {
                    "type": "string",
                    "description": "Low-privilege auth token for privilege escalation testing",
                    "default": "",
                },
            },
            "required": ["url"],
        }

    async def _execute(self, **kwargs: Any) -> ToolResult:
        base_url = kwargs["url"].rstrip("/")
        extra_endpoints = kwargs.get("endpoints", [])
        auth_header = kwargs.get("auth_header", "")

        if not base_url.startswith(("http://", "https://")):
            base_url = f"https://{base_url}"

        vulns: list[Vulnerability] = []
        findings: list[dict[str, Any]] = []

        # 1. Test unauthenticated access to admin paths
        unauth_findings = await self._test_unauth_access(base_url, extra_endpoints)
        for f in unauth_findings:
            findings.append(f)
            vulns.append(Vulnerability(
                title=f"Unauthenticated access: {f['path']}",
                severity=Severity.HIGH if f["status"] == 200 else Severity.MEDIUM,
                tool=self.name,
                description=f"Admin/sensitive endpoint '{f['path']}' returned HTTP {f['status']} without authentication.",
                evidence=f"GET {f['url']} → HTTP {f['status']} ({f['size']} bytes)",
                cwe_id="CWE-284",
                remediation="Require authentication for all admin and sensitive endpoints.",
            ))

        # 2. Test 403 bypass techniques on protected paths
        bypass_findings = await self._test_403_bypass(base_url)
        for f in bypass_findings:
            findings.append(f)
            vulns.append(Vulnerability(
                title=f"403 Bypass: {f['technique']} on {f['path']}",
                severity=Severity.HIGH,
                tool=self.name,
                description=(
                    f"Access control on '{f['path']}' was bypassed using {f['technique']}. "
                    f"Original returned 403, bypass returned {f['status']}."
                ),
                evidence=f"Original: 403 → Bypass: {f['status']} via {f['technique']}\nURL: {f['url']}",
                cwe_id="CWE-284",
                remediation="Normalize URL paths before authorization checks. Block path traversal patterns.",
            ))

        # 3. Test HTTP method override
        method_findings = await self._test_method_override(base_url)
        for f in method_findings:
            findings.append(f)
            vulns.append(Vulnerability(
                title=f"HTTP Method Override: {f['header']}",
                severity=Severity.MEDIUM,
                tool=self.name,
                description=f"Server accepts HTTP method override via {f['header']} header.",
                evidence=f"POST with {f['header']}: GET → treated as GET (status {f['status']})",
                cwe_id="CWE-650",
                remediation="Disable HTTP method override headers in production.",
            ))

        raw = f"Access control tests on {base_url}\n"
        raw += f"Tested: {len(ADMIN_PATHS)} admin paths, {len(PATH_TRAVERSALS)} bypass techniques\n"
        if findings:
            raw += f"FINDINGS: {len(findings)}\n"
            for f in findings:
                raw += f"  [{f.get('technique', f.get('path', 'method'))}] HTTP {f['status']} — {f['url']}\n"
        else:
            raw += "No access control bypasses found.\n"

        return ToolResult(
            tool_name=self.name,
            success=True,
            data={"findings_count": len(findings)},
            raw_output=raw,
            vulnerabilities=vulns,
        )

    async def _test_unauth_access(self, base_url: str, extra_endpoints: list[str]) -> list[dict]:
        """Test admin paths for unauthenticated access."""
        findings: list[dict] = []
        sem = asyncio.Semaphore(10)

        paths = list(ADMIN_PATHS)
        for ep in extra_endpoints[:20]:
            if ep.startswith("/"):
                paths.append(ep)
            elif ep.startswith("http"):
                paths.append(ep)

        async def check(path: str) -> dict | None:
            async with sem:
                url = path if path.startswith("http") else f"{base_url}{path}"
                try:
                    async with aiohttp.ClientSession(
                        timeout=aiohttp.ClientTimeout(total=8),
                        headers={"User-Agent": "Mozilla/5.0 (compatible; VulnHunter/2.0)"},
                    ) as session:
                        async with session.get(url, ssl=False, allow_redirects=False) as resp:
                            size = resp.content_length or 0
                            if resp.status in (200, 301, 302):
                                body = await resp.text(errors="replace")
                                if resp.status == 200 and len(body) > 100:
                                    return {"path": path, "url": url, "status": resp.status, "size": len(body)}
                except Exception:
                    pass
                return None

        results = await asyncio.gather(*[check(p) for p in paths], return_exceptions=True)
        for r in results:
            if isinstance(r, dict):
                findings.append(r)

        return findings

    async def _test_403_bypass(self, base_url: str) -> list[dict]:
        """Find 403 pages and try bypass techniques."""
        findings: list[dict] = []

        # First find which paths return 403
        forbidden_paths: list[str] = []
        async with aiohttp.ClientSession(
            timeout=aiohttp.ClientTimeout(total=8),
            headers={"User-Agent": "Mozilla/5.0 (compatible; VulnHunter/2.0)"},
        ) as session:
            for path in ADMIN_PATHS[:15]:
                try:
                    url = f"{base_url}{path}"
                    async with session.get(url, ssl=False, allow_redirects=False) as resp:
                        if resp.status == 403:
                            forbidden_paths.append(path)
                except Exception:
                    pass

        # Try bypass techniques on 403 paths
        for path in forbidden_paths[:5]:
            for traversal, technique in PATH_TRAVERSALS:
                bypass_url = f"{base_url}{traversal}"
                try:
                    async with aiohttp.ClientSession(
                        timeout=aiohttp.ClientTimeout(total=8),
                        headers={"User-Agent": "Mozilla/5.0 (compatible; VulnHunter/2.0)"},
                    ) as session:
                        async with session.get(bypass_url, ssl=False, allow_redirects=False) as resp:
                            if resp.status == 200:
                                findings.append({
                                    "path": path,
                                    "url": bypass_url,
                                    "status": resp.status,
                                    "technique": technique,
                                })
                                break
                except Exception:
                    pass

        return findings

    async def _test_method_override(self, base_url: str) -> list[dict]:
        """Test HTTP method override headers."""
        findings: list[dict] = []
        test_url = f"{base_url}/api/admin"

        for header_name, override_method in METHOD_OVERRIDES:
            if header_name == "_method":
                continue  # Query param, different test
            try:
                async with aiohttp.ClientSession(
                    timeout=aiohttp.ClientTimeout(total=8),
                    headers={
                        "User-Agent": "Mozilla/5.0 (compatible; VulnHunter/2.0)",
                        header_name: override_method,
                    },
                ) as session:
                    async with session.post(test_url, ssl=False, allow_redirects=False) as resp:
                        if resp.status == 200:
                            findings.append({
                                "header": header_name,
                                "url": test_url,
                                "status": resp.status,
                            })
            except Exception:
                pass

        return findings
