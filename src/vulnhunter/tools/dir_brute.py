"""Directory bruteforce tool — discovers hidden paths on web servers."""
from __future__ import annotations

from typing import Any

import aiohttp
import asyncio

from vulnhunter.models import ToolResult, Vulnerability, Severity
from vulnhunter.tools.base import BaseTool

COMMON_PATHS = [
    "/admin", "/login", "/dashboard", "/api", "/api/v1", "/api/v2",
    "/wp-admin", "/wp-login.php", "/wp-content", "/wp-includes",
    "/.git", "/.git/HEAD", "/.env", "/.htaccess", "/backup",
    "/config", "/configuration", "/phpmyadmin", "/pma",
    "/server-status", "/server-info", "/info.php", "/phpinfo.php",
    "/robots.txt", "/sitemap.xml", "/.well-known",
    "/console", "/debug", "/trace", "/actuator", "/actuator/health",
    "/swagger", "/swagger-ui", "/api-docs", "/graphql",
    "/uploads", "/files", "/static", "/assets", "/media",
    "/.DS_Store", "/web.config", "/crossdomain.xml",
    "/cgi-bin", "/test", "/temp", "/tmp", "/logs", "/log",
    "/.svn", "/.hg", "/backup.zip", "/backup.tar.gz",
    "/database", "/db", "/sql", "/dump", "/export",
]

SENSITIVE_PATHS = {
    "/.git", "/.git/HEAD", "/.env", "/.htaccess", "/.svn", "/.hg",
    "/.DS_Store", "/web.config", "/backup.zip", "/backup.tar.gz",
    "/phpinfo.php", "/info.php", "/server-status", "/server-info",
    "/database", "/db", "/sql", "/dump", "/export",
    "/console", "/debug", "/trace", "/actuator",
}


class DirBruteforceTool(BaseTool):
    @property
    def name(self) -> str:
        return "dir_bruteforce"

    @property
    def description(self) -> str:
        return (
            "Discovers hidden directories and files on a web server by testing common paths. "
            "Identifies exposed sensitive files like .git, .env, backups, and admin panels."
        )

    @property
    def parameters(self) -> dict[str, Any]:
        return {
            "type": "object",
            "properties": {
                "url": {
                    "type": "string",
                    "description": "Base URL to scan (e.g., https://example.com)",
                },
                "max_requests": {
                    "type": "integer",
                    "description": "Maximum number of paths to test",
                    "default": 50,
                },
            },
            "required": ["url"],
        }

    async def _execute(self, **kwargs: Any) -> ToolResult:
        base_url = kwargs["url"].rstrip("/")
        max_requests = int(kwargs.get("max_requests", 50))

        if not base_url.startswith(("http://", "https://")):
            base_url = f"https://{base_url}"

        paths_to_test = COMMON_PATHS[:max_requests]
        found: list[dict[str, Any]] = []
        vulns: list[Vulnerability] = []
        sem = asyncio.Semaphore(20)

        async def check_path(session: aiohttp.ClientSession, path: str) -> dict[str, Any] | None:
            async with sem:
                url = f"{base_url}{path}"
                try:
                    async with session.get(url, timeout=aiohttp.ClientTimeout(total=8),
                                           ssl=False, allow_redirects=False) as resp:
                        if resp.status in (200, 201, 301, 302, 403):
                            return {
                                "path": path,
                                "status": resp.status,
                                "size": resp.content_length or 0,
                                "url": url,
                            }
                except Exception:
                    pass
                return None

        async with aiohttp.ClientSession(
            headers={"User-Agent": "Mozilla/5.0 (compatible; VulnHunter/1.0)"}
        ) as session:
            tasks = [check_path(session, p) for p in paths_to_test]
            results = await asyncio.gather(*tasks)

        for r in results:
            if r:
                found.append(r)
                if r["path"] in SENSITIVE_PATHS and r["status"] in (200, 201):
                    vulns.append(Vulnerability(
                        title=f"Sensitive file exposed: {r['path']}",
                        severity=Severity.HIGH if r["path"] in ("/.git", "/.env", "/.git/HEAD") else Severity.MEDIUM,
                        tool=self.name,
                        description=f"Sensitive path '{r['path']}' is publicly accessible (HTTP {r['status']})",
                        evidence=f"GET {r['url']} → HTTP {r['status']}",
                        cwe_id="CWE-538",
                        remediation=f"Block public access to '{r['path']}' via server configuration",
                    ))

        found.sort(key=lambda x: x["status"])

        lines = [f"Directory scan of {base_url}: {len(found)} paths found"]
        for f in found:
            lines.append(f"  [{f['status']}] {f['path']}")

        return ToolResult(
            tool_name=self.name, success=True,
            data={"base_url": base_url, "found_paths": found, "total_tested": len(paths_to_test)},
            raw_output="\n".join(lines),
            vulnerabilities=vulns,
        )
