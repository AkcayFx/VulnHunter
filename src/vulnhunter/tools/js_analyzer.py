"""JavaScript endpoint extractor — discovers API endpoints, secrets, and internal URLs."""
from __future__ import annotations

import re
from typing import Any
from urllib.parse import urljoin, urlparse

import aiohttp

from vulnhunter.models import Severity, ToolResult, Vulnerability
from vulnhunter.tools.base import BaseTool

# Patterns to extract from JavaScript files
API_PATTERNS = [
    re.compile(r"""['"`](/api/[^'"`\s]{3,})['"`]"""),
    re.compile(r"""['"`](/graphql[^'"`\s]*)['"`]"""),
    re.compile(r"""['"`](/v[123]/[^'"`\s]{3,})['"`]"""),
    re.compile(r"""fetch\s*\(\s*['"`]([^'"`]+)['"`]"""),
    re.compile(r"""axios\.\w+\s*\(\s*['"`]([^'"`]+)['"`]"""),
    re.compile(r"""\.(?:get|post|put|patch|delete)\s*\(\s*['"`]([^'"`]+)['"`]"""),
    re.compile(r"""url\s*[:=]\s*['"`]([^'"`]+)['"`]"""),
    re.compile(r"""endpoint\s*[:=]\s*['"`]([^'"`]+)['"`]"""),
]

SECRET_PATTERNS = {
    "AWS Access Key": re.compile(r"AKIA[0-9A-Z]{16}"),
    "GitHub Token": re.compile(r"ghp_[A-Za-z0-9_]{36}"),
    "Slack Token": re.compile(r"xox[baprs]-[A-Za-z0-9-]+"),
    "Google API Key": re.compile(r"AIza[0-9A-Za-z_-]{35}"),
    "Generic API Key": re.compile(r"""(?:api[_-]?key|apikey|secret[_-]?key)\s*[:=]\s*['"`]([^'"`]{10,})['"`]""", re.IGNORECASE),
    "Bearer Token": re.compile(r"""Bearer\s+[A-Za-z0-9_.~+/=-]{20,}"""),
    "Private Key": re.compile(r"-----BEGIN (?:RSA |EC )?PRIVATE KEY-----"),
    "Firebase Config": re.compile(r"""['"`]https://[a-z0-9-]+\.firebaseio\.com['"`]"""),
}

INTERNAL_URL_PATTERN = re.compile(
    r"""['"`](https?://(?:localhost|127\.0\.0\.1|10\.\d+\.\d+\.\d+|192\.168\.\d+\.\d+|172\.(?:1[6-9]|2\d|3[01])\.\d+\.\d+)[^'"`]*)['"`]"""
)


class JSAnalyzerTool(BaseTool):
    """Analyze JavaScript files for API endpoints, secrets, and internal URLs."""

    @property
    def name(self) -> str:
        return "js_analyzer"

    @property
    def description(self) -> str:
        return (
            "Download and analyze JavaScript files from a target URL. "
            "Extracts API endpoints, hardcoded secrets (API keys, tokens), "
            "internal URLs, and other interesting strings. "
            "Critical for discovering hidden attack surface."
        )

    @property
    def parameters(self) -> dict[str, Any]:
        return {
            "type": "object",
            "properties": {
                "url": {
                    "type": "string",
                    "description": "Target URL to scrape JS files from (e.g., https://example.com)",
                },
                "js_urls": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "Optional list of specific JS URLs to analyze",
                    "default": [],
                },
            },
            "required": ["url"],
        }

    async def _execute(self, **kwargs: Any) -> ToolResult:
        url = kwargs["url"]
        js_urls = kwargs.get("js_urls", [])

        if not js_urls:
            js_urls = await self._find_js_urls(url)

        endpoints: set[str] = set()
        secrets: list[dict[str, str]] = []
        internal_urls: set[str] = set()
        vulns: list[Vulnerability] = []

        for js_url in js_urls[:20]:  # Cap at 20 files
            content = await self._fetch(js_url)
            if not content:
                continue

            # Extract API endpoints
            for pattern in API_PATTERNS:
                for match in pattern.finditer(content):
                    endpoints.add(match.group(1))

            # Check for secrets
            for secret_name, pattern in SECRET_PATTERNS.items():
                for match in pattern.finditer(content):
                    secret_val = match.group(0)[:50]
                    secrets.append({"type": secret_name, "value": secret_val, "file": js_url})
                    vulns.append(Vulnerability(
                        title=f"Hardcoded secret in JS: {secret_name}",
                        severity=Severity.HIGH,
                        tool=self.name,
                        description=f"Found {secret_name} in {js_url}",
                        evidence=f"{secret_val}...",
                        cwe_id="CWE-798",
                        remediation="Remove hardcoded secrets from client-side JavaScript.",
                    ))

            # Check for internal URLs
            for match in INTERNAL_URL_PATTERN.finditer(content):
                internal_urls.add(match.group(1))

        if internal_urls:
            vulns.append(Vulnerability(
                title=f"Internal URLs exposed in JavaScript ({len(internal_urls)} found)",
                severity=Severity.LOW,
                tool=self.name,
                description=f"Internal/private URLs found: {', '.join(list(internal_urls)[:5])}",
                evidence="\n".join(list(internal_urls)[:10]),
                cwe_id="CWE-200",
                remediation="Remove references to internal infrastructure from client-side code.",
            ))

        raw = f"Analyzed {len(js_urls)} JS files from {url}\n"
        raw += f"  API endpoints: {len(endpoints)}\n"
        raw += f"  Secrets found: {len(secrets)}\n"
        raw += f"  Internal URLs: {len(internal_urls)}\n\n"
        if endpoints:
            raw += "Endpoints:\n"
            for ep in sorted(endpoints)[:30]:
                raw += f"  {ep}\n"
        if secrets:
            raw += "\nSecrets (REDACTED):\n"
            for s in secrets[:10]:
                raw += f"  [{s['type']}] in {s['file']}\n"

        return ToolResult(
            tool_name=self.name,
            success=True,
            data={
                "endpoints": sorted(endpoints),
                "secrets_count": len(secrets),
                "internal_urls": sorted(internal_urls),
                "js_files_analyzed": len(js_urls),
            },
            raw_output=raw,
            vulnerabilities=vulns,
        )

    async def _find_js_urls(self, page_url: str) -> list[str]:
        """Fetch page HTML and extract <script src=...> URLs."""
        html = await self._fetch(page_url)
        if not html:
            return []

        js_urls: list[str] = []
        script_pattern = re.compile(r'<script[^>]+src=["\']([^"\']+)["\']', re.IGNORECASE)
        for match in script_pattern.finditer(html):
            src = match.group(1)
            full_url = urljoin(page_url, src)
            if full_url.endswith(".js") or ".js?" in full_url:
                js_urls.append(full_url)
        return js_urls

    @staticmethod
    async def _fetch(url: str) -> str:
        """Fetch URL content with timeout."""
        try:
            async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=15)) as session:
                async with session.get(url, ssl=False) as resp:
                    if resp.status == 200:
                        return await resp.text(errors="replace")
        except Exception:
            pass
        return ""
