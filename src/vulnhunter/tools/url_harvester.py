"""URL harvester — discovers historical URLs via Wayback Machine and CommonCrawl."""
from __future__ import annotations

import asyncio
from typing import Any
from urllib.parse import urlparse

import aiohttp

from vulnhunter.models import ToolResult
from vulnhunter.tools.base import BaseTool

# Extensions that are interesting for bug bounty
INTERESTING_EXTENSIONS = {
    ".php", ".asp", ".aspx", ".jsp", ".json", ".xml", ".config",
    ".yml", ".yaml", ".env", ".bak", ".old", ".sql", ".log",
    ".git", ".svn", ".txt", ".conf", ".ini", ".sh", ".py",
    ".rb", ".js", ".map", ".ts", ".graphql", ".wsdl", ".wadl",
}


class URLHarvesterTool(BaseTool):
    """Discover historical URLs via Wayback Machine CDX API."""

    @property
    def name(self) -> str:
        return "url_harvester"

    @property
    def description(self) -> str:
        return (
            "Query the Wayback Machine CDX API to discover historical URLs for a domain. "
            "Deduplicates results and filters by interesting file extensions. "
            "Useful for finding hidden endpoints, old admin panels, and forgotten files."
        )

    @property
    def parameters(self) -> dict[str, Any]:
        return {
            "type": "object",
            "properties": {
                "domain": {
                    "type": "string",
                    "description": "Target domain (e.g., example.com)",
                },
                "filter_interesting": {
                    "type": "boolean",
                    "description": "Only return URLs with interesting extensions (.php, .config, .env, etc.)",
                    "default": False,
                },
                "limit": {
                    "type": "integer",
                    "description": "Maximum number of URLs to return",
                    "default": 500,
                },
            },
            "required": ["domain"],
        }

    async def _execute(self, **kwargs: Any) -> ToolResult:
        domain = kwargs["domain"]
        filter_interesting = kwargs.get("filter_interesting", False)
        limit = kwargs.get("limit", 500)

        urls: set[str] = set()
        errors: list[str] = []

        # Query Wayback Machine CDX API
        cdx_url = f"https://web.archive.org/cdx/search/cdx?url=*.{domain}/*&output=json&fl=original&collapse=urlkey&limit=10000"
        try:
            async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=30)) as session:
                async with session.get(cdx_url) as resp:
                    if resp.status == 200:
                        data = await resp.json(content_type=None)
                        # First row is header
                        for row in data[1:]:
                            if row and row[0]:
                                urls.add(row[0])
        except Exception as e:
            errors.append(f"Wayback Machine: {e}")

        # Deduplicate and filter
        unique_urls = sorted(urls)
        if filter_interesting:
            unique_urls = [
                u for u in unique_urls
                if any(u.lower().endswith(ext) or ext + "?" in u.lower() for ext in INTERESTING_EXTENSIONS)
            ]

        unique_urls = unique_urls[:limit]

        # Categorize
        by_ext: dict[str, int] = {}
        for u in unique_urls:
            parsed = urlparse(u)
            path = parsed.path.lower()
            ext = "." + path.rsplit(".", 1)[-1] if "." in path.split("/")[-1] else "(no ext)"
            by_ext[ext] = by_ext.get(ext, 0) + 1

        raw = f"Discovered {len(unique_urls)} URLs for {domain}\n"
        raw += "Extensions breakdown:\n"
        for ext, count in sorted(by_ext.items(), key=lambda x: -x[1])[:15]:
            raw += f"  {ext}: {count}\n"
        raw += "\nSample URLs:\n"
        for u in unique_urls[:30]:
            raw += f"  {u}\n"
        if errors:
            raw += f"\nErrors: {'; '.join(errors)}\n"

        return ToolResult(
            tool_name=self.name,
            success=True,
            data={"urls": unique_urls, "total": len(unique_urls), "by_extension": by_ext},
            raw_output=raw,
        )
