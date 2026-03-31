"""Katana crawl wrapper — web crawler inside Docker sandbox."""
from __future__ import annotations

from typing import Any

from vulnhunter.models import ToolResult
from vulnhunter.tools.base import BaseTool
from vulnhunter.tools.pro.constants import SANDBOX_REQUIRED_MSG
from vulnhunter.tools.pro.parsers import parse_katana_jsonl


class KatanaCrawlTool(BaseTool):
    """Web crawler using ProjectDiscovery Katana (requires Docker sandbox)."""

    @property
    def name(self) -> str:
        return "katana_crawl"

    @property
    def description(self) -> str:
        return (
            "Run Katana web crawler inside Docker sandbox to discover URLs, endpoints, "
            "and JavaScript files. Supports depth control and scope filtering. "
            "Great for discovering attack surface before vulnerability testing."
        )

    @property
    def parameters(self) -> dict[str, Any]:
        return {
            "type": "object",
            "properties": {
                "url": {
                    "type": "string",
                    "description": "Starting URL to crawl (e.g., https://example.com)",
                },
                "depth": {
                    "type": "integer",
                    "description": "Crawl depth (1-5)",
                    "default": 3,
                },
                "js_crawl": {
                    "type": "boolean",
                    "description": "Enable JavaScript file crawling for endpoint extraction",
                    "default": True,
                },
            },
            "required": ["url"],
        }

    async def _execute(self, **kwargs: Any) -> ToolResult:
        if self.sandbox is None:
            raise RuntimeError(SANDBOX_REQUIRED_MSG)

        url = kwargs["url"]
        depth = kwargs.get("depth", 3)
        js_crawl = kwargs.get("js_crawl", True)

        cmd = ["katana", "-u", url, "-json", "-silent", "-depth", str(depth)]
        if js_crawl:
            cmd.append("-jc")

        exit_code, output = await self.sandbox.manager.exec_command(cmd, timeout=300)

        endpoints = parse_katana_jsonl(output)

        raw = f"Katana crawled {len(endpoints)} endpoints from {url}:\n"
        for ep in endpoints[:50]:
            raw += f"  [{ep.get('method', 'GET')}] {ep['url']}\n"
        if len(endpoints) > 50:
            raw += f"  ... and {len(endpoints) - 50} more\n"

        return ToolResult(
            tool_name=self.name,
            success=True,
            data={"endpoints": endpoints, "total": len(endpoints)},
            raw_output=raw,
        )
