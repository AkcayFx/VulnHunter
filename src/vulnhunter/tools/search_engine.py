"""Search engine tool — DuckDuckGo HTML scraping for OSINT."""
from __future__ import annotations

from typing import Any
from urllib.parse import quote_plus

import aiohttp
from bs4 import BeautifulSoup

from vulnhunter.models import ToolResult
from vulnhunter.tools.base import BaseTool


class SearchEngineTool(BaseTool):
    @property
    def name(self) -> str:
        return "search_engine"

    @property
    def description(self) -> str:
        return (
            "Search the web via DuckDuckGo for OSINT — find exposed panels, "
            "leaked credentials references, related domains, or public disclosures."
        )

    @property
    def parameters(self) -> dict[str, Any]:
        return {
            "type": "object",
            "properties": {
                "query": {
                    "type": "string",
                    "description": "Search query, e.g. 'site:example.com filetype:sql'",
                },
                "max_results": {
                    "type": "integer",
                    "description": "Maximum results to return",
                    "default": 10,
                },
            },
            "required": ["query"],
        }

    async def _execute(self, **kwargs: Any) -> ToolResult:
        query: str = kwargs["query"]
        max_results: int = kwargs.get("max_results", 10)

        url = f"https://html.duckduckgo.com/html/?q={quote_plus(query)}"
        headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
        }

        async with aiohttp.ClientSession() as session:
            async with session.get(url, headers=headers, timeout=aiohttp.ClientTimeout(total=15)) as resp:
                if resp.status != 200:
                    return ToolResult(
                        tool_name=self.name,
                        success=False,
                        error=f"DuckDuckGo returned HTTP {resp.status}",
                    )
                html = await resp.text(errors="replace")

        soup = BeautifulSoup(html, "html.parser")
        results: list[dict[str, str]] = []

        for result_div in soup.select(".result__body")[:max_results]:
            title_tag = result_div.select_one(".result__a")
            snippet_tag = result_div.select_one(".result__snippet")
            link_tag = result_div.select_one(".result__url")

            title = title_tag.get_text(strip=True) if title_tag else ""
            snippet = snippet_tag.get_text(strip=True) if snippet_tag else ""
            link = ""
            if title_tag and title_tag.get("href"):
                link = title_tag["href"]
            elif link_tag:
                link = link_tag.get_text(strip=True)

            if title or snippet:
                results.append({"title": title, "url": link, "snippet": snippet})

        lines = [f"Search results for: {query}", f"Found {len(results)} results\n"]
        for i, r in enumerate(results, 1):
            lines.append(f"{i}. {r['title']}")
            lines.append(f"   URL: {r['url']}")
            lines.append(f"   {r['snippet'][:200]}")
            lines.append("")

        return ToolResult(
            tool_name=self.name,
            success=True,
            data={"query": query, "results": results},
            raw_output="\n".join(lines),
        )
