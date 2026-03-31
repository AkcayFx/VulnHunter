"""Web scraper tool — fetches and extracts text from web pages."""
from __future__ import annotations

from typing import Any

import aiohttp
from bs4 import BeautifulSoup

from vulnhunter.models import ToolResult
from vulnhunter.tools.base import BaseTool


class WebScraperTool(BaseTool):
    @property
    def name(self) -> str:
        return "web_scraper"

    @property
    def description(self) -> str:
        return (
            "Fetch a URL and extract readable text, links, forms, and metadata. "
            "Useful for analysing page content, finding hidden endpoints, or gathering intel."
        )

    @property
    def parameters(self) -> dict[str, Any]:
        return {
            "type": "object",
            "properties": {
                "url": {"type": "string", "description": "Full URL to fetch"},
                "extract_links": {
                    "type": "boolean",
                    "description": "Also extract all <a> href links",
                    "default": True,
                },
                "extract_forms": {
                    "type": "boolean",
                    "description": "Also extract <form> actions and inputs",
                    "default": True,
                },
            },
            "required": ["url"],
        }

    async def _execute(self, **kwargs: Any) -> ToolResult:
        url: str = kwargs["url"]
        extract_links: bool = kwargs.get("extract_links", True)
        extract_forms: bool = kwargs.get("extract_forms", True)

        headers = {"User-Agent": "VulnHunter/2.0 (Security Audit)"}

        async with aiohttp.ClientSession() as session:
            async with session.get(url, headers=headers, timeout=aiohttp.ClientTimeout(total=15)) as resp:
                status = resp.status
                html = await resp.text(errors="replace")
                resp_headers = dict(resp.headers)

        soup = BeautifulSoup(html, "html.parser")

        title = soup.title.string.strip() if soup.title and soup.title.string else ""
        meta_tags = {}
        for tag in soup.find_all("meta"):
            name = tag.get("name") or tag.get("property", "")
            content = tag.get("content", "")
            if name and content:
                meta_tags[name] = content[:200]

        body_text = soup.get_text(separator=" ", strip=True)[:3000]

        data: dict[str, Any] = {
            "status_code": status,
            "title": title,
            "meta": meta_tags,
            "body_length": len(html),
            "text_preview": body_text[:1000],
        }

        links: list[str] = []
        if extract_links:
            for a in soup.find_all("a", href=True):
                href = a["href"]
                if href and not href.startswith("#"):
                    links.append(href)
            data["links"] = links[:100]

        forms: list[dict[str, Any]] = []
        if extract_forms:
            for form in soup.find_all("form"):
                form_data: dict[str, Any] = {
                    "action": form.get("action", ""),
                    "method": form.get("method", "GET").upper(),
                    "inputs": [],
                }
                for inp in form.find_all(["input", "textarea", "select"]):
                    form_data["inputs"].append({
                        "name": inp.get("name", ""),
                        "type": inp.get("type", "text"),
                    })
                forms.append(form_data)
            data["forms"] = forms[:20]

        lines = [f"URL: {url} — HTTP {status}"]
        if title:
            lines.append(f"Title: {title}")
        lines.append(f"Body size: {len(html)} bytes")
        if links:
            lines.append(f"Links found: {len(links)}")
        if forms:
            lines.append(f"Forms found: {len(forms)}")
        lines.append(f"\nText preview:\n{body_text[:500]}")

        return ToolResult(
            tool_name=self.name,
            success=True,
            data=data,
            raw_output="\n".join(lines),
        )
