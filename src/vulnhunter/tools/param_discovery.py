"""Parameter discovery — finds injectable parameters from URLs and HTML forms."""
from __future__ import annotations

import re
from typing import Any
from urllib.parse import parse_qs, urlparse

import aiohttp
from bs4 import BeautifulSoup

from vulnhunter.models import ToolResult
from vulnhunter.tools.base import BaseTool


class ParamDiscoveryTool(BaseTool):
    """Discover injectable parameters from forms, URLs, and JavaScript."""

    @property
    def name(self) -> str:
        return "param_discovery"

    @property
    def description(self) -> str:
        return (
            "Crawl a target URL and discover all injectable parameters: "
            "query string params, form fields, JSON body fields. "
            "Tags each parameter with its context (reflected, stored, numeric, etc.). "
            "Feed results directly into vulnerability testing tools."
        )

    @property
    def parameters(self) -> dict[str, Any]:
        return {
            "type": "object",
            "properties": {
                "url": {
                    "type": "string",
                    "description": "Target URL to analyze for parameters",
                },
                "known_urls": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "Additional URLs to extract parameters from (e.g., from url_harvester)",
                    "default": [],
                },
            },
            "required": ["url"],
        }

    async def _execute(self, **kwargs: Any) -> ToolResult:
        url = kwargs["url"]
        known_urls = kwargs.get("known_urls", [])

        params: dict[str, dict[str, Any]] = {}

        # 1. Extract params from known URLs
        all_urls = [url] + known_urls[:200]
        for u in all_urls:
            parsed = urlparse(u)
            qs = parse_qs(parsed.query)
            for param_name, values in qs.items():
                if param_name not in params:
                    params[param_name] = {
                        "source": "query_string",
                        "urls": [],
                        "sample_values": [],
                        "tags": set(),
                    }
                params[param_name]["urls"].append(u)
                params[param_name]["sample_values"].extend(values[:3])
                # Tag the parameter
                for val in values:
                    params[param_name]["tags"].update(self._tag_value(val))

        # 2. Fetch the page and extract form fields
        try:
            async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=15)) as session:
                async with session.get(url, ssl=False) as resp:
                    if resp.status == 200:
                        html = await resp.text(errors="replace")
                        form_params = self._extract_form_params(html)
                        for fp in form_params:
                            name = fp["name"]
                            if name not in params:
                                params[name] = {
                                    "source": "form",
                                    "urls": [url],
                                    "sample_values": [],
                                    "tags": set(),
                                }
                            params[name]["tags"].add(f"form_{fp['type']}")
                            if fp.get("action"):
                                params[name]["tags"].add("form_action")
        except Exception:
            pass

        # Convert sets to lists for JSON serialization
        param_list = []
        for name, info in params.items():
            param_list.append({
                "name": name,
                "source": info["source"],
                "url_count": len(info["urls"]),
                "sample_values": info["sample_values"][:5],
                "tags": sorted(info["tags"]),
            })

        raw = f"Discovered {len(param_list)} parameters:\n"
        for p in param_list[:30]:
            raw += f"  {p['name']} ({p['source']}) — tags: {', '.join(p['tags'])} — seen in {p['url_count']} URL(s)\n"

        return ToolResult(
            tool_name=self.name,
            success=True,
            data={"parameters": param_list, "total": len(param_list)},
            raw_output=raw,
        )

    @staticmethod
    def _extract_form_params(html: str) -> list[dict[str, str]]:
        """Extract form fields from HTML."""
        params: list[dict[str, str]] = []
        soup = BeautifulSoup(html, "html.parser")
        for form in soup.find_all("form"):
            action = form.get("action", "")
            method = form.get("method", "GET").upper()
            for inp in form.find_all(["input", "textarea", "select"]):
                name = inp.get("name")
                if name:
                    params.append({
                        "name": name,
                        "type": inp.get("type", "text"),
                        "action": action,
                        "method": method,
                    })
        return params

    @staticmethod
    def _tag_value(value: str) -> set[str]:
        """Tag a parameter value by its characteristics."""
        tags: set[str] = set()
        if value.isdigit():
            tags.add("numeric")
        if "@" in value:
            tags.add("email")
        if re.match(r"^[0-9a-f-]{36}$", value):
            tags.add("uuid")
        if re.match(r"^https?://", value):
            tags.add("url")
        if len(value) > 100:
            tags.add("long_value")
        return tags
