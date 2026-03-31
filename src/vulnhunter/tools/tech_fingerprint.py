"""Technology fingerprinting tool — identifies web technologies from HTTP headers and HTML."""
from __future__ import annotations

import re
from typing import Any

import aiohttp

from vulnhunter.models import ToolResult
from vulnhunter.tools.base import BaseTool

TECH_SIGNATURES: dict[str, list[dict[str, str]]] = {
    "WordPress": [
        {"type": "header", "key": "X-Powered-By", "pattern": r"(?i)wordpress"},
        {"type": "body", "pattern": r"wp-content|wp-includes|wp-json"},
        {"type": "body", "pattern": r'<meta name="generator" content="WordPress'},
    ],
    "Nginx": [
        {"type": "header", "key": "Server", "pattern": r"(?i)nginx"},
    ],
    "Apache": [
        {"type": "header", "key": "Server", "pattern": r"(?i)apache"},
    ],
    "Cloudflare": [
        {"type": "header", "key": "Server", "pattern": r"(?i)cloudflare"},
        {"type": "header", "key": "CF-RAY", "pattern": r".+"},
    ],
    "React": [
        {"type": "body", "pattern": r"react\.production\.min\.js|__NEXT_DATA__|_next/static"},
    ],
    "Vue.js": [
        {"type": "body", "pattern": r"vue\.runtime|Vue\.js|v-cloak"},
    ],
    "jQuery": [
        {"type": "body", "pattern": r"jquery[\.-][\d\.]+\.(?:min\.)?js"},
    ],
    "PHP": [
        {"type": "header", "key": "X-Powered-By", "pattern": r"(?i)php"},
    ],
    "ASP.NET": [
        {"type": "header", "key": "X-AspNet-Version", "pattern": r".+"},
        {"type": "header", "key": "X-Powered-By", "pattern": r"(?i)asp\.net"},
    ],
    "Django": [
        {"type": "header", "key": "X-Frame-Options", "pattern": r"DENY"},
        {"type": "body", "pattern": r"csrfmiddlewaretoken|django"},
    ],
    "Express": [
        {"type": "header", "key": "X-Powered-By", "pattern": r"(?i)express"},
    ],
    "Next.js": [
        {"type": "header", "key": "X-Powered-By", "pattern": r"(?i)next\.js"},
        {"type": "body", "pattern": r"__NEXT_DATA__|_next/static"},
    ],
    "Varnish": [
        {"type": "header", "key": "Via", "pattern": r"(?i)varnish"},
        {"type": "header", "key": "X-Varnish", "pattern": r".+"},
    ],
    "AWS S3": [
        {"type": "header", "key": "Server", "pattern": r"AmazonS3"},
        {"type": "header", "key": "x-amz-request-id", "pattern": r".+"},
    ],
    "IIS": [
        {"type": "header", "key": "Server", "pattern": r"(?i)Microsoft-IIS"},
    ],
    "Bootstrap": [
        {"type": "body", "pattern": r"bootstrap[\.-][\d\.]+\.(?:min\.)?(?:css|js)"},
    ],
    "Tailwind CSS": [
        {"type": "body", "pattern": r"tailwindcss|tailwind\.min\.css"},
    ],
}


class TechFingerprintTool(BaseTool):
    @property
    def name(self) -> str:
        return "tech_fingerprint"

    @property
    def description(self) -> str:
        return (
            "Identify web technologies used by a target URL — frameworks, servers, "
            "CDNs, CMS, JavaScript libraries — based on HTTP headers and HTML content."
        )

    @property
    def parameters(self) -> dict[str, Any]:
        return {
            "type": "object",
            "properties": {
                "url": {
                    "type": "string",
                    "description": "Target URL to fingerprint (e.g. https://example.com)",
                },
            },
            "required": ["url"],
        }

    async def _execute(self, **kwargs: Any) -> ToolResult:
        url: str = kwargs["url"]
        headers_req = {"User-Agent": "VulnHunter/2.0 (Security Audit)"}

        async with aiohttp.ClientSession() as session:
            async with session.get(
                url, headers=headers_req, timeout=aiohttp.ClientTimeout(total=15),
                allow_redirects=True,
            ) as resp:
                status = resp.status
                resp_headers = {k: v for k, v in resp.headers.items()}
                body = await resp.text(errors="replace")

        detected: dict[str, list[str]] = {}

        for tech_name, signatures in TECH_SIGNATURES.items():
            for sig in signatures:
                matched = False
                if sig["type"] == "header":
                    header_val = resp_headers.get(sig["key"], "")
                    if header_val and re.search(sig["pattern"], header_val):
                        matched = True
                        evidence = f"Header {sig['key']}: {header_val[:100]}"
                elif sig["type"] == "body":
                    m = re.search(sig["pattern"], body[:50000])
                    if m:
                        matched = True
                        evidence = f"Body match: {m.group()[:80]}"

                if matched:
                    detected.setdefault(tech_name, []).append(evidence)

        server = resp_headers.get("Server", "")
        powered_by = resp_headers.get("X-Powered-By", "")

        lines = [
            f"Technology fingerprint for {url} (HTTP {status})",
            f"Server header: {server or 'not disclosed'}",
            f"X-Powered-By: {powered_by or 'not disclosed'}",
            f"\nDetected {len(detected)} technologies:\n",
        ]
        for tech, evidences in sorted(detected.items()):
            lines.append(f"  [{tech}]")
            for ev in evidences:
                lines.append(f"    - {ev}")

        return ToolResult(
            tool_name=self.name,
            success=True,
            data={
                "url": url,
                "status": status,
                "server": server,
                "x_powered_by": powered_by,
                "technologies": {k: v for k, v in detected.items()},
            },
            raw_output="\n".join(lines),
        )
