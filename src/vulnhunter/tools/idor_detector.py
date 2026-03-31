"""IDOR detector — tests for Insecure Direct Object Reference vulnerabilities.

IDOR is consistently the highest-paid bug class in bounty programs ($200-$25,000).
It occurs when changing an object ID in a request gives access to another user's data.
"""
from __future__ import annotations

import re
from typing import Any
from urllib.parse import urlparse, urlencode, parse_qs

import aiohttp

from vulnhunter.models import Severity, ToolResult, Vulnerability
from vulnhunter.tools.base import BaseTool

ID_PATTERN = re.compile(r"(?:^|/)(\d{1,10})(?:/|$|\?)")
UUID_PATTERN = re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}", re.IGNORECASE)
ID_PARAM_NAMES = {
    "id", "user_id", "userid", "uid", "account_id", "accountid", "profile_id",
    "order_id", "orderid", "invoice_id", "doc_id", "file_id", "item_id",
    "project_id", "team_id", "org_id", "record_id", "message_id", "comment_id",
    "report_id", "ticket_id", "customer_id", "transaction_id",
}


class IDORDetectorTool(BaseTool):
    """Test for Insecure Direct Object Reference (IDOR) patterns."""

    @property
    def name(self) -> str:
        return "idor_detector"

    @property
    def description(self) -> str:
        return (
            "Detect IDOR (Insecure Direct Object Reference) patterns in API endpoints. "
            "Finds numeric/UUID IDs in URLs and tests if modifying them returns different data, "
            "indicating unauthorized access to other users' resources. "
            "IDOR is the highest-paid bug class ($200-$25,000)."
        )

    @property
    def parameters(self) -> dict[str, Any]:
        return {
            "type": "object",
            "properties": {
                "url": {
                    "type": "string",
                    "description": "URL with an ID to test (e.g., https://api.example.com/users/123)",
                },
                "endpoints": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "List of API endpoints to scan for IDOR patterns (from recon)",
                    "default": [],
                },
                "auth_header": {
                    "type": "string",
                    "description": "Authorization header value (e.g., 'Bearer token123') for authenticated IDOR testing",
                    "default": "",
                },
            },
            "required": ["url"],
        }

    async def _execute(self, **kwargs: Any) -> ToolResult:
        url = kwargs["url"]
        endpoints = kwargs.get("endpoints", [])
        auth_header = kwargs.get("auth_header", "")

        all_urls = [url] + endpoints[:30]
        vulns: list[Vulnerability] = []
        findings: list[dict[str, Any]] = []

        headers: dict[str, str] = {"User-Agent": "Mozilla/5.0 (compatible; VulnHunter/2.0)"}
        if auth_header:
            headers["Authorization"] = auth_header

        for test_url in all_urls:
            # Find IDs in path
            path_ids = self._find_path_ids(test_url)
            for original_id, modified_ids, position in path_ids:
                for mod_id in modified_ids:
                    result = await self._test_idor_path(test_url, original_id, mod_id, headers)
                    if result:
                        findings.append({
                            "url": test_url,
                            "id_type": "path",
                            "original": original_id,
                            "modified": mod_id,
                            "indicator": result,
                        })
                        vulns.append(Vulnerability(
                            title=f"Potential IDOR: ID '{original_id}' in URL path",
                            severity=Severity.HIGH,
                            tool=self.name,
                            description=(
                                f"Changing ID from '{original_id}' to '{mod_id}' in the URL path "
                                f"returned different data, suggesting unauthorized access to another "
                                f"user's resource."
                            ),
                            evidence=(
                                f"Original URL: {test_url}\n"
                                f"Modified ID: {original_id} → {mod_id}\n"
                                f"Indicator: {result}"
                            ),
                            cwe_id="CWE-639",
                            remediation=(
                                "Implement proper authorization checks. Verify the authenticated user "
                                "owns the requested resource before returning data. Use indirect "
                                "references (UUIDs) instead of sequential integers."
                            ),
                        ))
                        break

            # Find IDs in query parameters
            param_ids = self._find_param_ids(test_url)
            for param_name, original_val, modified_vals in param_ids:
                for mod_val in modified_vals:
                    result = await self._test_idor_param(test_url, param_name, mod_val, headers)
                    if result:
                        findings.append({
                            "url": test_url,
                            "id_type": "param",
                            "param": param_name,
                            "original": original_val,
                            "modified": mod_val,
                            "indicator": result,
                        })
                        vulns.append(Vulnerability(
                            title=f"Potential IDOR: parameter '{param_name}'",
                            severity=Severity.HIGH,
                            tool=self.name,
                            description=(
                                f"Changing parameter '{param_name}' from '{original_val}' to '{mod_val}' "
                                f"returned different valid data."
                            ),
                            evidence=(
                                f"URL: {test_url}\nParameter: {param_name}\n"
                                f"Original: {original_val} → Modified: {mod_val}\n"
                                f"Indicator: {result}"
                            ),
                            cwe_id="CWE-639",
                            remediation="Implement server-side authorization for every object access.",
                        ))
                        break

        raw = f"IDOR scan of {len(all_urls)} endpoint(s)\n"
        if findings:
            raw += f"POTENTIAL IDOR: {len(findings)} finding(s):\n"
            for f in findings:
                raw += f"  {f['id_type'].upper()} — {f.get('param', 'path')} @ {f['url']}\n"
        else:
            raw += "No obvious IDOR patterns detected.\n"
            raw += "Note: Full IDOR testing requires authenticated sessions with multiple user accounts.\n"

        return ToolResult(
            tool_name=self.name,
            success=True,
            data={"findings": findings, "total": len(findings)},
            raw_output=raw,
            vulnerabilities=vulns,
        )

    def _find_path_ids(self, url: str) -> list[tuple[str, list[str], int]]:
        """Find numeric IDs in URL path and generate modified versions."""
        parsed = urlparse(url)
        results: list[tuple[str, list[str], int]] = []

        parts = parsed.path.split("/")
        for i, part in enumerate(parts):
            if part.isdigit() and len(part) <= 10:
                original = part
                num = int(original)
                modified = [str(num + 1), str(num - 1), str(num + 100)]
                modified = [m for m in modified if m != original and int(m) > 0]
                if modified:
                    results.append((original, modified[:2], i))
            elif UUID_PATTERN.fullmatch(part):
                # UUID — can't easily enumerate, but flag the pattern
                pass

        return results

    def _find_param_ids(self, url: str) -> list[tuple[str, str, list[str]]]:
        """Find ID-like parameters in query string."""
        parsed = urlparse(url)
        params = parse_qs(parsed.query)
        results: list[tuple[str, str, list[str]]] = []

        for name, values in params.items():
            if name.lower() in ID_PARAM_NAMES and values:
                val = values[0]
                if val.isdigit():
                    num = int(val)
                    modified = [str(num + 1), str(num - 1)]
                    modified = [m for m in modified if m != val and int(m) > 0]
                    if modified:
                        results.append((name, val, modified))

        return results

    async def _test_idor_path(
        self, url: str, original_id: str, modified_id: str, headers: dict
    ) -> str:
        """Test path-based IDOR by swapping IDs."""
        modified_url = url.replace(f"/{original_id}", f"/{modified_id}", 1)
        return await self._compare_responses(url, modified_url, headers)

    async def _test_idor_param(
        self, url: str, param_name: str, modified_val: str, headers: dict
    ) -> str:
        """Test parameter-based IDOR by swapping values."""
        parsed = urlparse(url)
        params = parse_qs(parsed.query)
        params[param_name] = [modified_val]
        flat_params = {k: v[0] if isinstance(v, list) else v for k, v in params.items()}
        modified_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{urlencode(flat_params)}"
        return await self._compare_responses(url, modified_url, headers)

    async def _compare_responses(self, original_url: str, modified_url: str, headers: dict) -> str:
        """Fetch both URLs and compare. If modified returns 200 with different data, flag it."""
        try:
            async with aiohttp.ClientSession(
                timeout=aiohttp.ClientTimeout(total=10), headers=headers
            ) as session:
                async with session.get(original_url, ssl=False) as resp1:
                    status1 = resp1.status
                    body1 = await resp1.text(errors="replace")

                async with session.get(modified_url, ssl=False) as resp2:
                    status2 = resp2.status
                    body2 = await resp2.text(errors="replace")

            if status2 == 200 and status1 == 200:
                # Both return 200 but with different content = potential IDOR
                if body1 != body2 and len(body2) > 50:
                    if abs(len(body1) - len(body2)) < len(body1) * 0.9:
                        return f"Different data returned (original: {len(body1)}B, modified: {len(body2)}B)"

            if status2 == 200 and status1 in (401, 403):
                return f"Modified ID bypassed auth (original: {status1}, modified: {status2})"

        except Exception:
            pass
        return ""
