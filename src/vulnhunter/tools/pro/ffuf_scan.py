"""ffuf scan wrapper — web fuzzer inside Docker sandbox."""
from __future__ import annotations

from typing import Any

from vulnhunter.models import Severity, ToolResult, Vulnerability
from vulnhunter.tools.base import BaseTool
from vulnhunter.tools.pro.constants import SANDBOX_REQUIRED_MSG
from vulnhunter.tools.pro.parsers import parse_ffuf_json


class FfufScanTool(BaseTool):
    """Web fuzzer using ffuf for directory/file discovery."""

    @property
    def name(self) -> str:
        return "ffuf_scan"

    @property
    def description(self) -> str:
        return (
            "Run ffuf web fuzzer inside Docker sandbox to discover hidden directories, "
            "files, and endpoints. Uses wordlists and supports filtering by status code, "
            "response size, and word count."
        )

    @property
    def parameters(self) -> dict[str, Any]:
        return {
            "type": "object",
            "properties": {
                "url": {
                    "type": "string",
                    "description": "Target URL with FUZZ keyword (e.g., https://example.com/FUZZ). If no FUZZ keyword, /FUZZ is appended.",
                },
                "wordlist": {
                    "type": "string",
                    "description": "Wordlist to use: 'common' or 'directory-list-small'",
                    "default": "common",
                },
                "extensions": {
                    "type": "string",
                    "description": "File extensions to test (e.g., 'php,asp,jsp,html')",
                    "default": "",
                },
                "filter_status": {
                    "type": "string",
                    "description": "Filter out these status codes (e.g., '404,403')",
                    "default": "404",
                },
            },
            "required": ["url"],
        }

    async def _execute(self, **kwargs: Any) -> ToolResult:
        if self.sandbox is None:
            raise RuntimeError(SANDBOX_REQUIRED_MSG)

        url = kwargs["url"]
        if "FUZZ" not in url:
            url = url.rstrip("/") + "/FUZZ"

        wordlist_name = kwargs.get("wordlist", "common")
        wordlist_map = {
            "common": "/wordlists/common.txt",
            "directory-list-small": "/wordlists/directory-list-small.txt",
        }
        wordlist = wordlist_map.get(wordlist_name, "/wordlists/common.txt")

        extensions = kwargs.get("extensions", "")
        filter_status = kwargs.get("filter_status", "404")

        cmd = ["ffuf", "-u", url, "-w", wordlist, "-o", "/tmp/ffuf_out.json", "-of", "json", "-silent"]
        if extensions:
            cmd.extend(["-e", f".{extensions.replace(',', ',.')}"])
        if filter_status:
            cmd.extend(["-fc", filter_status])

        exit_code, _ = await self.sandbox.manager.exec_command(cmd, timeout=300)

        # Read the output file
        _, json_output = await self.sandbox.manager.exec_command(["cat", "/tmp/ffuf_out.json"], timeout=10)

        results = parse_ffuf_json(json_output)

        vulns: list[Vulnerability] = []
        sensitive_patterns = ["admin", "backup", "config", "env", "debug", "phpinfo", ".git", "wp-admin"]
        for r in results:
            found_path = r.get("input", "")
            if any(p in found_path.lower() for p in sensitive_patterns):
                vulns.append(Vulnerability(
                    title=f"Sensitive path discovered: {found_path}",
                    severity=Severity.MEDIUM,
                    tool=self.name,
                    description=f"Discovered potentially sensitive path: {r['url']} (status {r['status']})",
                    evidence=f"URL: {r['url']}, Status: {r['status']}, Size: {r['length']}",
                    remediation="Restrict access to sensitive paths or remove them from production.",
                ))

        raw = f"ffuf found {len(results)} paths:\n"
        for r in results[:50]:
            raw += f"  [{r['status']}] {r['url']} ({r['length']} bytes)\n"

        return ToolResult(
            tool_name=self.name,
            success=True,
            data={"results": results, "total": len(results)},
            raw_output=raw,
            vulnerabilities=vulns,
        )
