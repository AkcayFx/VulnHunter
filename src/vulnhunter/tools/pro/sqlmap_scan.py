"""sqlmap wrapper — SQL injection detection inside Docker sandbox."""
from __future__ import annotations

from typing import Any

from vulnhunter.models import ToolResult
from vulnhunter.tools.base import BaseTool
from vulnhunter.tools.pro.parsers import parse_sqlmap_output


class SqlmapScanTool(BaseTool):
    """SQL injection scanner using sqlmap (requires Docker sandbox)."""

    @property
    def name(self) -> str:
        return "sqlmap_scan"

    @property
    def description(self) -> str:
        return (
            "Run sqlmap inside Docker sandbox to detect and exploit SQL injection vulnerabilities. "
            "Tests GET/POST parameters for various injection techniques. "
            "Uses --batch mode for non-interactive execution."
        )

    @property
    def parameters(self) -> dict[str, Any]:
        return {
            "type": "object",
            "properties": {
                "url": {
                    "type": "string",
                    "description": "Target URL with injectable parameter (e.g., https://example.com/search?q=test)",
                },
                "method": {
                    "type": "string",
                    "enum": ["GET", "POST"],
                    "description": "HTTP method",
                    "default": "GET",
                },
                "data": {
                    "type": "string",
                    "description": "POST data (e.g., 'user=test&pass=test')",
                    "default": "",
                },
                "level": {
                    "type": "integer",
                    "description": "Testing level (1-5, higher = more thorough)",
                    "default": 2,
                },
                "risk": {
                    "type": "integer",
                    "description": "Risk level (1-3, higher = riskier tests)",
                    "default": 2,
                },
            },
            "required": ["url"],
        }

    async def _execute(self, **kwargs: Any) -> ToolResult:
        if self.sandbox is None:
            raise RuntimeError("sqlmap_scan requires Docker sandbox mode")

        url = kwargs["url"]
        method = kwargs.get("method", "GET")
        data = kwargs.get("data", "")
        level = kwargs.get("level", 2)
        risk = kwargs.get("risk", 2)

        cmd = [
            "python3", "-m", "sqlmap",
            "-u", url,
            "--batch",
            f"--level={level}",
            f"--risk={risk}",
            "--output-dir=/tmp/sqlmap",
            "--disable-coloring",
        ]

        if method == "POST" and data:
            cmd.extend(["--method=POST", f"--data={data}"])

        exit_code, output = await self.sandbox.manager.exec_command(cmd, timeout=300)

        vulns = parse_sqlmap_output(output)

        raw = f"sqlmap scan complete\n"
        if vulns:
            raw += f"Found {len(vulns)} injection point(s):\n"
            for v in vulns:
                raw += f"  [CRITICAL] {v.title}\n"
        else:
            raw += "No SQL injection vulnerabilities found.\n"

        return ToolResult(
            tool_name=self.name,
            success=True,
            data={"injection_points": len(vulns)},
            raw_output=raw,
            vulnerabilities=vulns,
        )
