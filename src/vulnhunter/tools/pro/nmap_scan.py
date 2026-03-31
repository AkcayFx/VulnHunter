"""Nmap scan wrapper — runs nmap inside Docker sandbox."""
from __future__ import annotations

from typing import Any

from vulnhunter.models import Severity, ToolResult, Vulnerability
from vulnhunter.tools.base import BaseTool
from vulnhunter.tools.pro.constants import SANDBOX_REQUIRED_MSG
from vulnhunter.tools.pro.parsers import parse_nmap_xml


class NmapScanTool(BaseTool):
    """Professional port/service scanner using Nmap (requires Docker sandbox)."""

    @property
    def name(self) -> str:
        return "nmap_scan"

    @property
    def description(self) -> str:
        return (
            "Run Nmap service/version scan inside a Docker sandbox. "
            "Detects open ports, services, versions, and runs default scripts. "
            "More thorough than the built-in port scanner."
        )

    @property
    def parameters(self) -> dict[str, Any]:
        return {
            "type": "object",
            "properties": {
                "target": {
                    "type": "string",
                    "description": "Target hostname or IP address",
                },
                "ports": {
                    "type": "string",
                    "description": "Port specification (e.g., '22,80,443' or '1-1024' or 'top1000')",
                    "default": "top1000",
                },
                "scan_type": {
                    "type": "string",
                    "enum": ["service", "quick", "full", "udp"],
                    "description": "Scan type: service (-sV -sC), quick (-F), full (-p-), udp (-sU --top-ports 100)",
                    "default": "service",
                },
            },
            "required": ["target"],
        }

    async def _execute(self, **kwargs: Any) -> ToolResult:
        if self.sandbox is None:
            raise RuntimeError(SANDBOX_REQUIRED_MSG)

        target = kwargs["target"]
        ports = kwargs.get("ports", "top1000")
        scan_type = kwargs.get("scan_type", "service")

        cmd = ["nmap"]
        if scan_type == "service":
            cmd.extend(["-sV", "-sC"])
        elif scan_type == "quick":
            cmd.append("-F")
        elif scan_type == "full":
            cmd.extend(["-sV", "-p-"])
        elif scan_type == "udp":
            cmd.extend(["-sU", "--top-ports", "100"])

        if ports != "top1000":
            cmd.extend(["-p", ports])
        else:
            cmd.extend(["--top-ports", "1000"])

        cmd.extend(["-oX", "-", target])

        exit_code, output = await self.sandbox.manager.exec_command(cmd, timeout=300)

        if exit_code != 0 and not output.strip():
            return ToolResult(
                tool_name=self.name,
                success=False,
                error=f"Nmap exited with code {exit_code}",
                raw_output=output,
            )

        ports_data = parse_nmap_xml(output)
        open_ports = [p for p in ports_data if p["state"] == "open"]

        vulns: list[Vulnerability] = []
        for p in open_ports:
            # Flag risky services
            risky = {21: "FTP", 23: "Telnet", 445: "SMB", 3389: "RDP", 5900: "VNC"}
            if p["port"] in risky:
                vulns.append(Vulnerability(
                    title=f"Risky service exposed: {risky[p['port']]} on port {p['port']}",
                    severity=Severity.MEDIUM,
                    tool=self.name,
                    description=f"{risky[p['port']]} service detected ({p['version']}). This service is frequently targeted.",
                    evidence=f"{p['host']}:{p['port']} — {p['service']} {p['version']}",
                    remediation=f"Restrict access to port {p['port']} or disable the service if not required.",
                ))

        summary_lines = [f"  {p['port']}/{p['protocol']} {p['state']} {p['service']} {p['version']}" for p in open_ports]
        raw = f"Open ports ({len(open_ports)}):\n" + "\n".join(summary_lines)

        return ToolResult(
            tool_name=self.name,
            success=True,
            data={"ports": ports_data, "open_count": len(open_ports)},
            raw_output=raw,
            vulnerabilities=vulns,
        )
