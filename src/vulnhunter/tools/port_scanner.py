"""Async TCP port scanner — pure Python, no nmap required."""
from __future__ import annotations

import asyncio
import socket
from typing import Any

from vulnhunter.models import ToolResult, Vulnerability, Severity
from vulnhunter.tools.base import BaseTool

COMMON_SERVICES: dict[int, str] = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
    80: "HTTP", 110: "POP3", 111: "RPCBind", 135: "MSRPC", 139: "NetBIOS",
    143: "IMAP", 443: "HTTPS", 445: "SMB", 993: "IMAPS", 995: "POP3S",
    1433: "MSSQL", 1521: "Oracle", 3306: "MySQL", 3389: "RDP",
    5432: "PostgreSQL", 5900: "VNC", 6379: "Redis", 8080: "HTTP-Proxy",
    8443: "HTTPS-Alt", 8888: "HTTP-Alt", 9200: "Elasticsearch", 27017: "MongoDB",
}

RISKY_PORTS: dict[int, str] = {
    21: "FTP allows unencrypted file transfer",
    23: "Telnet transmits data in plaintext including passwords",
    135: "MSRPC often targeted by worms and exploits",
    139: "NetBIOS can leak system information",
    445: "SMB is frequently targeted (EternalBlue, WannaCry)",
    3389: "RDP is a common attack vector for brute-force and exploits",
    5900: "VNC often has weak authentication",
    6379: "Redis default config has no authentication",
    9200: "Elasticsearch default config allows unauthenticated access",
    27017: "MongoDB default config allows unauthenticated access",
}


class PortScannerTool(BaseTool):
    @property
    def name(self) -> str:
        return "port_scanner"

    @property
    def description(self) -> str:
        return (
            "Scans TCP ports on a target host to discover open services. "
            "Returns list of open ports with service names and identifies risky services."
        )

    @property
    def parameters(self) -> dict[str, Any]:
        return {
            "type": "object",
            "properties": {
                "target": {
                    "type": "string",
                    "description": "Target hostname or IP address to scan",
                },
                "ports": {
                    "type": "string",
                    "description": "Comma-separated ports or range like '1-1024' or '22,80,443'. Defaults to common ports.",
                    "default": "common",
                },
                "timeout": {
                    "type": "number",
                    "description": "Connection timeout per port in seconds",
                    "default": 2,
                },
            },
            "required": ["target"],
        }

    async def _execute(self, **kwargs: Any) -> ToolResult:
        target = kwargs["target"]
        ports_str = kwargs.get("ports", "common")
        timeout = float(kwargs.get("timeout", 2))

        # Resolve hostname
        try:
            ip = socket.gethostbyname(target)
        except socket.gaierror:
            return ToolResult(
                tool_name=self.name, success=False,
                error=f"Cannot resolve hostname: {target}",
            )

        # Parse ports
        ports = self._parse_ports(ports_str)

        # Scan concurrently with semaphore to limit connections
        sem = asyncio.Semaphore(200)
        open_ports: list[dict[str, Any]] = []

        async def scan_port(port: int) -> dict[str, Any] | None:
            async with sem:
                try:
                    _, writer = await asyncio.wait_for(
                        asyncio.open_connection(ip, port), timeout=timeout
                    )
                    writer.close()
                    await writer.wait_closed()
                    service = COMMON_SERVICES.get(port, "unknown")
                    return {"port": port, "state": "open", "service": service}
                except (asyncio.TimeoutError, ConnectionRefusedError, OSError):
                    return None

        tasks = [scan_port(p) for p in ports]
        results = await asyncio.gather(*tasks)

        for r in results:
            if r:
                open_ports.append(r)

        open_ports.sort(key=lambda x: x["port"])

        # Identify vulnerabilities (risky open ports)
        vulns: list[Vulnerability] = []
        for op in open_ports:
            port = op["port"]
            if port in RISKY_PORTS:
                vulns.append(Vulnerability(
                    title=f"Risky service on port {port} ({op['service']})",
                    severity=Severity.MEDIUM if port not in (445, 3389) else Severity.HIGH,
                    tool=self.name,
                    description=RISKY_PORTS[port],
                    evidence=f"Port {port} is open on {target} ({ip})",
                    cwe_id="CWE-284",
                ))

        summary_lines = [f"Port scan of {target} ({ip}): {len(open_ports)} open ports found"]
        for op in open_ports:
            summary_lines.append(f"  {op['port']}/tcp  open  {op['service']}")

        return ToolResult(
            tool_name=self.name,
            success=True,
            data={
                "target": target,
                "ip": ip,
                "open_ports": open_ports,
                "total_scanned": len(ports),
                "total_open": len(open_ports),
            },
            raw_output="\n".join(summary_lines),
            vulnerabilities=vulns,
        )

    @staticmethod
    def _parse_ports(ports_str: str) -> list[int]:
        if ports_str == "common":
            return list(COMMON_SERVICES.keys())

        ports: list[int] = []
        for part in ports_str.split(","):
            part = part.strip()
            if "-" in part:
                start, end = part.split("-", 1)
                ports.extend(range(int(start), int(end) + 1))
            else:
                ports.append(int(part))
        return ports
