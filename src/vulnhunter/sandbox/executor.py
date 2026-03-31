"""Sandboxed tool executor — wraps tool network calls to run inside a container."""
from __future__ import annotations

import json
import logging
from typing import Any

from vulnhunter.sandbox.manager import ContainerManager

logger = logging.getLogger("vulnhunter.sandbox")


class SandboxedExecutor:
    """Runs Python code snippets inside an active sandbox container.

    Tools can delegate their network-heavy logic here so the host
    never directly performs untrusted network operations.
    """

    def __init__(self, manager: ContainerManager):
        self.manager = manager

    async def run_script(self, script: str, timeout: int = 60) -> dict[str, Any]:
        """Execute a Python script in the sandbox and parse its JSON stdout."""
        exit_code, output = await self.manager.exec_python(script, timeout=timeout)
        if exit_code != 0:
            return {"success": False, "error": output.strip(), "exit_code": exit_code}

        try:
            return json.loads(output.strip())
        except json.JSONDecodeError:
            return {"success": True, "raw_output": output.strip()}

    async def tcp_connect(self, host: str, port: int, timeout: float = 2.0) -> bool:
        """Attempt a TCP connection from inside the sandbox."""
        script = f"""
import socket, json
try:
    s = socket.create_connection(({host!r}, {port}), timeout={timeout})
    s.close()
    print(json.dumps({{"open": True}}))
except Exception:
    print(json.dumps({{"open": False}}))
"""
        result = await self.run_script(script, timeout=int(timeout) + 5)
        return result.get("open", False)

    async def http_get(self, url: str, timeout: int = 10) -> dict[str, Any]:
        """Perform an HTTP GET from inside the sandbox."""
        script = f"""
import urllib.request, json
try:
    req = urllib.request.Request({url!r}, headers={{"User-Agent": "VulnHunter/2.0"}})
    with urllib.request.urlopen(req, timeout={timeout}) as resp:
        body = resp.read(32768).decode(errors="replace")
        headers = dict(resp.getheaders())
        print(json.dumps({{"status": resp.status, "headers": headers, "body": body[:8192]}}))
except Exception as e:
    print(json.dumps({{"error": str(e)}}))
"""
        return await self.run_script(script, timeout=timeout + 5)

    async def dns_resolve(self, hostname: str, record_type: str = "A") -> list[str]:
        """Resolve DNS from inside the sandbox."""
        script = f"""
import socket, json
try:
    results = socket.getaddrinfo({hostname!r}, None)
    ips = list(set(r[4][0] for r in results))
    print(json.dumps({{"records": ips}}))
except Exception as e:
    print(json.dumps({{"records": [], "error": str(e)}}))
"""
        result = await self.run_script(script, timeout=15)
        return result.get("records", [])
