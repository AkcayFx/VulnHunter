"""SSL/TLS certificate and protocol checker."""
from __future__ import annotations

import ssl
import socket
import datetime
from typing import Any

from vulnhunter.models import ToolResult, Vulnerability, Severity
from vulnhunter.tools.base import BaseTool


class SSLCheckerTool(BaseTool):
    @property
    def name(self) -> str:
        return "ssl_checker"

    @property
    def description(self) -> str:
        return (
            "Checks SSL/TLS certificate validity, expiry, protocol version, and cipher strength. "
            "Identifies weak configurations and certificate issues."
        )

    @property
    def parameters(self) -> dict[str, Any]:
        return {
            "type": "object",
            "properties": {
                "target": {
                    "type": "string",
                    "description": "Target hostname to check SSL/TLS",
                },
                "port": {
                    "type": "integer",
                    "description": "Port number (default: 443)",
                    "default": 443,
                },
            },
            "required": ["target"],
        }

    async def _execute(self, **kwargs: Any) -> ToolResult:
        target = kwargs["target"]
        port = int(kwargs.get("port", 443))
        vulns: list[Vulnerability] = []

        try:
            ctx = ssl.create_default_context()
            with socket.create_connection((target, port), timeout=10) as sock:
                with ctx.wrap_socket(sock, server_hostname=target) as ssock:
                    cert = ssock.getpeercert()
                    cipher = ssock.cipher()
                    protocol = ssock.version()
        except ssl.SSLCertVerificationError as e:
            vulns.append(Vulnerability(
                title="Invalid SSL Certificate",
                severity=Severity.HIGH,
                tool=self.name,
                description=f"SSL certificate verification failed: {e}",
                evidence=str(e),
                cwe_id="CWE-295",
                remediation="Install a valid SSL certificate from a trusted CA",
            ))
            return ToolResult(
                tool_name=self.name, success=True,
                data={"error": str(e), "valid": False},
                raw_output=f"SSL check for {target}:{port}: Certificate verification FAILED\n  {e}",
                vulnerabilities=vulns,
            )
        except (ConnectionRefusedError, OSError) as e:
            # Port closed / no HTTPS — report as a finding, not a tool failure
            no_https_vuln = Vulnerability(
                title="No HTTPS / SSL Not Available",
                severity=Severity.HIGH,
                tool=self.name,
                description=f"Port {port} is closed or not serving SSL/TLS on {target}",
                evidence=str(e),
                cwe_id="CWE-319",
                remediation="Deploy a TLS certificate and redirect all HTTP traffic to HTTPS",
            )
            return ToolResult(
                tool_name=self.name, success=True,
                data={"target": target, "port": port, "https_available": False},
                raw_output=f"SSL check for {target}:{port}: No HTTPS detected (port closed or not listening)",
                vulnerabilities=[no_https_vuln],
            )
        except Exception as e:
            return ToolResult(
                tool_name=self.name, success=False,
                error=f"Cannot establish SSL connection to {target}:{port}: {e}",
            )

        # Parse certificate info
        subject = dict(x[0] for x in cert.get("subject", []))
        issuer = dict(x[0] for x in cert.get("issuer", []))
        not_after = cert.get("notAfter", "")
        not_before = cert.get("notBefore", "")
        san = [entry[1] for entry in cert.get("subjectAltName", [])]

        # Check expiry
        expiry = datetime.datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z")
        days_left = (expiry - datetime.datetime.utcnow()).days

        if days_left < 0:
            vulns.append(Vulnerability(
                title="Expired SSL Certificate",
                severity=Severity.CRITICAL,
                tool=self.name,
                description=f"Certificate expired {abs(days_left)} days ago",
                evidence=f"Expiry: {not_after}",
                cwe_id="CWE-298",
                remediation="Renew the SSL certificate immediately",
            ))
        elif days_left < 30:
            vulns.append(Vulnerability(
                title="SSL Certificate Expiring Soon",
                severity=Severity.MEDIUM,
                tool=self.name,
                description=f"Certificate expires in {days_left} days",
                evidence=f"Expiry: {not_after}",
                cwe_id="CWE-298",
                remediation="Plan certificate renewal before expiry",
            ))

        # Check protocol
        weak_protocols = ["SSLv2", "SSLv3", "TLSv1", "TLSv1.1"]
        if protocol in weak_protocols:
            vulns.append(Vulnerability(
                title=f"Weak TLS Protocol: {protocol}",
                severity=Severity.HIGH,
                tool=self.name,
                description=f"Server uses deprecated protocol {protocol}",
                evidence=f"Negotiated protocol: {protocol}",
                cwe_id="CWE-326",
                remediation="Disable protocols below TLS 1.2",
            ))

        # Check cipher strength
        if cipher:
            cipher_name, _, bits = cipher
            if bits and bits < 128:
                vulns.append(Vulnerability(
                    title=f"Weak cipher: {cipher_name} ({bits} bits)",
                    severity=Severity.HIGH,
                    tool=self.name,
                    description="Cipher strength below 128 bits is considered weak",
                    evidence=f"Cipher: {cipher_name}, Bits: {bits}",
                    cwe_id="CWE-326",
                    remediation="Configure server to use strong ciphers (AES-256, ChaCha20)",
                ))

        data = {
            "target": target,
            "port": port,
            "valid": True,
            "subject": subject,
            "issuer": issuer,
            "protocol": protocol,
            "cipher": cipher[0] if cipher else "unknown",
            "bits": cipher[2] if cipher else 0,
            "not_before": not_before,
            "not_after": not_after,
            "days_until_expiry": days_left,
            "san": san,
        }

        cn = subject.get("commonName", "N/A")
        issuer_cn = issuer.get("commonName", "N/A")
        lines = [
            f"SSL/TLS check for {target}:{port}",
            f"  Subject: {cn}",
            f"  Issuer: {issuer_cn}",
            f"  Protocol: {protocol}",
            f"  Cipher: {cipher[0] if cipher else 'N/A'} ({cipher[2] if cipher else '?'} bits)",
            f"  Valid: {not_before} → {not_after} ({days_left} days left)",
            f"  SANs: {', '.join(san[:5])}{'...' if len(san) > 5 else ''}",
        ]

        return ToolResult(
            tool_name=self.name, success=True,
            data=data, raw_output="\n".join(lines),
            vulnerabilities=vulns,
        )
