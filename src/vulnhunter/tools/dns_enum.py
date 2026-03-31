"""DNS enumeration tool — discovers subdomains and DNS records."""
from __future__ import annotations

import socket
from typing import Any

from vulnhunter.models import ToolResult, Vulnerability, Severity
from vulnhunter.tools.base import BaseTool

try:
    import dns.resolver
    import dns.reversename
    import dns.zone
    import dns.query
    HAS_DNSPYTHON = True
except ImportError:
    HAS_DNSPYTHON = False

COMMON_SUBDOMAINS = [
    "www", "mail", "ftp", "admin", "api", "dev", "staging", "test",
    "blog", "shop", "app", "portal", "vpn", "remote", "webmail",
    "ns1", "ns2", "mx", "smtp", "pop", "imap", "cdn", "static",
    "media", "assets", "img", "images", "docs", "wiki", "git",
    "jenkins", "ci", "cd", "monitor", "grafana", "prometheus",
    "db", "database", "redis", "elastic", "kibana", "status",
]


class DNSEnumTool(BaseTool):
    @property
    def name(self) -> str:
        return "dns_enum"

    @property
    def description(self) -> str:
        return (
            "Enumerates DNS records (A, AAAA, MX, NS, TXT, CNAME) and discovers subdomains. "
            "Useful for mapping the target's infrastructure."
        )

    @property
    def parameters(self) -> dict[str, Any]:
        return {
            "type": "object",
            "properties": {
                "domain": {
                    "type": "string",
                    "description": "Target domain to enumerate (e.g., example.com)",
                },
                "check_subdomains": {
                    "type": "boolean",
                    "description": "Whether to bruteforce common subdomains",
                    "default": True,
                },
            },
            "required": ["domain"],
        }

    async def _execute(self, **kwargs: Any) -> ToolResult:
        domain = kwargs["domain"]
        check_subs = kwargs.get("check_subdomains", True)

        records: dict[str, list[str]] = {}
        vulns: list[Vulnerability] = []

        if HAS_DNSPYTHON:
            resolver = dns.resolver.Resolver()
            resolver.timeout = 5
            resolver.lifetime = 10

            # Query standard record types
            for rtype in ["A", "AAAA", "MX", "NS", "TXT", "CNAME", "SOA"]:
                try:
                    answers = resolver.resolve(domain, rtype)
                    records[rtype] = [str(r) for r in answers]
                except Exception:
                    pass

            # Check for zone transfer vulnerability
            if "NS" in records:
                for ns in records["NS"]:
                    try:
                        zone = dns.zone.from_xfr(dns.query.xfr(ns.rstrip('.'), domain, timeout=5))
                        if zone:
                            vulns.append(Vulnerability(
                                title="DNS Zone Transfer Allowed (AXFR)",
                                severity=Severity.HIGH,
                                tool=self.name,
                                description=f"Nameserver {ns} allows zone transfer, exposing all DNS records",
                                evidence=f"AXFR successful on {ns}",
                                cwe_id="CWE-200",
                                remediation="Restrict AXFR to authorized secondary nameservers only",
                            ))
                    except Exception:
                        pass
        else:
            # Fallback: basic socket resolution
            try:
                ips = socket.getaddrinfo(domain, None)
                records["A"] = list(set(addr[4][0] for addr in ips if addr[0] == socket.AF_INET))
                records["AAAA"] = list(set(addr[4][0] for addr in ips if addr[0] == socket.AF_INET6))
            except Exception:
                pass

        # Subdomain enumeration
        found_subdomains: list[dict[str, str]] = []
        if check_subs:
            for sub in COMMON_SUBDOMAINS:
                fqdn = f"{sub}.{domain}"
                try:
                    ip = socket.gethostbyname(fqdn)
                    found_subdomains.append({"subdomain": fqdn, "ip": ip})
                except socket.gaierror:
                    pass

        # Check SPF/DMARC
        txt_records = records.get("TXT", [])
        has_spf = any("v=spf1" in r for r in txt_records)
        has_dmarc = False
        if HAS_DNSPYTHON:
            try:
                dmarc_answers = dns.resolver.Resolver().resolve(f"_dmarc.{domain}", "TXT")
                has_dmarc = any("v=DMARC1" in str(r) for r in dmarc_answers)
            except Exception:
                pass

        if not has_spf:
            vulns.append(Vulnerability(
                title="Missing SPF Record",
                severity=Severity.MEDIUM,
                tool=self.name,
                description="No SPF record found — domain can be used for email spoofing",
                evidence=f"No TXT record with 'v=spf1' found for {domain}",
                cwe_id="CWE-290",
                remediation="Add an SPF TXT record (e.g., 'v=spf1 include:_spf.google.com ~all')",
            ))

        if not has_dmarc:
            vulns.append(Vulnerability(
                title="Missing DMARC Record",
                severity=Severity.MEDIUM,
                tool=self.name,
                description="No DMARC record found — no email authentication enforcement",
                evidence=f"No TXT record at _dmarc.{domain}",
                cwe_id="CWE-290",
                remediation="Add a DMARC TXT record at _dmarc.{domain}",
            ))

        lines = [f"DNS enumeration for {domain}"]
        for rtype, vals in records.items():
            lines.append(f"  {rtype}: {', '.join(vals[:5])}")
        if found_subdomains:
            lines.append(f"  Subdomains found: {len(found_subdomains)}")
            for s in found_subdomains[:10]:
                lines.append(f"    {s['subdomain']} → {s['ip']}")

        return ToolResult(
            tool_name=self.name, success=True,
            data={
                "domain": domain,
                "records": records,
                "subdomains": found_subdomains,
                "has_spf": has_spf,
                "has_dmarc": has_dmarc,
            },
            raw_output="\n".join(lines),
            vulnerabilities=vulns,
        )
