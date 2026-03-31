"""MITRE ATT&CK mapping for vulnerabilities and attack chains."""
from __future__ import annotations

from dataclasses import dataclass, field

from vulnhunter.models import Vulnerability

TECHNIQUE_MAP: dict[str, list[tuple[str, str, str]]] = {
    # CWE -> list of (technique_id, technique_name, tactic)
    "CWE-89":  [("T1190", "Exploit Public-Facing Application", "Initial Access")],
    "CWE-79":  [("T1189", "Drive-by Compromise", "Initial Access"),
                ("T1059.007", "JavaScript", "Execution")],
    "CWE-918": [("T1090", "Proxy", "Command and Control"),
                ("T1552.005", "Cloud Instance Metadata API", "Credential Access")],
    "CWE-601": [("T1566.002", "Spearphishing Link", "Initial Access")],
    "CWE-284": [("T1078", "Valid Accounts", "Persistence"),
                ("T1548", "Abuse Elevation Control Mechanism", "Privilege Escalation")],
    "CWE-522": [("T1110", "Brute Force", "Credential Access")],
    "CWE-200": [("T1005", "Data from Local System", "Collection"),
                ("T1530", "Data from Cloud Storage", "Collection")],
    "CWE-639": [("T1078", "Valid Accounts", "Persistence"),
                ("T1530", "Data from Cloud Storage", "Collection")],
    "CWE-644": [("T1557", "Adversary-in-the-Middle", "Credential Access"),
                ("T1040", "Network Sniffing", "Credential Access")],
    "CWE-352": [("T1185", "Browser Session Hijacking", "Collection")],
    "CWE-502": [("T1059", "Command and Scripting Interpreter", "Execution")],
    "CWE-611": [("T1005", "Data from Local System", "Collection")],
    "CWE-776": [("T1499", "Endpoint Denial of Service", "Impact")],
    "CWE-434": [("T1505.003", "Web Shell", "Persistence")],
    "CWE-22":  [("T1083", "File and Directory Discovery", "Discovery")],
    "CWE-78":  [("T1059", "Command and Scripting Interpreter", "Execution")],
    "CWE-770": [("T1499", "Endpoint Denial of Service", "Impact")],
    "CWE-295": [("T1557", "Adversary-in-the-Middle", "Credential Access")],
    "CWE-311": [("T1040", "Network Sniffing", "Credential Access")],
    "CWE-798": [("T1078.001", "Default Accounts", "Persistence")],
    "CWE-862": [("T1548", "Abuse Elevation Control Mechanism", "Privilege Escalation")],
    "CWE-863": [("T1548", "Abuse Elevation Control Mechanism", "Privilege Escalation")],
    "CWE-94":  [("T1059", "Command and Scripting Interpreter", "Execution")],
    "CWE-287": [("T1078", "Valid Accounts", "Persistence")],
    "CWE-306": [("T1078", "Valid Accounts", "Persistence")],
    "CWE-269": [("T1548", "Abuse Elevation Control Mechanism", "Privilege Escalation")],
    "CWE-732": [("T1222", "File and Directory Permissions Modification", "Defense Evasion")],
}

KEYWORD_TECHNIQUE_MAP: list[tuple[list[str], str, str, str]] = [
    (["ssrf", "server-side request forgery"], "T1090", "Proxy", "Command and Control"),
    (["sql injection", "sqli"], "T1190", "Exploit Public-Facing Application", "Initial Access"),
    (["xss", "cross-site scripting"], "T1189", "Drive-by Compromise", "Initial Access"),
    (["rce", "remote code execution", "command injection"], "T1059", "Command and Scripting Interpreter", "Execution"),
    (["subdomain takeover"], "T1584.001", "Domains", "Resource Development"),
    (["cors"], "T1557", "Adversary-in-the-Middle", "Credential Access"),
    (["idor", "insecure direct object"], "T1530", "Data from Cloud Storage", "Collection"),
    (["host header"], "T1557", "Adversary-in-the-Middle", "Credential Access"),
    (["access control", "authorization bypass", "403 bypass"], "T1548", "Abuse Elevation Control Mechanism", "Privilege Escalation"),
    (["graphql", "introspection"], "T1595.002", "Vulnerability Scanning", "Reconnaissance"),
    (["password reset", "account takeover"], "T1078", "Valid Accounts", "Persistence"),
    (["open redirect"], "T1566.002", "Spearphishing Link", "Initial Access"),
    (["sensitive data", "exposure", "information disclosure"], "T1005", "Data from Local System", "Collection"),
    (["default credential", "default login"], "T1078.001", "Default Accounts", "Persistence"),
    (["file upload"], "T1505.003", "Web Shell", "Persistence"),
    (["path traversal", "directory traversal", "lfi"], "T1083", "File and Directory Discovery", "Discovery"),
    (["deserialization"], "T1059", "Command and Scripting Interpreter", "Execution"),
    (["metadata", "aws", "cloud credential"], "T1552.005", "Cloud Instance Metadata API", "Credential Access"),
    (["brute force", "credential stuffing"], "T1110", "Brute Force", "Credential Access"),
    (["session hijack", "cookie theft"], "T1185", "Browser Session Hijacking", "Collection"),
]


@dataclass
class MitreTechnique:
    technique_id: str
    name: str
    tactic: str
    description: str = ""


class MitreMapper:
    """Maps vulnerabilities to MITRE ATT&CK techniques."""

    def map_vulnerability(self, vuln: Vulnerability) -> list[MitreTechnique]:
        techniques: list[MitreTechnique] = []
        seen: set[str] = set()

        if vuln.cwe_id and vuln.cwe_id in TECHNIQUE_MAP:
            for tid, tname, tactic in TECHNIQUE_MAP[vuln.cwe_id]:
                if tid not in seen:
                    techniques.append(MitreTechnique(tid, tname, tactic))
                    seen.add(tid)

        text = f"{vuln.title} {vuln.description}".lower()
        for keywords, tid, tname, tactic in KEYWORD_TECHNIQUE_MAP:
            if tid in seen:
                continue
            if any(kw in text for kw in keywords):
                techniques.append(MitreTechnique(tid, tname, tactic))
                seen.add(tid)

        return techniques

    def map_vulnerabilities(self, vulns: list[Vulnerability]) -> dict[str, list[MitreTechnique]]:
        result: dict[str, list[MitreTechnique]] = {}
        for vuln in vulns:
            techs = self.map_vulnerability(vuln)
            if techs:
                result[vuln.title] = techs
        return result

    def get_tactic_summary(self, vulns: list[Vulnerability]) -> dict[str, list[str]]:
        """Group all mapped techniques by tactic."""
        tactics: dict[str, list[str]] = {}
        for vuln in vulns:
            for tech in self.map_vulnerability(vuln):
                tactics.setdefault(tech.tactic, [])
                entry = f"{tech.technique_id}: {tech.name}"
                if entry not in tactics[tech.tactic]:
                    tactics[tech.tactic].append(entry)
        return tactics
