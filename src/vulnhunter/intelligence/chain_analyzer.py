"""Attack chain analyzer — correlates vulnerabilities into multi-step attack paths."""
from __future__ import annotations

import logging
from dataclasses import dataclass, field

from vulnhunter.intelligence.mitre_attack import MitreMapper, MitreTechnique
from vulnhunter.models import Severity, Vulnerability

logger = logging.getLogger("vulnhunter.intelligence")


@dataclass
class AttackChain:
    name: str
    steps: list[Vulnerability]
    impact: str
    combined_cvss: float = 0.0
    mitre_techniques: list[str] = field(default_factory=list)
    narrative: str = ""


CHAIN_RULES: list[dict] = [
    {
        "name": "SSRF → Cloud Credential Theft → Account Takeover",
        "requires": [["ssrf", "server-side request forgery"], ["metadata", "aws", "cloud", "169.254"]],
        "impact": "Attacker exploits SSRF to reach cloud metadata endpoint, steal IAM credentials, and take over cloud infrastructure.",
        "combined_cvss": 9.8,
    },
    {
        "name": "Subdomain Takeover → Phishing → Cookie Theft",
        "requires": [["subdomain takeover", "dangling cname"]],
        "extra_keywords": ["cookie", "session"],
        "impact": "Attacker claims an abandoned subdomain, hosts a phishing page on the trusted domain, and steals session cookies.",
        "combined_cvss": 9.1,
    },
    {
        "name": "Open Redirect → OAuth Token Theft → Account Takeover",
        "requires": [["open redirect", "redirect"]],
        "extra_keywords": ["oauth", "token", "login"],
        "impact": "Attacker uses open redirect to intercept OAuth callback, stealing access tokens and gaining full account access.",
        "combined_cvss": 8.6,
    },
    {
        "name": "XSS → CSRF Token Extraction → Admin Action Execution",
        "requires": [["xss", "cross-site scripting"]],
        "extra_keywords": ["admin", "csrf"],
        "impact": "Attacker uses XSS to extract CSRF tokens and execute privileged admin actions on behalf of the victim.",
        "combined_cvss": 8.8,
    },
    {
        "name": "SQL Injection → Data Exfiltration → Password Reuse → Admin Access",
        "requires": [["sql injection", "sqli"]],
        "impact": "Attacker dumps user credentials via SQL injection, then reuses passwords to access admin accounts.",
        "combined_cvss": 9.8,
    },
    {
        "name": "IDOR → Mass Data Exfiltration",
        "requires": [["idor", "insecure direct object"]],
        "impact": "Attacker enumerates sequential IDs to extract every user's private data from the API.",
        "combined_cvss": 8.5,
    },
    {
        "name": "GraphQL Introspection → Mutation Abuse → Privilege Escalation",
        "requires": [["graphql", "introspection"]],
        "extra_keywords": ["mutation", "admin"],
        "impact": "Attacker uses leaked schema to discover admin mutations, then invokes them without authorization.",
        "combined_cvss": 8.6,
    },
    {
        "name": "Host Header Poisoning → Password Reset Token Theft",
        "requires": [["host header", "password reset poisoning"]],
        "impact": "Attacker poisons the Host header to redirect password reset links to their server, stealing reset tokens.",
        "combined_cvss": 9.1,
    },
    {
        "name": "Broken Access Control → Admin Panel Takeover",
        "requires": [["access control", "admin", "403 bypass", "unauthenticated"]],
        "impact": "Attacker bypasses access controls to reach the admin panel and take full control of the application.",
        "combined_cvss": 9.1,
    },
    {
        "name": "CORS Misconfiguration → Cross-Origin Data Theft",
        "requires": [["cors", "misconfiguration", "reflects"]],
        "impact": "Attacker exploits permissive CORS policy to steal sensitive data cross-origin from authenticated users.",
        "combined_cvss": 7.5,
    },
    {
        "name": "JS Secrets Leak → API Key Abuse → Data Access",
        "requires": [["api key", "hardcoded secret", "bearer token", "secret"]],
        "impact": "Attacker extracts API keys from JavaScript files and uses them to access backend services.",
        "combined_cvss": 8.2,
    },
]

_SEVERITY_SCORE = {
    Severity.CRITICAL: 4.0,
    Severity.HIGH: 3.0,
    Severity.MEDIUM: 2.0,
    Severity.LOW: 1.0,
    Severity.INFO: 0.5,
}


class AttackChainAnalyzer:
    """Correlates vulnerabilities into multi-step attack chains using rule-based detection."""

    def __init__(self) -> None:
        self.mitre = MitreMapper()

    def analyze(self, vulns: list[Vulnerability]) -> list[AttackChain]:
        if not vulns:
            return []

        chains: list[AttackChain] = []
        all_text = " ".join(f"{v.title} {v.description} {v.evidence}" for v in vulns).lower()

        for rule in CHAIN_RULES:
            matched_vulns: list[Vulnerability] = []

            for keyword_group in rule["requires"]:
                for vuln in vulns:
                    vuln_text = f"{vuln.title} {vuln.description} {vuln.evidence}".lower()
                    if any(kw in vuln_text for kw in keyword_group):
                        if vuln not in matched_vulns:
                            matched_vulns.append(vuln)

            if not matched_vulns:
                continue

            # Check extra_keywords against the full corpus if defined
            extra = rule.get("extra_keywords", [])
            if extra and not any(ek in all_text for ek in extra):
                # Still create chain if primary vuln matched, extra is a bonus
                pass

            mitre_ids: list[str] = []
            for v in matched_vulns:
                for t in self.mitre.map_vulnerability(v):
                    if t.technique_id not in mitre_ids:
                        mitre_ids.append(t.technique_id)

            chain = AttackChain(
                name=rule["name"],
                steps=matched_vulns,
                impact=rule["impact"],
                combined_cvss=rule["combined_cvss"],
                mitre_techniques=mitre_ids,
                narrative=self._build_narrative(rule["name"], matched_vulns, rule["impact"]),
            )
            chains.append(chain)

        chains.sort(key=lambda c: c.combined_cvss, reverse=True)
        return chains

    def calculate_chain_impact(self, chain: AttackChain) -> float:
        """Combined score — always higher than any individual vuln in the chain."""
        individual_max = max((_SEVERITY_SCORE.get(v.severity, 1.0) for v in chain.steps), default=0)
        chain_bonus = len(chain.steps) * 0.5
        return min(individual_max + chain_bonus + 2.0, 10.0)

    @staticmethod
    def _build_narrative(name: str, vulns: list[Vulnerability], impact: str) -> str:
        steps = []
        for i, v in enumerate(vulns, 1):
            steps.append(f"Step {i}: Exploit {v.title} ({v.severity.value.upper()}) via {v.tool}")
        steps_text = "\n".join(steps)
        return f"Attack Chain: {name}\n\n{steps_text}\n\nImpact: {impact}"

    def generate_chain_summary(self, chains: list[AttackChain]) -> str:
        if not chains:
            return "No attack chains identified."

        lines = [f"## Attack Chain Analysis — {len(chains)} chain(s) identified\n"]
        for i, chain in enumerate(chains, 1):
            lines.append(f"### Chain {i}: {chain.name} (CVSS {chain.combined_cvss})")
            lines.append(f"**Impact:** {chain.impact}")
            lines.append(f"**Steps:** {len(chain.steps)} vulnerabilities chained")
            for j, v in enumerate(chain.steps, 1):
                lines.append(f"  {j}. [{v.severity.value.upper()}] {v.title}")
            if chain.mitre_techniques:
                lines.append(f"**MITRE ATT&CK:** {', '.join(chain.mitre_techniques)}")
            lines.append("")

        return "\n".join(lines)
