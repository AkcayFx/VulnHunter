"""Severity justification generator for bug bounty submissions."""
from __future__ import annotations

from vulnhunter.models import Vulnerability


CIA_KEYWORDS: dict[str, dict[str, list[str]]] = {
    "confidentiality": {
        "high": ["data exfiltration", "credential", "password", "token", "secret", "pii", "metadata",
                 "database dump", "user data", "private", "api key", "session"],
        "low": ["information disclosure", "version", "technology", "stack trace", "debug", "path disclosure"],
    },
    "integrity": {
        "high": ["rce", "command injection", "code execution", "account takeover", "modify",
                 "write", "delete", "admin", "privilege escalation", "sql injection"],
        "low": ["xss", "reflected", "open redirect", "phishing"],
    },
    "availability": {
        "high": ["denial of service", "dos", "crash", "resource exhaustion", "infinite loop"],
        "low": ["rate limit", "slow"],
    },
}


class SeverityJustifier:
    """Generates the impact/severity justification that bounty programs require."""

    def justify(self, vuln: Vulnerability) -> str:
        text = f"{vuln.title} {vuln.description}".lower()
        cia = self._assess_cia(text)

        parts = [f"**Severity Assessment: {vuln.severity.value.upper()}**\n"]

        if cia["confidentiality"]:
            parts.append(f"- **Confidentiality Impact ({cia['confidentiality']}):** {self._confidentiality_text(cia['confidentiality'], text)}")
        if cia["integrity"]:
            parts.append(f"- **Integrity Impact ({cia['integrity']}):** {self._integrity_text(cia['integrity'], text)}")
        if cia["availability"]:
            parts.append(f"- **Availability Impact ({cia['availability']}):** {self._availability_text(cia['availability'], text)}")

        if vuln.cvss_score > 0:
            parts.append(f"\nCVSS Base Score: **{vuln.cvss_score:.1f}** — {self._score_label(vuln.cvss_score)}")

        return "\n".join(parts)

    @staticmethod
    def _assess_cia(text: str) -> dict[str, str]:
        result: dict[str, str] = {"confidentiality": "", "integrity": "", "availability": ""}
        for pillar, levels in CIA_KEYWORDS.items():
            for level in ("high", "low"):
                if any(kw in text for kw in levels[level]):
                    result[pillar] = level.upper()
                    break
        return result

    @staticmethod
    def _confidentiality_text(level: str, text: str) -> str:
        if level == "HIGH":
            if any(kw in text for kw in ("credential", "password", "token")):
                return "Attacker can access user credentials and authentication tokens, leading to mass account compromise."
            if any(kw in text for kw in ("database", "sql injection", "dump")):
                return "Attacker can extract database contents including user PII and sensitive records."
            return "Attacker can access sensitive data that should be restricted."
        return "Limited information exposure that may assist further attacks."

    @staticmethod
    def _integrity_text(level: str, text: str) -> str:
        if level == "HIGH":
            if any(kw in text for kw in ("rce", "command injection", "code execution")):
                return "Attacker can execute arbitrary code on the server, fully compromising application integrity."
            if any(kw in text for kw in ("admin", "privilege")):
                return "Attacker can perform privileged actions, modifying application configuration and user data."
            return "Attacker can modify data or application state in unauthorized ways."
        return "Limited ability to influence application behavior or data presentation."

    @staticmethod
    def _availability_text(level: str, text: str) -> str:
        if level == "HIGH":
            return "Attacker can disrupt service availability, causing downtime for legitimate users."
        return "Minor impact on service performance or availability."

    @staticmethod
    def _score_label(score: float) -> str:
        if score >= 9.0:
            return "Critical — immediate remediation required"
        if score >= 7.0:
            return "High — should be fixed in the next release cycle"
        if score >= 4.0:
            return "Medium — should be scheduled for remediation"
        if score >= 0.1:
            return "Low — fix when convenient"
        return "Informational"
