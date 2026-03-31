"""Enhanced Nuclei result parser with deduplication, CWE enrichment, and severity mapping."""
from __future__ import annotations

import json
from typing import Any

from vulnhunter.models import Severity, Vulnerability

SEVERITY_MAP: dict[str, Severity] = {
    "critical": Severity.CRITICAL,
    "high": Severity.HIGH,
    "medium": Severity.MEDIUM,
    "low": Severity.LOW,
    "info": Severity.INFO,
}

# Common Nuclei template-id prefixes → CWE mapping for enrichment
# when the template doesn't include its own CWE classification.
TEMPLATE_CWE_MAP: dict[str, str] = {
    "sqli": "CWE-89",
    "sql-injection": "CWE-89",
    "xss": "CWE-79",
    "cross-site-scripting": "CWE-79",
    "ssrf": "CWE-918",
    "open-redirect": "CWE-601",
    "lfi": "CWE-98",
    "rfi": "CWE-98",
    "rce": "CWE-94",
    "command-injection": "CWE-78",
    "path-traversal": "CWE-22",
    "directory-traversal": "CWE-22",
    "idor": "CWE-639",
    "cors": "CWE-942",
    "crlf": "CWE-93",
    "xxe": "CWE-611",
    "ssti": "CWE-1336",
    "deserialization": "CWE-502",
    "exposed-panel": "CWE-200",
    "default-login": "CWE-798",
    "default-credential": "CWE-798",
    "information-disclosure": "CWE-200",
    "directory-listing": "CWE-548",
    "backup-file": "CWE-530",
    "git-config": "CWE-538",
    "env-file": "CWE-538",
    "debug": "CWE-215",
    "takeover": "CWE-284",
    "subdomain-takeover": "CWE-284",
    "misconfig": "CWE-16",
    "misconfiguration": "CWE-16",
    "jwt": "CWE-347",
    "weak-crypto": "CWE-327",
    "csrf": "CWE-352",
    "upload": "CWE-434",
}


def parse_nuclei_results(output: str) -> list[NucleiResult]:
    """Parse raw Nuclei JSONL output into structured result objects."""
    results: list[NucleiResult] = []
    seen_keys: set[str] = set()

    for line in output.strip().splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            data = json.loads(line)
        except json.JSONDecodeError:
            continue

        result = NucleiResult.from_json(data)

        # Deduplicate by (template_id, matched_at) pair
        dedup_key = f"{result.template_id}::{result.matched_at}"
        if dedup_key in seen_keys:
            continue
        seen_keys.add(dedup_key)

        results.append(result)

    return results


def results_to_vulnerabilities(results: list[NucleiResult]) -> list[Vulnerability]:
    """Convert parsed Nuclei results into VulnHunter Vulnerability objects."""
    vulns: list[Vulnerability] = []
    for r in results:
        vulns.append(r.to_vulnerability())
    return vulns


def parse_and_convert(output: str) -> list[Vulnerability]:
    """One-step: parse JSONL → deduplicate → convert to Vulnerability list."""
    return results_to_vulnerabilities(parse_nuclei_results(output))


class NucleiResult:
    """Structured representation of a single Nuclei finding."""

    __slots__ = (
        "template_id", "name", "severity", "description", "matched_at",
        "extracted_results", "cwe_id", "cvss_score", "cvss_vector",
        "tags", "reference", "remediation", "curl_command", "raw",
    )

    def __init__(
        self,
        template_id: str = "",
        name: str = "",
        severity: Severity = Severity.INFO,
        description: str = "",
        matched_at: str = "",
        extracted_results: list[str] | None = None,
        cwe_id: str = "",
        cvss_score: float = 0.0,
        cvss_vector: str = "",
        tags: list[str] | None = None,
        reference: list[str] | None = None,
        remediation: str = "",
        curl_command: str = "",
        raw: dict[str, Any] | None = None,
    ):
        self.template_id = template_id
        self.name = name
        self.severity = severity
        self.description = description
        self.matched_at = matched_at
        self.extracted_results = extracted_results or []
        self.cwe_id = cwe_id
        self.cvss_score = cvss_score
        self.cvss_vector = cvss_vector
        self.tags = tags or []
        self.reference = reference or []
        self.remediation = remediation
        self.curl_command = curl_command
        self.raw = raw or {}

    @classmethod
    def from_json(cls, data: dict[str, Any]) -> NucleiResult:
        """Build from a single Nuclei JSON output line."""
        info = data.get("info", {})
        classification = info.get("classification", {})

        sev_str = info.get("severity", "info").lower()
        severity = SEVERITY_MAP.get(sev_str, Severity.INFO)

        # CWE: prefer classification, fall back to template-id heuristic
        cwe_ids = classification.get("cwe-id", [])
        cwe_id = str(cwe_ids[0]) if cwe_ids else ""
        if not cwe_id:
            cwe_id = _infer_cwe(data.get("template-id", ""), info.get("tags", []))

        cvss_score = 0.0
        try:
            cvss_score = float(classification.get("cvss-score", 0.0) or 0.0)
        except (ValueError, TypeError):
            pass

        curl_cmd = data.get("curl-command", "")

        return cls(
            template_id=data.get("template-id", ""),
            name=info.get("name", data.get("template-id", "Unknown")),
            severity=severity,
            description=info.get("description", ""),
            matched_at=data.get("matched-at", ""),
            extracted_results=data.get("extracted-results", []),
            cwe_id=cwe_id,
            cvss_score=cvss_score,
            cvss_vector=classification.get("cvss-metrics", ""),
            tags=info.get("tags", []),
            reference=info.get("reference", []),
            remediation=info.get("remediation", ""),
            curl_command=curl_cmd,
            raw=data,
        )

    def to_vulnerability(self) -> Vulnerability:
        """Convert to VulnHunter Vulnerability model."""
        evidence_parts = [f"Matched at: {self.matched_at}"]
        if self.extracted_results:
            evidence_parts.append(f"Extracted: {', '.join(self.extracted_results[:5])}")
        if self.curl_command:
            evidence_parts.append(f"PoC: {self.curl_command}")
        if self.reference:
            evidence_parts.append(f"References: {', '.join(self.reference[:3])}")

        return Vulnerability(
            title=self.name,
            severity=self.severity,
            tool="nuclei_scan",
            description=self.description or f"Detected by Nuclei template: {self.template_id}",
            evidence="\n".join(evidence_parts),
            cwe_id=self.cwe_id,
            cvss_score=self.cvss_score,
            cvss_vector=self.cvss_vector,
            remediation=self.remediation,
        )


def _infer_cwe(template_id: str, tags: list[str]) -> str:
    """Infer CWE from template ID or tags when classification is missing."""
    combined = template_id.lower()
    for tag in tags:
        combined += f" {tag.lower()}"

    for keyword, cwe in TEMPLATE_CWE_MAP.items():
        if keyword in combined:
            return cwe

    return ""
