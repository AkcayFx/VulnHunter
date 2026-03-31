"""CI/CD output formats — SARIF for GitHub Security tab, JSON summary for pipelines."""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from vulnhunter.models import ScanReport


def generate_sarif(report: ScanReport) -> dict[str, Any]:
    """Generate SARIF v2.1.0 output for GitHub Security tab integration."""
    rules: list[dict] = []
    results: list[dict] = []
    seen_rules: set[str] = set()

    for vuln in report.vulnerabilities:
        rule_id = vuln.cwe_id or f"vulnhunter-{vuln.tool}-{vuln.severity.value}"

        if rule_id not in seen_rules:
            seen_rules.add(rule_id)
            rules.append({
                "id": rule_id,
                "name": vuln.title[:100],
                "shortDescription": {"text": vuln.title},
                "fullDescription": {"text": vuln.description[:500]},
                "help": {"text": vuln.remediation or "Review and remediate this finding."},
                "defaultConfiguration": {
                    "level": _sarif_level(vuln.severity.value),
                },
                "properties": {
                    "tags": ["security", vuln.severity.value, vuln.tool],
                },
            })

        result: dict[str, Any] = {
            "ruleId": rule_id,
            "level": _sarif_level(vuln.severity.value),
            "message": {"text": vuln.description},
            "locations": [
                {
                    "physicalLocation": {
                        "artifactLocation": {
                            "uri": report.target.host,
                            "uriBaseId": "TARGET",
                        },
                    },
                },
            ],
            "properties": {
                "tool": vuln.tool,
                "cvss_score": vuln.cvss_score,
                "cwe_id": vuln.cwe_id,
            },
        }

        if vuln.evidence:
            result["codeFlows"] = [
                {
                    "message": {"text": "Evidence"},
                    "threadFlows": [
                        {
                            "locations": [
                                {
                                    "location": {
                                        "message": {"text": vuln.evidence[:500]},
                                        "physicalLocation": {
                                            "artifactLocation": {"uri": report.target.host},
                                        },
                                    },
                                },
                            ],
                        },
                    ],
                },
            ]

        results.append(result)

    return {
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "VulnHunter",
                        "version": "2.0.0",
                        "informationUri": "https://github.com/vulnhunter/vulnhunter",
                        "rules": rules,
                    },
                },
                "results": results,
                "invocations": [
                    {
                        "executionSuccessful": True,
                        "properties": {
                            "target": report.target.host,
                            "risk_score": report.risk_score,
                            "threat_level": report.threat_level,
                            "total_vulns": report.total_vulns,
                            "duration_seconds": report.total_duration_seconds,
                        },
                    },
                ],
            },
        ],
    }


def generate_ci_summary(report: ScanReport) -> dict[str, Any]:
    """Generate a concise JSON summary for CI pipeline consumption."""
    return {
        "target": report.target.host,
        "risk_score": report.risk_score,
        "threat_level": report.threat_level,
        "total_vulnerabilities": report.total_vulns,
        "vuln_counts": report.vuln_counts,
        "duration_seconds": round(report.total_duration_seconds, 2),
        "attack_chains": len(report.attack_chains),
        "pass": True,  # Will be overridden by CLI based on --fail-on
        "vulnerabilities": [
            {
                "title": v.title,
                "severity": v.severity.value,
                "tool": v.tool,
                "cwe_id": v.cwe_id,
                "cvss_score": v.cvss_score,
            }
            for v in report.vulnerabilities
        ],
    }


def save_sarif(report: ScanReport, output_path: str | Path) -> str:
    """Save SARIF report to a file."""
    path = Path(output_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    sarif = generate_sarif(report)
    path.write_text(json.dumps(sarif, indent=2), encoding="utf-8")
    return str(path)


def _sarif_level(severity: str) -> str:
    mapping = {
        "critical": "error",
        "high": "error",
        "medium": "warning",
        "low": "note",
        "info": "note",
    }
    return mapping.get(severity.lower(), "note")
