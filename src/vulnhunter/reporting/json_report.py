"""JSON report generator."""
from __future__ import annotations

import json
from pathlib import Path
from datetime import datetime

from vulnhunter.models import ScanReport


def save_json_report(report: ScanReport, output_dir: str = "./reports") -> str:
    out = Path(output_dir)
    out.mkdir(parents=True, exist_ok=True)

    ts = report.timestamp.strftime("%Y%m%d_%H%M%S")
    filename = f"vulnhunter_{report.target.host}_{ts}.json"
    path = out / filename

    data = {
        "vulnhunter_version": "1.0.0",
        "target": report.target.host,
        "timestamp": report.timestamp.isoformat(),
        "risk_score": report.risk_score,
        "threat_level": report.threat_level,
        "executive_summary": report.ai_summary,
        "total_duration_seconds": round(report.total_duration_seconds, 2),
        "vulnerabilities": [
            {
                "title": v.title,
                "severity": v.severity.value,
                "tool": v.tool,
                "description": v.description,
                "evidence": v.evidence,
                "cwe_id": v.cwe_id,
                "cvss_score": v.cvss_score,
                "remediation": v.remediation,
            }
            for v in report.vulnerabilities
        ],
        "remediation_steps": report.remediation_steps,
        "tool_results": [
            {
                "tool": tr.tool_name,
                "success": tr.success,
                "duration": round(tr.duration_seconds, 2),
                "findings": len(tr.vulnerabilities),
                "error": tr.error,
            }
            for tr in report.tool_results
        ],
    }

    path.write_text(json.dumps(data, indent=2, ensure_ascii=False))
    return str(path)
