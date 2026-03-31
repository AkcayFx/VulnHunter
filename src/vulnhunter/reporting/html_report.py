"""HTML report generator with embedded premium dark-theme styling."""
from __future__ import annotations

from pathlib import Path

from vulnhunter.models import ScanReport


def save_html_report(report: ScanReport, output_dir: str = "./reports") -> str:
    out = Path(output_dir)
    out.mkdir(parents=True, exist_ok=True)

    ts = report.timestamp.strftime("%Y%m%d_%H%M%S")
    filename = f"vulnhunter_{report.target.host}_{ts}.html"
    path = out / filename

    html = _build_html(report)
    path.write_text(html, encoding="utf-8")
    return str(path)


def _severity_color(severity: str) -> str:
    return {
        "critical": "#ff4444",
        "high": "#ff8c00",
        "medium": "#ffd700",
        "low": "#4fc3f7",
        "info": "#81c784",
    }.get(severity, "#888")


def _build_html(report: ScanReport) -> str:
    vuln_rows = ""
    for v in sorted(report.vulnerabilities, key=lambda x: ["critical","high","medium","low","info"].index(x.severity.value)):
        color = _severity_color(v.severity.value)
        vuln_rows += f"""
        <tr>
            <td><span class="badge" style="background:{color}">{v.severity.value.upper()}</span></td>
            <td>{v.title}</td>
            <td>{v.tool}</td>
            <td>{v.description}</td>
            <td><code>{v.cwe_id or 'N/A'}</code></td>
            <td>{v.remediation or 'N/A'}</td>
        </tr>"""

    tool_rows = ""
    for tr in report.tool_results:
        status = "OK" if tr.success else "FAIL"
        status_color = "#81c784" if tr.success else "#ff4444"
        tool_rows += f"""
        <tr>
            <td>{tr.tool_name}</td>
            <td><span style="color:{status_color}">{status}</span></td>
            <td>{len(tr.vulnerabilities)}</td>
            <td>{tr.duration_seconds:.1f}s</td>
            <td>{tr.error or '-'}</td>
        </tr>"""

    remediation_items = ""
    for i, step in enumerate(report.remediation_steps, 1):
        remediation_items += f"<li>{step}</li>\n"

    risk_color = "#ff4444" if report.risk_score >= 7 else "#ffd700" if report.risk_score >= 4 else "#81c784"

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>VulnHunter Report — {report.target.host}</title>
    <style>
        @import url('https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&family=JetBrains+Mono:wght@400;500&display=swap');
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        body {{
            font-family: 'Inter', sans-serif;
            background: #0a0a0f;
            color: #e0e0e0;
            line-height: 1.6;
        }}
        .container {{ max-width: 1200px; margin: 0 auto; padding: 24px; }}
        header {{
            background: linear-gradient(135deg, #1a1a2e 0%, #16213e 50%, #0f3460 100%);
            padding: 40px 0;
            border-bottom: 2px solid #e94560;
            margin-bottom: 32px;
        }}
        header h1 {{
            font-size: 2rem;
            font-weight: 700;
            background: linear-gradient(135deg, #e94560, #ff6b6b);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            margin-bottom: 8px;
        }}
        header .subtitle {{ color: #8892b0; font-size: 0.95rem; }}
        .meta-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 16px;
            margin-bottom: 32px;
        }}
        .meta-card {{
            background: #12121a;
            border: 1px solid #1e1e2e;
            border-radius: 12px;
            padding: 20px;
            text-align: center;
        }}
        .meta-card .label {{ font-size: 0.8rem; color: #8892b0; text-transform: uppercase; letter-spacing: 1px; }}
        .meta-card .value {{ font-size: 1.8rem; font-weight: 700; margin-top: 8px; }}
        .risk-score {{ color: {risk_color}; font-size: 2.5rem !important; }}
        .section {{
            background: #12121a;
            border: 1px solid #1e1e2e;
            border-radius: 12px;
            padding: 24px;
            margin-bottom: 24px;
        }}
        .section h2 {{
            font-size: 1.3rem;
            font-weight: 600;
            margin-bottom: 16px;
            padding-bottom: 12px;
            border-bottom: 1px solid #1e1e2e;
            color: #e94560;
        }}
        .summary-text {{ color: #b0b0b0; font-size: 1.05rem; line-height: 1.8; }}
        table {{ width: 100%; border-collapse: collapse; font-size: 0.9rem; }}
        th {{ background: #1a1a2e; color: #e94560; text-align: left; padding: 12px; font-weight: 600; }}
        td {{ padding: 12px; border-bottom: 1px solid #1e1e2e; }}
        tr:hover {{ background: #15152a; }}
        .badge {{
            padding: 4px 10px;
            border-radius: 6px;
            color: #fff;
            font-size: 0.75rem;
            font-weight: 600;
            text-transform: uppercase;
        }}
        code {{ font-family: 'JetBrains Mono', monospace; background: #1a1a2e; padding: 2px 6px; border-radius: 4px; font-size: 0.85rem; }}
        ol {{ padding-left: 24px; }}
        ol li {{ margin-bottom: 8px; color: #b0b0b0; }}
        .footer {{ text-align: center; color: #555; margin-top: 40px; font-size: 0.85rem; }}
    </style>
</head>
<body>
    <header>
        <div class="container">
            <h1>VulnHunter Security Report</h1>
            <p class="subtitle">Target: {report.target.host} | Scanned: {report.timestamp.strftime('%Y-%m-%d %H:%M:%S UTC')} | Duration: {report.total_duration_seconds:.1f}s</p>
        </div>
    </header>

    <div class="container">
        <div class="meta-grid">
            <div class="meta-card">
                <div class="label">Risk Score</div>
                <div class="value risk-score">{report.risk_score:.1f}</div>
            </div>
            <div class="meta-card">
                <div class="label">Threat Level</div>
                <div class="value">{report.threat_level}</div>
            </div>
            <div class="meta-card">
                <div class="label">Vulnerabilities</div>
                <div class="value">{report.total_vulns}</div>
            </div>
            <div class="meta-card">
                <div class="label">Tools Run</div>
                <div class="value">{len(report.tool_results)}</div>
            </div>
        </div>

        <div class="section">
            <h2>Executive Summary</h2>
            <p class="summary-text">{report.ai_summary or 'No AI summary available.'}</p>
        </div>

        <div class="section">
            <h2>Vulnerabilities ({report.total_vulns})</h2>
            <table>
                <thead><tr><th>Severity</th><th>Title</th><th>Tool</th><th>Description</th><th>CWE</th><th>Remediation</th></tr></thead>
                <tbody>{vuln_rows if vuln_rows else '<tr><td colspan="6" style="text-align:center;color:#666">No vulnerabilities found</td></tr>'}</tbody>
            </table>
        </div>

        <div class="section">
            <h2>Tool Results</h2>
            <table>
                <thead><tr><th>Tool</th><th>Status</th><th>Findings</th><th>Duration</th><th>Error</th></tr></thead>
                <tbody>{tool_rows}</tbody>
            </table>
        </div>

        {"<div class='section'><h2>Remediation Steps</h2><ol>" + remediation_items + "</ol></div>" if remediation_items else ""}

        <div class="footer">
            Generated by VulnHunter v1.0.0 — Autonomous AI Penetration Testing Platform
        </div>
    </div>
</body>
</html>"""
