"""Reporting module for VulnHunter."""
from vulnhunter.reporting.json_report import save_json_report
from vulnhunter.reporting.html_report import save_html_report
from vulnhunter.reporting.cvss import (
    CVSSVector,
    calculate_base_score,
    score_to_severity,
    estimate_vector_from_vuln,
)

__all__ = [
    "save_json_report",
    "save_html_report",
    "generate_pdf",
    "CVSSVector",
    "calculate_base_score",
    "score_to_severity",
    "estimate_vector_from_vuln",
    "BountyReportGenerator",
    "SeverityJustifier",
]


def __getattr__(name: str):
    if name == "generate_pdf":
        from vulnhunter.reporting.pdf_report import generate_pdf
        return generate_pdf
    if name == "BountyReportGenerator":
        from vulnhunter.reporting.bounty_report import BountyReportGenerator
        return BountyReportGenerator
    if name == "SeverityJustifier":
        from vulnhunter.reporting.severity_justification import SeverityJustifier
        return SeverityJustifier
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
