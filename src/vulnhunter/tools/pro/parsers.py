"""Output parsers for professional pentesting tools."""
from __future__ import annotations

import json
import re
import xml.etree.ElementTree as ET
from typing import Any

from vulnhunter.models import Severity, Vulnerability


def parse_nmap_xml(xml_str: str) -> list[dict[str, Any]]:
    """Parse Nmap XML output into structured port/service data."""
    results: list[dict[str, Any]] = []
    try:
        root = ET.fromstring(xml_str)
    except ET.ParseError:
        return results

    for host_el in root.findall(".//host"):
        addr_el = host_el.find("address")
        addr = addr_el.get("addr", "") if addr_el is not None else ""

        for port_el in host_el.findall(".//port"):
            state_el = port_el.find("state")
            service_el = port_el.find("service")
            port_data: dict[str, Any] = {
                "host": addr,
                "port": int(port_el.get("portid", "0")),
                "protocol": port_el.get("protocol", "tcp"),
                "state": state_el.get("state", "unknown") if state_el is not None else "unknown",
                "service": service_el.get("name", "") if service_el is not None else "",
                "version": "",
                "scripts": [],
            }
            if service_el is not None:
                product = service_el.get("product", "")
                version = service_el.get("version", "")
                port_data["version"] = f"{product} {version}".strip()

            for script_el in port_el.findall("script"):
                port_data["scripts"].append({
                    "id": script_el.get("id", ""),
                    "output": script_el.get("output", ""),
                })
            results.append(port_data)

    return results


def parse_nuclei_jsonl(output: str) -> list[Vulnerability]:
    """Parse Nuclei JSONL output into Vulnerability objects."""
    vulns: list[Vulnerability] = []
    severity_map = {
        "critical": Severity.CRITICAL,
        "high": Severity.HIGH,
        "medium": Severity.MEDIUM,
        "low": Severity.LOW,
        "info": Severity.INFO,
    }

    for line in output.strip().splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            finding = json.loads(line)
        except json.JSONDecodeError:
            continue

        info = finding.get("info", {})
        sev_str = info.get("severity", "info").lower()
        severity = severity_map.get(sev_str, Severity.INFO)

        classification = info.get("classification", {})
        cwe_ids = classification.get("cwe-id", [])
        cwe_id = cwe_ids[0] if cwe_ids else ""
        cvss_score = float(classification.get("cvss-score", 0.0) or 0.0)

        vulns.append(Vulnerability(
            title=info.get("name", finding.get("template-id", "Unknown")),
            severity=severity,
            tool="nuclei_scan",
            description=info.get("description", ""),
            evidence=finding.get("matched-at", ""),
            cwe_id=str(cwe_id),
            cvss_score=cvss_score,
            remediation=info.get("remediation", ""),
        ))

    return vulns


def parse_ffuf_json(output: str) -> list[dict[str, Any]]:
    """Parse ffuf JSON output into discovered paths."""
    results: list[dict[str, Any]] = []
    try:
        data = json.loads(output)
    except json.JSONDecodeError:
        return results

    for result in data.get("results", []):
        results.append({
            "url": result.get("url", ""),
            "status": result.get("status", 0),
            "length": result.get("length", 0),
            "words": result.get("words", 0),
            "lines": result.get("lines", 0),
            "input": result.get("input", {}).get("FUZZ", ""),
        })
    return results


def parse_sqlmap_output(output: str) -> list[Vulnerability]:
    """Parse sqlmap text output into Vulnerability objects."""
    vulns: list[Vulnerability] = []

    # sqlmap reports injection points with lines like:
    # Parameter: id (GET)
    #     Type: boolean-based blind
    #     Title: AND boolean-based blind - WHERE or HAVING clause
    param_pattern = re.compile(r"Parameter:\s+(\S+)\s+\((\w+)\)")
    type_pattern = re.compile(r"Type:\s+(.+)")
    title_pattern = re.compile(r"Title:\s+(.+)")

    current_param = ""
    current_method = ""

    for line in output.splitlines():
        param_match = param_pattern.search(line)
        if param_match:
            current_param = param_match.group(1)
            current_method = param_match.group(2)
            continue

        title_match = title_pattern.search(line)
        if title_match and current_param:
            vulns.append(Vulnerability(
                title=f"SQL Injection — {title_match.group(1).strip()}",
                severity=Severity.CRITICAL,
                tool="sqlmap_scan",
                description=f"SQL injection found in parameter '{current_param}' ({current_method})",
                evidence=f"Parameter: {current_param} ({current_method})",
                cwe_id="CWE-89",
                remediation="Use parameterized queries or prepared statements.",
            ))

    return vulns


def parse_nikto_json(output: str) -> list[Vulnerability]:
    """Parse Nikto JSON output into Vulnerability objects."""
    vulns: list[Vulnerability] = []
    try:
        data = json.loads(output)
    except json.JSONDecodeError:
        return vulns

    items = data.get("vulnerabilities", data.get("items", []))
    if isinstance(data, list):
        items = data

    for item in items:
        if isinstance(item, dict):
            osvdb_id = item.get("OSVDB", item.get("id", ""))
            vulns.append(Vulnerability(
                title=item.get("msg", item.get("description", "Nikto finding")),
                severity=Severity.MEDIUM,
                tool="nikto_scan",
                description=item.get("msg", item.get("description", "")),
                evidence=f"OSVDB-{osvdb_id}" if osvdb_id else "",
                remediation="Review and remediate the identified issue.",
            ))

    return vulns


def parse_httpx_jsonl(output: str) -> list[dict[str, Any]]:
    """Parse httpx JSONL output into live host data."""
    hosts: list[dict[str, Any]] = []
    for line in output.strip().splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            data = json.loads(line)
        except json.JSONDecodeError:
            continue
        hosts.append({
            "url": data.get("url", ""),
            "status_code": data.get("status_code", 0),
            "title": data.get("title", ""),
            "tech": data.get("tech", []),
            "content_length": data.get("content_length", 0),
            "webserver": data.get("webserver", ""),
            "host": data.get("host", ""),
        })
    return hosts


def parse_subfinder_jsonl(output: str) -> list[str]:
    """Parse subfinder JSONL output into a list of subdomains."""
    subdomains: list[str] = []
    for line in output.strip().splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            data = json.loads(line)
            host = data.get("host", line)
        except json.JSONDecodeError:
            host = line
        if host and host not in subdomains:
            subdomains.append(host)
    return subdomains


def parse_katana_jsonl(output: str) -> list[dict[str, Any]]:
    """Parse katana JSONL output into discovered endpoints."""
    endpoints: list[dict[str, Any]] = []
    for line in output.strip().splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            data = json.loads(line)
        except json.JSONDecodeError:
            endpoints.append({"url": line})
            continue
        endpoints.append({
            "url": data.get("request", {}).get("endpoint", data.get("url", line)),
            "method": data.get("request", {}).get("method", "GET"),
            "source": data.get("source", ""),
            "tag": data.get("tag", ""),
        })
    return endpoints
