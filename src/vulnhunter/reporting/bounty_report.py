"""Bug bounty report generator — HackerOne / Bugcrowd submission-ready markdown."""
from __future__ import annotations

from vulnhunter.models import AttackChain, Vulnerability
from vulnhunter.reporting.severity_justification import SeverityJustifier


class BountyReportGenerator:
    """Generate platform-specific bug bounty submission reports."""

    def __init__(self) -> None:
        self.justifier = SeverityJustifier()

    def generate_hackerone(
        self, vuln: Vulnerability, chain: AttackChain | None = None,
    ) -> str:
        severity_justification = self.justifier.justify(vuln)
        poc = self.generate_poc(vuln)

        sections = [
            f"## Summary\n\n{vuln.title}\n",
            f"## Vulnerability Type\n\n{vuln.cwe_id or 'N/A'}\n",
            f"## Severity\n\n**CVSS Score:** {vuln.cvss_score:.1f}",
            f"**CVSS Vector:** `{vuln.cvss_vector}`" if vuln.cvss_vector else "",
            f"\n{severity_justification}\n",
            f"## Description\n\n{vuln.description}\n",
            self._steps_to_reproduce(vuln),
            f"## Impact\n\n{self._impact_statement(vuln, chain)}\n",
        ]

        if chain:
            chain_text = f"## Attack Chain\n\n**{chain.name}** (Combined CVSS: {chain.combined_cvss})\n\n"
            for i, step in enumerate(chain.steps, 1):
                chain_text += f"{i}. [{step.severity.value.upper()}] {step.title}\n"
            chain_text += f"\n{chain.impact}\n"
            if chain.mitre_techniques:
                chain_text += f"\n**MITRE ATT&CK:** {', '.join(chain.mitre_techniques)}\n"
            sections.append(chain_text)

        sections.append(f"## Proof of Concept\n\n{poc['curl']}\n")

        if vuln.remediation:
            sections.append(f"## Remediation\n\n{vuln.remediation}\n")

        sections.append(
            "## Supporting Material/References\n\n"
            f"- Tool: {vuln.tool}\n"
            f"- CWE: {vuln.cwe_id or 'N/A'}\n"
        )

        return "\n".join(s for s in sections if s)

    def generate_bugcrowd(
        self, vuln: Vulnerability, chain: AttackChain | None = None,
    ) -> str:
        poc = self.generate_poc(vuln)
        severity_justification = self.justifier.justify(vuln)

        sections = [
            f"# {vuln.title}\n",
            f"**Severity:** {vuln.severity.value.upper()} | "
            f"**CVSS:** {vuln.cvss_score:.1f} | "
            f"**CWE:** {vuln.cwe_id or 'N/A'}\n",
            f"## Overview\n\n{vuln.description}\n",
            f"## Severity Justification\n\n{severity_justification}\n",
            self._steps_to_reproduce(vuln),
            f"## Proof of Concept\n\n```bash\n{poc['curl_raw']}\n```\n",
            f"## Business Impact\n\n{self._impact_statement(vuln, chain)}\n",
        ]

        if vuln.remediation:
            sections.append(f"## Suggested Fix\n\n{vuln.remediation}\n")

        return "\n".join(sections)

    def generate_poc(self, vuln: Vulnerability) -> dict[str, str]:
        """Generate proof-of-concept in curl and Python formats."""
        evidence = vuln.evidence or ""
        url = ""
        for line in evidence.split("\n"):
            if line.strip().lower().startswith(("url:", "http://", "https://")):
                url = line.replace("URL:", "").replace("url:", "").strip()
                break

        if not url:
            url = "https://TARGET/ENDPOINT"

        curl_cmd = f'curl -v "{url}"'
        if "POST" in evidence.upper():
            curl_cmd = f'curl -v -X POST "{url}" -H "Content-Type: application/json"'
        if "host header" in vuln.title.lower():
            curl_cmd = f'curl -v "{url}" -H "Host: evil.attacker.com"'
        if "cors" in vuln.title.lower():
            curl_cmd = f'curl -v "{url}" -H "Origin: https://evil.attacker.com"'
        if "ssrf" in vuln.title.lower():
            curl_cmd = f'curl -v "{url}?url=http://169.254.169.254/latest/meta-data/"'

        python_script = (
            "import requests\n\n"
            f"url = \"{url}\"\n"
            f"# {vuln.title}\n"
            "response = requests.get(url, verify=False)\n"
            "print(f'Status: {response.status_code}')\n"
            "print(response.text[:500])\n"
        )

        return {
            "curl": f"```bash\n{curl_cmd}\n```",
            "curl_raw": curl_cmd,
            "python": f"```python\n{python_script}```",
        }

    @staticmethod
    def _steps_to_reproduce(vuln: Vulnerability) -> str:
        evidence = vuln.evidence or ""
        steps = "## Steps to Reproduce\n\n"
        steps += f"1. Navigate to the target application\n"

        if "parameter" in evidence.lower() or "param" in vuln.description.lower():
            steps += f"2. Identify the vulnerable parameter in the request\n"
            steps += f"3. Inject the payload as described in the evidence\n"
        elif "endpoint" in evidence.lower() or "url" in evidence.lower():
            steps += f"2. Send a request to the vulnerable endpoint\n"
            steps += f"3. Observe the vulnerable response\n"
        else:
            steps += f"2. Reproduce the vulnerability as described below\n"

        steps += f"4. Observe the result confirming the vulnerability\n"

        if evidence:
            steps += f"\n**Evidence:**\n```\n{evidence[:1000]}\n```\n"

        return steps

    @staticmethod
    def _impact_statement(vuln: Vulnerability, chain: AttackChain | None) -> str:
        impacts: dict[str, str] = {
            "critical": "This vulnerability poses an immediate, critical risk to the application and its users. "
                        "Exploitation could lead to complete system compromise, mass data breach, or full account takeover.",
            "high": "This vulnerability presents a significant security risk. "
                    "An attacker could exploit it to access sensitive data, modify critical records, or escalate privileges.",
            "medium": "This vulnerability has a moderate security impact. "
                      "While exploitation requires specific conditions, it could lead to data exposure or functionality abuse.",
            "low": "This vulnerability has limited direct impact but could be chained with other findings "
                   "to create a more severe attack path.",
        }

        statement = impacts.get(vuln.severity.value, "This vulnerability should be reviewed and addressed.")

        if chain:
            statement += (
                f"\n\n**Chain Amplification:** When combined in the attack chain "
                f"\"{chain.name}\" (CVSS {chain.combined_cvss}), the impact is significantly elevated: "
                f"{chain.impact}"
            )

        return statement
