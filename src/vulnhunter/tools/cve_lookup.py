"""CVE lookup tool — queries public CVE databases for known vulnerabilities."""
from __future__ import annotations

from typing import Any

import aiohttp

from vulnhunter.models import ToolResult
from vulnhunter.tools.base import BaseTool


class CVELookupTool(BaseTool):
    @property
    def name(self) -> str:
        return "cve_lookup"

    @property
    def description(self) -> str:
        return (
            "Searches for known CVE vulnerabilities related to a specific software product, "
            "version, or keyword. Uses the cve.circl.lu public API."
        )

    @property
    def parameters(self) -> dict[str, Any]:
        return {
            "type": "object",
            "properties": {
                "keyword": {
                    "type": "string",
                    "description": "Product name or keyword to search for CVEs (e.g., 'apache 2.4', 'nginx', 'openssh 8.9')",
                },
                "max_results": {
                    "type": "integer",
                    "description": "Maximum number of CVEs to return",
                    "default": 10,
                },
            },
            "required": ["keyword"],
        }

    async def _execute(self, **kwargs: Any) -> ToolResult:
        keyword = kwargs["keyword"]
        max_results = int(kwargs.get("max_results", 10))

        # NVD API 2.0 — the authoritative public CVE database
        url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
        params = {"keywordSearch": keyword, "resultsPerPage": min(max_results, 20)}

        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(
                    url, params=params,
                    timeout=aiohttp.ClientTimeout(total=20),
                    headers={"User-Agent": "VulnHunter/1.0"},
                ) as resp:
                    if resp.status != 200:
                        return ToolResult(
                            tool_name=self.name, success=False,
                            error=f"NVD API returned status {resp.status}",
                        )
                    data = await resp.json()
        except Exception as e:
            return ToolResult(
                tool_name=self.name, success=False,
                error=f"CVE lookup failed: {e}",
            )

        vulnerabilities = data.get("vulnerabilities", [])
        total = data.get("totalResults", 0)

        if not vulnerabilities:
            return ToolResult(
                tool_name=self.name, success=True,
                data={"keyword": keyword, "cves": [], "total": 0},
                raw_output=f"No CVEs found for '{keyword}'",
            )

        cves = []
        for entry in vulnerabilities[:max_results]:
            cve_obj = entry.get("cve", {})
            cve_id = cve_obj.get("id", "N/A")

            # Extract English description
            descriptions = cve_obj.get("descriptions", [])
            summary = next(
                (d["value"] for d in descriptions if d.get("lang") == "en"),
                "No description",
            )[:200]

            # Extract CVSS score (prefer v3.1, fallback v3.0, then v2)
            metrics = cve_obj.get("metrics", {})
            cvss = "N/A"
            for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
                if key in metrics and metrics[key]:
                    cvss = metrics[key][0].get("cvssData", {}).get("baseScore", "N/A")
                    break

            published = cve_obj.get("published", "N/A")[:10]  # date only
            refs = [r["url"] for r in cve_obj.get("references", [])[:3]]

            cves.append({
                "id": cve_id,
                "summary": summary,
                "cvss": cvss,
                "published": published,
                "references": refs,
            })

        lines = [f"CVE lookup for '{keyword}': {len(cves)} results (of {total} total)"]
        for cve in cves:
            cvss_str = str(cve["cvss"]) if cve["cvss"] != "N/A" else "?"
            lines.append(f"  {cve['id']} (CVSS: {cvss_str}) — {cve['summary'][:100]}")

        return ToolResult(
            tool_name=self.name, success=True,
            data={"keyword": keyword, "cves": cves, "total": total},
            raw_output="\n".join(lines),
        )
