"""Subdomain takeover checker — detects dangling CNAMEs pointing to decommissioned services."""
from __future__ import annotations

import asyncio
from typing import Any

import aiohttp
import dns.asyncresolver

from vulnhunter.models import Severity, ToolResult, Vulnerability
from vulnhunter.tools.base import BaseTool

# Fingerprints: service CNAME pattern -> (response fingerprint, service name)
TAKEOVER_FINGERPRINTS: list[tuple[str, str, str]] = [
    ("github.io", "There isn't a GitHub Pages site here", "GitHub Pages"),
    ("herokuapp.com", "No such app", "Heroku"),
    ("s3.amazonaws.com", "NoSuchBucket", "AWS S3"),
    ("cloudfront.net", "Bad Request", "AWS CloudFront"),
    ("azurewebsites.net", "404 Web Site not found", "Azure Web Apps"),
    ("blob.core.windows.net", "BlobNotFound", "Azure Blob Storage"),
    ("trafficmanager.net", "404 Not Found", "Azure Traffic Manager"),
    ("shopify.com", "Sorry, this shop is currently unavailable", "Shopify"),
    ("wpengine.com", "The site you were looking for couldn't be found", "WP Engine"),
    ("pantheon.io", "The gods are wise", "Pantheon"),
    ("ghost.io", "The thing you were looking for is no longer here", "Ghost"),
    ("surge.sh", "project not found", "Surge.sh"),
    ("bitbucket.io", "Repository not found", "Bitbucket"),
    ("zendesk.com", "Help Center Closed", "Zendesk"),
    ("teamwork.com", "Oops - We didn't find your site", "Teamwork"),
    ("helpjuice.com", "We could not find what you're looking for", "Helpjuice"),
    ("helpscoutdocs.com", "No settings were found for this company", "HelpScout"),
    ("cargo.site", "If you're moving your domain away from Cargo", "Cargo"),
    ("statuspage.io", "You are being redirected", "Statuspage"),
    ("tumblr.com", "There's nothing here", "Tumblr"),
    ("wordpress.com", "Do you want to register", "WordPress.com"),
    ("smartjob", "Job Board Is Unavailable", "Smartjobboard"),
    ("tictail.com", "to target URL: <a href=\"https://tictail.com", "Tictail"),
    ("strikingly.com", "But if you're looking to build your own website", "Strikingly"),
    ("fly.io", "404 Not Found", "Fly.io"),
    ("vercel.app", "NOT_FOUND", "Vercel"),
    ("netlify.app", "Not Found", "Netlify"),
    ("ngrok.io", "Tunnel .* not found", "Ngrok"),
    ("readme.io", "Project doesnt exist", "Readme.io"),
    ("gitbook.io", "noopener noreferrer", "GitBook"),
]


class SubdomainTakeoverTool(BaseTool):
    """Check subdomains for potential takeover via dangling CNAME records."""

    @property
    def name(self) -> str:
        return "takeover_check"

    @property
    def description(self) -> str:
        return (
            "Check a list of subdomains for potential subdomain takeover vulnerabilities. "
            "Resolves CNAME records and checks if they point to decommissioned services "
            "(GitHub Pages, Heroku, AWS S3, etc.). Subdomain takeover = instant Critical finding."
        )

    @property
    def parameters(self) -> dict[str, Any]:
        return {
            "type": "object",
            "properties": {
                "subdomains": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "List of subdomains to check (e.g., ['blog.example.com', 'status.example.com'])",
                },
            },
            "required": ["subdomains"],
        }

    async def _execute(self, **kwargs: Any) -> ToolResult:
        subdomains = kwargs["subdomains"]
        vulns: list[Vulnerability] = []
        checked = 0
        cname_found = 0

        resolver = dns.asyncresolver.Resolver()
        resolver.timeout = 5
        resolver.lifetime = 10

        async def check_one(subdomain: str) -> dict[str, Any] | None:
            nonlocal checked, cname_found
            checked += 1
            try:
                answers = await resolver.resolve(subdomain, "CNAME")
            except Exception:
                return None

            for rdata in answers:
                cname = str(rdata.target).rstrip(".")
                cname_found += 1

                # Check fingerprints
                for pattern, fingerprint, service in TAKEOVER_FINGERPRINTS:
                    if pattern in cname:
                        # Verify by fetching
                        body = await self._fetch_body(subdomain)
                        if fingerprint.lower() in body.lower():
                            return {
                                "subdomain": subdomain,
                                "cname": cname,
                                "service": service,
                                "fingerprint": fingerprint,
                                "vulnerable": True,
                            }
            return None

        # Check in batches of 10
        results: list[dict[str, Any]] = []
        for i in range(0, len(subdomains), 10):
            batch = subdomains[i:i + 10]
            batch_results = await asyncio.gather(*[check_one(sd) for sd in batch], return_exceptions=True)
            for r in batch_results:
                if isinstance(r, dict) and r.get("vulnerable"):
                    results.append(r)
                    vulns.append(Vulnerability(
                        title=f"Subdomain Takeover: {r['subdomain']} ({r['service']})",
                        severity=Severity.CRITICAL,
                        tool=self.name,
                        description=(
                            f"Subdomain {r['subdomain']} has a CNAME pointing to {r['cname']} "
                            f"({r['service']}), but the service appears unclaimed. "
                            f"An attacker can register this service and serve content on {r['subdomain']}."
                        ),
                        evidence=f"CNAME: {r['cname']}, Fingerprint: {r['fingerprint']}",
                        cwe_id="CWE-284",
                        remediation=f"Remove the DNS CNAME record for {r['subdomain']} or reclaim the {r['service']} resource.",
                    ))

        raw = f"Checked {checked} subdomains, {cname_found} had CNAME records\n"
        if results:
            raw += f"VULNERABLE: {len(results)} potential takeovers:\n"
            for r in results:
                raw += f"  {r['subdomain']} -> {r['cname']} ({r['service']})\n"
        else:
            raw += "No takeover vulnerabilities found.\n"

        return ToolResult(
            tool_name=self.name,
            success=True,
            data={"vulnerable": results, "checked": checked, "cname_count": cname_found},
            raw_output=raw,
            vulnerabilities=vulns,
        )

    @staticmethod
    async def _fetch_body(host: str) -> str:
        """Fetch HTTP body for fingerprint matching."""
        for scheme in ("https", "http"):
            try:
                async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=10)) as session:
                    async with session.get(f"{scheme}://{host}", ssl=False) as resp:
                        return await resp.text(errors="replace")
            except Exception:
                continue
        return ""
