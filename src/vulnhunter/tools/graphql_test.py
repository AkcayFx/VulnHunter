"""GraphQL introspection and attack tool — discovers and tests GraphQL APIs.

GraphQL introspection left enabled is a common bug bounty finding.
Combined with authorization bypass, it can expose the entire API schema.
"""
from __future__ import annotations

import json
from typing import Any

import aiohttp

from vulnhunter.models import Severity, ToolResult, Vulnerability
from vulnhunter.tools.base import BaseTool

GRAPHQL_PATHS = [
    "/graphql", "/gql", "/api/graphql", "/api/gql",
    "/v1/graphql", "/v2/graphql", "/graphql/v1",
    "/query", "/api/query",
]

INTROSPECTION_QUERY = """
query IntrospectionQuery {
  __schema {
    queryType { name }
    mutationType { name }
    types {
      name
      kind
      fields {
        name
        type { name kind ofType { name kind } }
        args { name type { name kind } }
      }
    }
  }
}
"""

BATCH_QUERY = [
    {"query": "{ __typename }"},
    {"query": "{ __typename }"},
    {"query": "{ __typename }"},
]


class GraphQLTestTool(BaseTool):
    """Discover and test GraphQL endpoints for security issues."""

    @property
    def name(self) -> str:
        return "graphql_test"

    @property
    def description(self) -> str:
        return (
            "Discover GraphQL endpoints and test for security issues: "
            "introspection enabled (schema leak), batch query attacks, "
            "field suggestion exploitation, and authorization bypass on mutations. "
            "Extracts all types, queries, and mutations from the schema."
        )

    @property
    def parameters(self) -> dict[str, Any]:
        return {
            "type": "object",
            "properties": {
                "url": {
                    "type": "string",
                    "description": "Base URL (e.g., https://example.com) or direct GraphQL endpoint",
                },
                "endpoint": {
                    "type": "string",
                    "description": "Known GraphQL endpoint path (e.g., /graphql). If empty, auto-discovers.",
                    "default": "",
                },
            },
            "required": ["url"],
        }

    async def _execute(self, **kwargs: Any) -> ToolResult:
        url = kwargs["url"].rstrip("/")
        endpoint = kwargs.get("endpoint", "")

        if not url.startswith(("http://", "https://")):
            url = f"https://{url}"

        vulns: list[Vulnerability] = []
        findings: list[dict[str, Any]] = []

        # 1. Discover GraphQL endpoint
        gql_url = ""
        if endpoint:
            gql_url = f"{url}{endpoint}" if endpoint.startswith("/") else endpoint
        else:
            gql_url = await self._discover_endpoint(url)

        if not gql_url:
            return ToolResult(
                tool_name=self.name,
                success=True,
                data={"graphql_found": False},
                raw_output=f"No GraphQL endpoint found on {url}\nTested paths: {', '.join(GRAPHQL_PATHS)}",
            )

        findings.append({"type": "endpoint_found", "url": gql_url})

        # 2. Test introspection
        schema = await self._test_introspection(gql_url)
        if schema:
            types = schema.get("types", [])
            queries = []
            mutations = []
            sensitive_fields: list[str] = []

            for t in types:
                if t.get("name", "").startswith("__"):
                    continue
                fields = t.get("fields") or []

                if t.get("name") == schema.get("queryType", {}).get("name"):
                    queries = [f["name"] for f in fields]
                elif t.get("name") == schema.get("mutationType", {}).get("name"):
                    mutations = [f["name"] for f in fields]

                for f in fields:
                    fname = f["name"].lower()
                    if any(kw in fname for kw in ("password", "secret", "token", "key", "ssn", "credit")):
                        sensitive_fields.append(f"{t['name']}.{f['name']}")

            findings.append({
                "type": "introspection",
                "types_count": len([t for t in types if not t.get("name", "").startswith("__")]),
                "queries": queries,
                "mutations": mutations,
                "sensitive_fields": sensitive_fields,
            })

            vulns.append(Vulnerability(
                title="GraphQL Introspection Enabled",
                severity=Severity.MEDIUM,
                tool=self.name,
                description=(
                    f"GraphQL introspection is enabled at {gql_url}. "
                    f"Schema exposes {len(queries)} queries, {len(mutations)} mutations, "
                    f"and {len(types)} types. This leaks the entire API structure."
                ),
                evidence=(
                    f"Endpoint: {gql_url}\n"
                    f"Queries: {', '.join(queries[:10])}\n"
                    f"Mutations: {', '.join(mutations[:10])}"
                ),
                cwe_id="CWE-200",
                remediation="Disable introspection in production: set introspection: false in your GraphQL server config.",
            ))

            if sensitive_fields:
                vulns.append(Vulnerability(
                    title=f"Sensitive fields in GraphQL schema ({len(sensitive_fields)})",
                    severity=Severity.HIGH,
                    tool=self.name,
                    description=f"GraphQL schema contains sensitive field names: {', '.join(sensitive_fields[:10])}",
                    evidence="\n".join(sensitive_fields[:20]),
                    cwe_id="CWE-200",
                    remediation="Review and restrict access to sensitive fields via field-level authorization.",
                ))

        # 3. Test batch query support
        batch_supported = await self._test_batch_query(gql_url)
        if batch_supported:
            findings.append({"type": "batch_query", "supported": True})
            vulns.append(Vulnerability(
                title="GraphQL Batch Query Enabled",
                severity=Severity.LOW,
                tool=self.name,
                description=(
                    f"GraphQL endpoint {gql_url} accepts batch queries. "
                    f"This can be abused for brute-force attacks and rate limit bypass."
                ),
                evidence=f"Batch query accepted at {gql_url}",
                cwe_id="CWE-770",
                remediation="Limit batch query size or disable batch queries in production.",
            ))

        # 4. Test field suggestions (information disclosure)
        suggestions = await self._test_field_suggestions(gql_url)
        if suggestions:
            findings.append({"type": "field_suggestions", "fields": suggestions})
            vulns.append(Vulnerability(
                title="GraphQL Field Suggestions Enabled",
                severity=Severity.LOW,
                tool=self.name,
                description=(
                    f"GraphQL endpoint suggests field names on typos: {', '.join(suggestions[:5])}. "
                    f"Attackers can enumerate the schema even with introspection disabled."
                ),
                evidence=f"Suggested fields: {', '.join(suggestions[:10])}",
                cwe_id="CWE-200",
                remediation="Disable field suggestions in production GraphQL server config.",
            ))

        raw = f"GraphQL security test on {gql_url or url}\n"
        if gql_url:
            raw += f"  Endpoint: {gql_url}\n"
        if schema:
            raw += f"  Introspection: ENABLED (schema leaked)\n"
            raw += f"  Queries: {len(queries)}, Mutations: {len(mutations)}\n"
            if sensitive_fields:
                raw += f"  Sensitive fields: {', '.join(sensitive_fields[:5])}\n"
        if batch_supported:
            raw += f"  Batch queries: ENABLED\n"
        if suggestions:
            raw += f"  Field suggestions: ENABLED ({', '.join(suggestions[:3])})\n"
        if not findings:
            raw += "  No GraphQL security issues found.\n"

        return ToolResult(
            tool_name=self.name,
            success=True,
            data={
                "graphql_found": bool(gql_url),
                "introspection_enabled": bool(schema),
                "findings_count": len(vulns),
            },
            raw_output=raw,
            vulnerabilities=vulns,
        )

    async def _discover_endpoint(self, base_url: str) -> str:
        """Probe common GraphQL paths."""
        for path in GRAPHQL_PATHS:
            url = f"{base_url}{path}"
            try:
                async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=8)) as session:
                    async with session.post(
                        url,
                        json={"query": "{ __typename }"},
                        headers={"Content-Type": "application/json"},
                        ssl=False,
                    ) as resp:
                        if resp.status == 200:
                            body = await resp.text()
                            if "__typename" in body or "data" in body:
                                return url
            except Exception:
                pass
        return ""

    async def _test_introspection(self, gql_url: str) -> dict[str, Any] | None:
        """Run introspection query and return schema."""
        try:
            async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=15)) as session:
                async with session.post(
                    gql_url,
                    json={"query": INTROSPECTION_QUERY},
                    headers={"Content-Type": "application/json"},
                    ssl=False,
                ) as resp:
                    if resp.status == 200:
                        data = await resp.json(content_type=None)
                        schema = data.get("data", {}).get("__schema")
                        if schema and schema.get("types"):
                            return schema
        except Exception:
            pass
        return None

    async def _test_batch_query(self, gql_url: str) -> bool:
        """Test if batch queries are accepted."""
        try:
            async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=10)) as session:
                async with session.post(
                    gql_url,
                    json=BATCH_QUERY,
                    headers={"Content-Type": "application/json"},
                    ssl=False,
                ) as resp:
                    if resp.status == 200:
                        data = await resp.json(content_type=None)
                        return isinstance(data, list) and len(data) > 1
        except Exception:
            pass
        return False

    async def _test_field_suggestions(self, gql_url: str) -> list[str]:
        """Test if the server suggests fields on typos."""
        suggestions: list[str] = []
        typo_queries = [
            '{ usrs { id } }',
            '{ usr { id } }',
            '{ admi { id } }',
        ]
        for q in typo_queries:
            try:
                async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=8)) as session:
                    async with session.post(
                        gql_url,
                        json={"query": q},
                        headers={"Content-Type": "application/json"},
                        ssl=False,
                    ) as resp:
                        if resp.status == 200:
                            data = await resp.json(content_type=None)
                            errors = data.get("errors", [])
                            for err in errors:
                                msg = err.get("message", "")
                                if "did you mean" in msg.lower():
                                    import re
                                    suggested = re.findall(r'"(\w+)"', msg)
                                    suggestions.extend(suggested)
            except Exception:
                pass
        return list(dict.fromkeys(suggestions))
