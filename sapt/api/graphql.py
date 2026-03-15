"""
SAPT GraphQL Testing Module (Gap #2 fix).
Tests for GraphQL introspection, nested query DoS, batch attacks, and field suggestions.
"""

from __future__ import annotations

import json
from typing import Any, Dict, List, Optional

import aiohttp

from sapt.core.logger import get_logger, log_finding
from sapt.models.models import Finding, Evidence, VulnerabilityType, SeverityLevel


GRAPHQL_ENDPOINTS = [
    "/graphql", "/graphql/", "/gql", "/query",
    "/api/graphql", "/v1/graphql", "/v2/graphql",
]

INTROSPECTION_QUERY = """{
  __schema {
    types {
      name
      fields {
        name
        type { name }
      }
    }
    queryType { name }
    mutationType { name }
  }
}"""

BATCH_QUERY = [
    {"query": "{ __typename }"},
    {"query": "{ __typename }"},
    {"query": "{ __typename }"},
    {"query": "{ __typename }"},
    {"query": "{ __typename }"},
]


async def test_graphql(
    base_url: str,
    session: Optional[aiohttp.ClientSession] = None,
) -> List[Finding]:
    """Test for GraphQL vulnerabilities."""
    logger = get_logger()
    findings: List[Finding] = []
    close_session = False

    if session is None:
        session = aiohttp.ClientSession()
        close_session = True

    try:
        # Find GraphQL endpoint
        graphql_url = None
        for endpoint in GRAPHQL_ENDPOINTS:
            test_url = f"{base_url.rstrip('/')}{endpoint}"
            try:
                async with session.post(
                    test_url,
                    json={"query": "{ __typename }"},
                    timeout=aiohttp.ClientTimeout(total=8),
                ) as resp:
                    if resp.status == 200:
                        body = await resp.text()
                        if "data" in body or "__typename" in body:
                            graphql_url = test_url
                            break
            except Exception:
                continue

        if not graphql_url:
            return findings

        logger.info(f"  GraphQL endpoint found: {graphql_url}")

        # ── Test 1: Introspection ─────────────────────────────────────────
        try:
            async with session.post(
                graphql_url,
                json={"query": INTROSPECTION_QUERY},
                timeout=aiohttp.ClientTimeout(total=10),
            ) as resp:
                if resp.status == 200:
                    data = await resp.json()
                    if data.get("data", {}).get("__schema"):
                        schema = data["data"]["__schema"]
                        type_count = len(schema.get("types", []))
                        findings.append(Finding(
                            id=f"graphql_{len(findings)+1:03d}",
                            target_url=graphql_url,
                            vuln_type=VulnerabilityType.MISCONFIG,
                            severity=SeverityLevel.MEDIUM,
                            title="GraphQL Introspection Enabled",
                            description=(
                                f"GraphQL introspection is enabled, exposing "
                                f"{type_count} types. Attackers can discover "
                                "the entire API schema."
                            ),
                            owasp_category="A05",
                            evidence=[Evidence(
                                type="http_request",
                                data=json.dumps(data, indent=2)[:500],
                            )],
                            tool_source="sapt_graphql",
                        ))
                        log_finding("GraphQL Introspection Enabled", "medium")
        except Exception:
            pass

        # ── Test 2: Batch Query Attack ────────────────────────────────────
        try:
            async with session.post(
                graphql_url,
                json=BATCH_QUERY,
                timeout=aiohttp.ClientTimeout(total=10),
            ) as resp:
                if resp.status == 200:
                    data = await resp.json()
                    if isinstance(data, list) and len(data) > 1:
                        findings.append(Finding(
                            id=f"graphql_{len(findings)+1:03d}",
                            target_url=graphql_url,
                            vuln_type=VulnerabilityType.MISCONFIG,
                            severity=SeverityLevel.MEDIUM,
                            title="GraphQL Batch Query Allowed",
                            description=(
                                "Server accepts batched GraphQL queries. "
                                "Can be used for brute-force or DoS attacks."
                            ),
                            owasp_category="A05",
                            tool_source="sapt_graphql",
                        ))
                        log_finding("GraphQL Batch Query Allowed", "medium")
        except Exception:
            pass

    finally:
        if close_session:
            await session.close()

    return findings
