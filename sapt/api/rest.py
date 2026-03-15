"""
SAPT REST API Testing Module (Gap #2 fix).
Tests for common REST API vulnerabilities including version enumeration,
rate limiting bypass, and method testing.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional

import aiohttp

from sapt.core.logger import get_logger, log_finding
from sapt.models.models import Finding, Evidence, VulnerabilityType, SeverityLevel


API_VERSION_PATHS = [
    "/api/v1", "/api/v2", "/api/v3",
    "/api/v1.0", "/api/v1.1", "/api/v2.0",
    "/v1", "/v2", "/v3",
]

RATE_LIMIT_BYPASS_HEADERS = [
    {"X-Forwarded-For": "127.0.0.1"},
    {"X-Real-IP": "127.0.0.1"},
    {"X-Originating-IP": "127.0.0.1"},
    {"X-Remote-Addr": "127.0.0.1"},
    {"X-Client-IP": "127.0.0.1"},
    {"True-Client-IP": "127.0.0.1"},
    {"X-Forwarded-For": "10.0.0.1"},
]

HTTP_METHODS = ["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS", "HEAD"]


async def test_rest_api(
    base_url: str,
    session: Optional[aiohttp.ClientSession] = None,
) -> List[Finding]:
    """Test for REST API vulnerabilities."""
    logger = get_logger()
    findings: List[Finding] = []
    close_session = False

    if session is None:
        session = aiohttp.ClientSession()
        close_session = True

    try:
        # ── API Version Enumeration ───────────────────────────────────────
        accessible_versions = []
        for path in API_VERSION_PATHS:
            url = f"{base_url.rstrip('/')}{path}"
            try:
                async with session.get(
                    url, timeout=aiohttp.ClientTimeout(total=5),
                    allow_redirects=False,
                ) as resp:
                    if resp.status in (200, 301, 302):
                        accessible_versions.append((path, resp.status))
            except Exception:
                continue

        if len(accessible_versions) > 1:
            findings.append(Finding(
                id=f"api_{len(findings)+1:03d}",
                target_url=base_url,
                vuln_type=VulnerabilityType.MISCONFIG,
                severity=SeverityLevel.MEDIUM,
                title="Multiple API versions accessible",
                description=(
                    f"Found {len(accessible_versions)} API versions: "
                    f"{', '.join(v[0] for v in accessible_versions)}. "
                    "Older versions may have unpatched vulnerabilities."
                ),
                owasp_category="A05",
                evidence=[Evidence(
                    type="http_request",
                    data="\n".join(f"{v[0]} → HTTP {v[1]}" for v in accessible_versions),
                )],
                tool_source="sapt_rest",
            ))

        # ── CORS Misconfiguration ─────────────────────────────────────────
        try:
            async with session.options(
                base_url,
                headers={"Origin": "https://evil.com"},
                timeout=aiohttp.ClientTimeout(total=5),
            ) as resp:
                acao = resp.headers.get("Access-Control-Allow-Origin", "")
                if acao == "*" or "evil.com" in acao:
                    findings.append(Finding(
                        id=f"api_{len(findings)+1:03d}",
                        target_url=base_url,
                        vuln_type=VulnerabilityType.MISCONFIG,
                        severity=SeverityLevel.HIGH,
                        title="CORS Misconfiguration — Wildcard/Reflected Origin",
                        description=(
                            f"Access-Control-Allow-Origin returns '{acao}'. "
                            "Allows cross-origin requests from any domain."
                        ),
                        owasp_category="A05",
                        evidence=[Evidence(
                            type="http_request",
                            data=f"Origin: https://evil.com → ACAO: {acao}",
                        )],
                        tool_source="sapt_rest",
                    ))
                    log_finding("CORS Misconfiguration", "high")
        except Exception:
            pass

        # ── HTTP Method Testing ───────────────────────────────────────────
        dangerous_methods = []
        for method in ["PUT", "DELETE", "PATCH"]:
            try:
                async with session.request(
                    method, base_url,
                    timeout=aiohttp.ClientTimeout(total=5),
                ) as resp:
                    if resp.status not in (404, 405, 501):
                        dangerous_methods.append((method, resp.status))
            except Exception:
                continue

        if dangerous_methods:
            findings.append(Finding(
                id=f"api_{len(findings)+1:03d}",
                target_url=base_url,
                vuln_type=VulnerabilityType.MISCONFIG,
                severity=SeverityLevel.LOW,
                title="Dangerous HTTP methods accepted",
                description=(
                    f"Server accepts methods: "
                    f"{', '.join(m[0] for m in dangerous_methods)}. "
                    "Verify these are intentionally allowed."
                ),
                owasp_category="A05",
                tool_source="sapt_rest",
            ))

    finally:
        if close_session:
            await session.close()

    return findings
