"""
OWASP A07 — Authentication Failures & JWT Testing Module.
Tests for auth bypass, JWT manipulation, and session issues.
"""

from __future__ import annotations

import base64
import json
from typing import Any, Dict, List, Optional

import aiohttp

from sapt.core.logger import get_logger, log_finding
from sapt.models.models import Finding, Evidence, VulnerabilityType, SeverityLevel


# ── JWT Analysis ─────────────────────────────────────────────────────────────

def analyze_jwt(token: str) -> Dict[str, Any]:
    """Decode and analyze a JWT token for vulnerabilities."""
    findings = []

    try:
        parts = token.split(".")
        if len(parts) != 3:
            return {"valid": False, "error": "Not a valid JWT format"}

        # Decode header
        header = json.loads(_b64_decode(parts[0]))
        payload_data = json.loads(_b64_decode(parts[1]))

        # Check for weak algorithms
        alg = header.get("alg", "")
        if alg == "none":
            findings.append("CRITICAL: Algorithm 'none' — signature bypass possible")
        elif alg in ("HS256", "HS384", "HS512"):
            findings.append("WARNING: Symmetric algorithm — key brute-force possible")
        elif alg == "":
            findings.append("WARNING: No algorithm specified")

        # Check for sensitive data in payload
        sensitive_keys = ["password", "secret", "ssn", "credit_card", "token"]
        for key in sensitive_keys:
            if key in str(payload_data).lower():
                findings.append(f"WARNING: Sensitive field '{key}' in JWT payload")

        # Check expiration
        if "exp" not in payload_data:
            findings.append("WARNING: No expiration (exp) claim — token never expires")

        # Check issuer
        if "iss" not in payload_data:
            findings.append("INFO: No issuer (iss) claim")

        return {
            "valid": True,
            "header": header,
            "payload": payload_data,
            "algorithm": alg,
            "findings": findings,
        }
    except Exception as e:
        return {"valid": False, "error": str(e)}


def _b64_decode(data: str) -> str:
    """Base64url decode."""
    padding = 4 - len(data) % 4
    data += "=" * padding
    return base64.urlsafe_b64decode(data).decode("utf-8")


# ── Auth Bypass Tests ────────────────────────────────────────────────────────

AUTH_BYPASS_HEADERS = [
    {"X-Forwarded-For": "127.0.0.1"},
    {"X-Original-URL": "/admin"},
    {"X-Rewrite-URL": "/admin"},
    {"X-Custom-IP-Authorization": "127.0.0.1"},
    {"X-Forwarded-Host": "localhost"},
    {"X-Host": "localhost"},
]

AUTH_BYPASS_PATHS = [
    "/admin", "/admin/", "/admin/dashboard",
    "/api/admin", "/api/v1/admin",
    "/.admin", "/admin.php", "/admin.html",
    "/manager", "/console", "/panel",
    "/wp-admin", "/administrator",
]


async def test_auth_bypass(
    base_url: str,
    session: Optional[aiohttp.ClientSession] = None,
) -> List[Finding]:
    """Test for authentication bypass vulnerabilities."""
    logger = get_logger()
    findings: List[Finding] = []
    close_session = False

    if session is None:
        session = aiohttp.ClientSession()
        close_session = True

    try:
        # Test admin paths without auth
        for path in AUTH_BYPASS_PATHS:
            url = f"{base_url.rstrip('/')}{path}"

            try:
                async with session.get(
                    url, timeout=aiohttp.ClientTimeout(total=8),
                    allow_redirects=False,
                ) as resp:
                    if resp.status == 200:
                        body = await resp.text()
                        if len(body) > 100 and "login" not in body.lower():
                            finding = Finding(
                                id=f"auth_{len(findings)+1:03d}",
                                target_url=url,
                                vuln_type=VulnerabilityType.AUTH_BYPASS,
                                severity=SeverityLevel.HIGH,
                                title=f"Unauthenticated access to {path}",
                                description=f"Admin path {path} accessible without authentication.",
                                owasp_category="A07",
                                evidence=[Evidence(
                                    type="http_request",
                                    data=f"GET {url} → HTTP 200 ({len(body)} chars)",
                                )],
                                tool_source="sapt_auth",
                            )
                            findings.append(finding)
                            log_finding(finding.title, "high")
            except Exception:
                continue

        # Test header-based auth bypass
        for headers in AUTH_BYPASS_HEADERS:
            for path in AUTH_BYPASS_PATHS[:3]:
                url = f"{base_url.rstrip('/')}{path}"
                try:
                    async with session.get(
                        url, headers=headers,
                        timeout=aiohttp.ClientTimeout(total=8),
                        allow_redirects=False,
                    ) as resp:
                        if resp.status == 200:
                            header_name = list(headers.keys())[0]
                            finding = Finding(
                                id=f"auth_{len(findings)+1:03d}",
                                target_url=url,
                                vuln_type=VulnerabilityType.AUTH_BYPASS,
                                severity=SeverityLevel.CRITICAL,
                                title=f"Auth bypass via {header_name}",
                                description=(
                                    f"Authentication bypassed using header "
                                    f"{header_name}: {headers[header_name]}"
                                ),
                                owasp_category="A07",
                                evidence=[Evidence(
                                    type="http_request",
                                    data=f"GET {url} with {headers} → HTTP 200",
                                )],
                                tool_source="sapt_auth",
                            )
                            findings.append(finding)
                            log_finding(finding.title, "critical")
                except Exception:
                    continue

    finally:
        if close_session:
            await session.close()

    logger.info(f"Auth bypass testing: {len(findings)} findings")
    return findings
