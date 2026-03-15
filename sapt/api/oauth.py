"""
SAPT OAuth Testing Module (Gap #2 fix).
Tests for OAuth misconfigurations including redirect_uri manipulation,
state parameter bypass, and token leakage.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional
from urllib.parse import urlencode, urlparse, parse_qs

import aiohttp

from sapt.core.logger import get_logger, log_finding
from sapt.models.models import Finding, Evidence, VulnerabilityType, SeverityLevel


OAUTH_ENDPOINTS = [
    "/oauth/authorize", "/oauth2/authorize",
    "/auth/authorize", "/authorize",
    "/login/oauth/authorize", "/oauth/token",
    "/.well-known/openid-configuration",
]


async def test_oauth(
    base_url: str,
    session: Optional[aiohttp.ClientSession] = None,
) -> List[Finding]:
    """Test for OAuth vulnerabilities."""
    logger = get_logger()
    findings: List[Finding] = []
    close_session = False

    if session is None:
        session = aiohttp.ClientSession()
        close_session = True

    try:
        # Find OAuth endpoints
        oauth_url = None
        for endpoint in OAUTH_ENDPOINTS:
            url = f"{base_url.rstrip('/')}{endpoint}"
            try:
                async with session.get(
                    url, timeout=aiohttp.ClientTimeout(total=5),
                    allow_redirects=False,
                ) as resp:
                    if resp.status in (200, 302, 400):
                        oauth_url = url
                        break
            except Exception:
                continue

        if not oauth_url:
            return findings

        # ── Test 1: Open Redirect via redirect_uri ────────────────────────
        evil_redirects = [
            "https://evil.com",
            "https://evil.com%40legitimate.com",
            f"{base_url}@evil.com",
            f"{base_url}.evil.com",
        ]

        for evil_uri in evil_redirects:
            params = urlencode({
                "response_type": "code",
                "client_id": "test",
                "redirect_uri": evil_uri,
                "scope": "read",
            })
            test_url = f"{oauth_url}?{params}"

            try:
                async with session.get(
                    test_url,
                    timeout=aiohttp.ClientTimeout(total=8),
                    allow_redirects=False,
                ) as resp:
                    location = resp.headers.get("Location", "")
                    if "evil.com" in location:
                        findings.append(Finding(
                            id=f"oauth_{len(findings)+1:03d}",
                            target_url=test_url,
                            vuln_type=VulnerabilityType.AUTH_BYPASS,
                            severity=SeverityLevel.HIGH,
                            title="OAuth redirect_uri open redirect",
                            description=(
                                f"OAuth authorize endpoint redirects to "
                                f"attacker-controlled domain: {evil_uri}"
                            ),
                            owasp_category="A07",
                            evidence=[Evidence(
                                type="http_request",
                                data=f"redirect_uri={evil_uri}\nLocation: {location}",
                            )],
                            tool_source="sapt_oauth",
                        ))
                        log_finding("OAuth redirect_uri bypass", "high")
                        break
            except Exception:
                continue

        # ── Test 2: Missing state parameter ───────────────────────────────
        params_no_state = urlencode({
            "response_type": "code",
            "client_id": "test",
            "redirect_uri": base_url,
        })
        test_url = f"{oauth_url}?{params_no_state}"

        try:
            async with session.get(
                test_url,
                timeout=aiohttp.ClientTimeout(total=8),
                allow_redirects=False,
            ) as resp:
                if resp.status != 400:
                    findings.append(Finding(
                        id=f"oauth_{len(findings)+1:03d}",
                        target_url=test_url,
                        vuln_type=VulnerabilityType.AUTH_BYPASS,
                        severity=SeverityLevel.MEDIUM,
                        title="OAuth state parameter not enforced",
                        description=(
                            "OAuth authorize endpoint does not require 'state' parameter. "
                            "This allows CSRF attacks on the OAuth flow."
                        ),
                        owasp_category="A07",
                        tool_source="sapt_oauth",
                    ))
        except Exception:
            pass

    finally:
        if close_session:
            await session.close()

    return findings
