"""
OWASP A05 — Security Misconfiguration Testing Module.
Tests for common misconfigurations, exposed files, and default credentials.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional

import aiohttp

from sapt.core.logger import get_logger, log_finding
from sapt.models.models import Finding, Evidence, VulnerabilityType, SeverityLevel


SENSITIVE_PATHS = [
    "/.env", "/.git/config", "/.git/HEAD", "/.gitignore",
    "/.svn/entries", "/.hg/",
    "/wp-config.php.bak", "/config.php.bak", "/config.yaml",
    "/.htaccess", "/.htpasswd", "/web.config",
    "/robots.txt", "/sitemap.xml",
    "/server-status", "/server-info",
    "/phpinfo.php", "/info.php", "/test.php",
    "/debug", "/debug/vars", "/debug/pprof",
    "/actuator", "/actuator/health", "/actuator/env",
    "/swagger-ui.html", "/swagger-ui/", "/api-docs",
    "/openapi.json", "/openapi.yaml",
    "/.well-known/", "/crossdomain.xml",
    "/elmah.axd", "/trace.axd",
    "/backup.zip", "/backup.tar.gz", "/backup.sql",
    "/dump.sql", "/database.sql",
    "/.DS_Store", "/Thumbs.db",
    "/package.json", "/composer.json", "/Gemfile",
]

SENSITIVE_FILE_INDICATORS = {
    ".env":         ["DB_PASSWORD", "DATABASE_URL", "SECRET_KEY", "API_KEY"],
    ".git/config":  ["[core]", "[remote", "url ="],
    "phpinfo":      ["phpinfo()", "PHP Version", "Configuration"],
    "actuator":     ["status", "UP", "diskSpace"],
    "swagger":      ["swagger", "openapi", "paths"],
}


async def test_misconfig(
    base_url: str,
    session: Optional[aiohttp.ClientSession] = None,
) -> List[Finding]:
    """Test for security misconfigurations."""
    logger = get_logger()
    findings: List[Finding] = []
    close_session = False

    if session is None:
        session = aiohttp.ClientSession()
        close_session = True

    try:
        for path in SENSITIVE_PATHS:
            url = f"{base_url.rstrip('/')}{path}"

            try:
                async with session.get(
                    url,
                    timeout=aiohttp.ClientTimeout(total=8),
                    allow_redirects=False,
                ) as resp:
                    if resp.status == 200:
                        body = await resp.text()
                        severity = _assess_severity(path, body)

                        if severity:
                            finding = Finding(
                                id=f"misconfig_{len(findings)+1:03d}",
                                target_url=url,
                                vuln_type=VulnerabilityType.MISCONFIG,
                                severity=severity,
                                title=f"Exposed sensitive file: {path}",
                                description=(
                                    f"Sensitive file/path '{path}' is publicly accessible. "
                                    f"Response: HTTP 200, {len(body)} chars."
                                ),
                                owasp_category="A05",
                                evidence=[Evidence(
                                    type="http_request",
                                    data=f"GET {url} → HTTP 200\n\n{body[:300]}",
                                )],
                                tool_source="sapt_misconfig",
                            )
                            findings.append(finding)
                            log_finding(finding.title, severity.value)

            except Exception:
                continue

        # Check security headers
        try:
            async with session.get(
                base_url,
                timeout=aiohttp.ClientTimeout(total=8),
            ) as resp:
                header_findings = _check_security_headers(
                    base_url, dict(resp.headers)
                )
                findings.extend(header_findings)
        except Exception:
            pass

    finally:
        if close_session:
            await session.close()

    logger.info(f"Misconfiguration testing: {len(findings)} findings")
    return findings


def _assess_severity(path: str, body: str) -> Optional[SeverityLevel]:
    """Assess severity of an exposed file."""
    body_lower = body.lower()

    # Critical exposures
    critical_paths = [".env", ".git/config", "backup.sql", "dump.sql", "database.sql"]
    for cp in critical_paths:
        if cp in path:
            for indicator_set in SENSITIVE_FILE_INDICATORS.values():
                for indicator in indicator_set:
                    if indicator.lower() in body_lower:
                        return SeverityLevel.CRITICAL

    # High exposures
    high_paths = [".htpasswd", "config.php", "config.yaml", "phpinfo", "actuator/env"]
    for hp in high_paths:
        if hp in path:
            return SeverityLevel.HIGH

    # Medium
    medium_paths = ["swagger", "api-docs", "openapi", "server-status", "debug"]
    for mp in medium_paths:
        if mp in path:
            return SeverityLevel.MEDIUM

    # Low/Info
    if len(body) > 50:
        return SeverityLevel.LOW

    return None


SECURITY_HEADERS = {
    "strict-transport-security":    ("HSTS header missing", SeverityLevel.MEDIUM),
    "x-content-type-options":       ("X-Content-Type-Options header missing", SeverityLevel.LOW),
    "x-frame-options":              ("X-Frame-Options header missing (clickjacking risk)", SeverityLevel.MEDIUM),
    "content-security-policy":      ("Content-Security-Policy header missing", SeverityLevel.MEDIUM),
    "x-xss-protection":            ("X-XSS-Protection header missing", SeverityLevel.LOW),
    "referrer-policy":              ("Referrer-Policy header missing", SeverityLevel.LOW),
    "permissions-policy":           ("Permissions-Policy header missing", SeverityLevel.LOW),
}


def _check_security_headers(base_url: str, headers: Dict[str, str]) -> List[Finding]:
    """Check for missing security headers."""
    findings = []
    headers_lower = {k.lower(): v for k, v in headers.items()}

    for header, (description, severity) in SECURITY_HEADERS.items():
        if header not in headers_lower:
            findings.append(Finding(
                id=f"header_{len(findings)+1:03d}",
                target_url=base_url,
                vuln_type=VulnerabilityType.MISCONFIG,
                severity=severity,
                title=description,
                description=f"Missing security header: {header}",
                owasp_category="A05",
                evidence=[Evidence(
                    type="http_request",
                    data=f"Response headers do not include: {header}",
                )],
                tool_source="sapt_headers",
            ))

    return findings
