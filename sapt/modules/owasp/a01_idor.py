"""
OWASP A01 — IDOR (Insecure Direct Object Reference) Testing Module.
Tests for broken access control by manipulating object identifiers.
"""

from __future__ import annotations

import re
from typing import Any, Dict, List, Optional

import aiohttp

from sapt.core.logger import get_logger, log_finding
from sapt.models.models import Finding, Evidence, VulnerabilityType, SeverityLevel


# ── IDOR Patterns ────────────────────────────────────────────────────────────

IDOR_PARAM_PATTERNS = [
    r'[?&](id|user_id|userId|account_id|accountId|order_id|orderId)=(\d+)',
    r'[?&](profile|account|user|order|invoice|doc|file|record)=([^&]+)',
    r'/(\d+)(?:/|$)',              # Path-based numeric IDs
    r'/([a-f0-9-]{36})(?:/|$)',    # UUID-based IDs
]


async def test_idor(
    target_urls: List[str],
    session: Optional[aiohttp.ClientSession] = None,
) -> List[Finding]:
    """
    Test for IDOR vulnerabilities by manipulating ID parameters.
    Returns list of Finding objects.
    """
    logger = get_logger()
    findings: List[Finding] = []
    close_session = False

    if session is None:
        session = aiohttp.ClientSession()
        close_session = True

    try:
        for url in target_urls:
            for pattern in IDOR_PARAM_PATTERNS:
                matches = re.finditer(pattern, url)
                for match in matches:
                    param_name = match.group(1) if match.lastindex >= 1 else "id"
                    original_value = match.group(2) if match.lastindex >= 2 else match.group(1)

                    # Generate test values
                    test_values = _generate_idor_values(original_value)

                    for test_val in test_values:
                        test_url = url.replace(
                            f"{param_name}={original_value}",
                            f"{param_name}={test_val}",
                        )
                        if test_url == url:
                            test_url = re.sub(
                                rf'/{re.escape(str(original_value))}(?=/|$)',
                                f'/{test_val}',
                                url,
                            )

                        try:
                            async with session.get(
                                test_url,
                                timeout=aiohttp.ClientTimeout(total=10),
                            ) as resp:
                                if resp.status == 200:
                                    body = await resp.text()
                                    if len(body) > 50:
                                        finding = Finding(
                                            id=f"idor_{len(findings)+1:03d}",
                                            target_url=test_url,
                                            vuln_type=VulnerabilityType.IDOR,
                                            severity=SeverityLevel.HIGH,
                                            title=f"Potential IDOR on {param_name}",
                                            description=(
                                                f"Changing {param_name} from '{original_value}' to "
                                                f"'{test_val}' returned HTTP 200 with content. "
                                                "Verify if unauthorized data is accessible."
                                            ),
                                            owasp_category="A01",
                                            evidence=[Evidence(
                                                type="http_request",
                                                data=f"GET {test_url} → HTTP {resp.status}",
                                                description=f"Response length: {len(body)} chars",
                                            )],
                                            reproduction_steps=[
                                                f"1. Original URL: {url}",
                                                f"2. Modified URL: {test_url}",
                                                f"3. Changed {param_name}: {original_value} → {test_val}",
                                                f"4. Got HTTP {resp.status} with {len(body)} chars response",
                                            ],
                                            tool_source="sapt_idor",
                                        )
                                        findings.append(finding)
                                        log_finding(finding.title, "high")
                        except Exception:
                            continue

    finally:
        if close_session:
            await session.close()

    logger.info(f"IDOR testing: {len(findings)} potential findings")
    return findings


def _generate_idor_values(original: str) -> List[str]:
    """Generate test values for IDOR testing."""
    values = []
    try:
        num = int(original)
        values.extend([str(num + 1), str(num - 1), str(num + 100), "0", "1"])
    except ValueError:
        values.extend(["1", "admin", "test", "0"])
    return values[:5]
