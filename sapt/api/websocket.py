"""
SAPT WebSocket Testing Module.
Tests for WebSocket security issues.
"""

from __future__ import annotations

from typing import List, Optional

import aiohttp

from sapt.core.logger import get_logger, log_finding
from sapt.models.models import Finding, Evidence, VulnerabilityType, SeverityLevel


WS_ENDPOINTS = ["/ws", "/websocket", "/socket", "/socket.io/", "/ws/v1"]


async def test_websocket(
    base_url: str,
    session: Optional[aiohttp.ClientSession] = None,
) -> List[Finding]:
    """Test for WebSocket vulnerabilities."""
    logger = get_logger()
    findings: List[Finding] = []
    close_session = False

    if session is None:
        session = aiohttp.ClientSession()
        close_session = True

    try:
        ws_url = base_url.replace("https://", "wss://").replace("http://", "ws://")

        for endpoint in WS_ENDPOINTS:
            test_url = f"{ws_url.rstrip('/')}{endpoint}"
            try:
                async with session.ws_connect(
                    test_url, timeout=5,
                    origin="https://evil.com",
                ) as ws:
                    # If connection succeeds with evil origin → CORS issue
                    findings.append(Finding(
                        id=f"ws_{len(findings)+1:03d}",
                        target_url=test_url,
                        vuln_type=VulnerabilityType.MISCONFIG,
                        severity=SeverityLevel.MEDIUM,
                        title=f"WebSocket accepts cross-origin connection",
                        description=(
                            f"WebSocket at {endpoint} accepts connections from "
                            "arbitrary origins. Verify Origin header validation."
                        ),
                        owasp_category="A05",
                        tool_source="sapt_websocket",
                    ))
                    log_finding("WebSocket CORS issue", "medium")
                    await ws.close()
            except Exception:
                continue

    finally:
        if close_session:
            await session.close()

    return findings
