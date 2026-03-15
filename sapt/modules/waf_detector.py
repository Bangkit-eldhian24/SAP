"""
SAPT WAF Detector — WAF fingerprinting and bypass strategies (Gap #3 fix).
Detects common WAFs from HTTP headers and provides bypass configurations.
"""

from __future__ import annotations

import re
from typing import Any, Dict, List, Optional

import aiohttp

from sapt.core.logger import get_logger


# ── WAF Signatures ───────────────────────────────────────────────────────────

WAF_SIGNATURES: Dict[str, List[str]] = {
    "cloudflare": ["cf-ray", "cloudflare", "__cfduid", "cf-cache-status", "cf-request-id"],
    "aws_waf":    ["x-amzn-requestid", "awselb", "x-amz-cf-id", "x-amz-apigw-id"],
    "imperva":    ["x-iinfo", "visid_incap", "incap_ses_", "x-cdn"],
    "akamai":     ["akamai-origin-hop", "x-akamai-transformed", "x-akamai-request-id"],
    "sucuri":     ["x-sucuri-id", "x-sucuri-cache", "sucuri-"],
    "f5_big_ip":  ["x-wa-info", "bigipserver", "f5-"],
    "barracuda":  ["barra_counter_session", "barracuda"],
    "modsecurity": ["mod_security", "modsecurity", "nyob"],
    "fortinet":   ["fortigate", "fortiwaf", "fgta_"],
    "citrix":     ["ns_af", "citrix_ns", "via: ns-cache"],
}

# ── Bypass Strategies ────────────────────────────────────────────────────────

BYPASS_STRATEGIES: Dict[str, Dict[str, Any]] = {
    "cloudflare": {
        "payload_encoding": ["url_double", "unicode", "html_entity"],
        "header_rotation": True,
        "delay_between": 0.5,
        "user_agent_rotate": True,
        "tips": [
            "Try URL double-encoding payloads",
            "Use Unicode normalization bypass",
            "Rotate User-Agent headers",
            "Try accessing origin IP directly",
        ],
    },
    "aws_waf": {
        "payload_encoding": ["url_single", "case_variation"],
        "header_rotation": False,
        "delay_between": 1.0,
        "user_agent_rotate": True,
        "tips": [
            "Try case variation in SQL keywords",
            "Use comment-based SQLi obfuscation",
            "Test with different HTTP methods",
        ],
    },
    "imperva": {
        "payload_encoding": ["url_double", "unicode", "hex"],
        "header_rotation": True,
        "delay_between": 1.5,
        "user_agent_rotate": True,
        "tips": [
            "Try double URL encoding",
            "Use CRLF injection in headers",
            "Test with chunked transfer encoding",
        ],
    },
    "akamai": {
        "payload_encoding": ["url_single", "unicode"],
        "header_rotation": True,
        "delay_between": 2.0,
        "user_agent_rotate": True,
        "tips": [
            "Slow down scan rate significantly",
            "Use parameter pollution",
            "Try HPP (HTTP Parameter Pollution)",
        ],
    },
    "modsecurity": {
        "payload_encoding": ["url_double", "hex", "unicode"],
        "header_rotation": False,
        "delay_between": 0.3,
        "user_agent_rotate": False,
        "tips": [
            "Check ModSecurity paranoia level via error responses",
            "Try SQL comment obfuscation: /*!50000 SELECT*/",
            "Use multipart/form-data for payload delivery",
        ],
    },
}

# ── Detection Functions ──────────────────────────────────────────────────────

async def detect_waf(
    url: str,
    session: Optional[aiohttp.ClientSession] = None,
) -> Optional[str]:
    """
    Detect WAF vendor from HTTP response headers.
    Returns WAF vendor name or None.
    """
    logger = get_logger()
    close_session = False

    try:
        if session is None:
            session = aiohttp.ClientSession()
            close_session = True

        async with session.get(
            url,
            timeout=aiohttp.ClientTimeout(total=10),
            allow_redirects=True,
        ) as resp:
            headers = {k.lower(): v.lower() for k, v in resp.headers.items()}
            cookies = str(resp.cookies).lower()

            # Check each WAF signature
            for waf_name, signatures in WAF_SIGNATURES.items():
                for sig in signatures:
                    sig_lower = sig.lower()
                    # Check in headers
                    for header_name, header_value in headers.items():
                        if sig_lower in header_name or sig_lower in header_value:
                            logger.info(f"🛡️  WAF detected: {waf_name} (via header: {header_name})")
                            return waf_name
                    # Check in cookies
                    if sig_lower in cookies:
                        logger.info(f"🛡️  WAF detected: {waf_name} (via cookie)")
                        return waf_name

        # Additional detection: send a malicious payload and check for WAF block
        test_url = f"{url.rstrip('/')}/?test=<script>alert(1)</script>"
        async with session.get(
            test_url,
            timeout=aiohttp.ClientTimeout(total=10),
            allow_redirects=True,
        ) as resp:
            if resp.status in (403, 406, 419, 429, 503):
                body = await resp.text()
                body_lower = body.lower()

                waf_body_indicators = {
                    "cloudflare": ["cloudflare", "ray id", "cf-ray"],
                    "aws_waf":    ["access denied", "request blocked"],
                    "imperva":    ["incapsula", "imperva"],
                    "sucuri":     ["sucuri", "cloudproxy"],
                    "akamai":     ["akamai", "ghost"],
                }
                for waf_name, indicators in waf_body_indicators.items():
                    for indicator in indicators:
                        if indicator in body_lower:
                            logger.info(f"🛡️  WAF detected: {waf_name} (via block page)")
                            return waf_name

                logger.warning("🛡️  WAF detected (unknown vendor) — got blocked on test payload")
                return "unknown"

        return None

    except Exception as e:
        logger.debug(f"WAF detection error for {url}: {e}")
        return None
    finally:
        if close_session and session:
            await session.close()


def get_bypass_strategy(waf_vendor: str) -> Dict[str, Any]:
    """Get bypass configuration for detected WAF."""
    return BYPASS_STRATEGIES.get(waf_vendor, {
        "payload_encoding": ["url_single"],
        "delay_between": 1.0,
        "tips": ["Unknown WAF — use conservative approach"],
    })


def detect_waf_from_headers(headers: Dict[str, str]) -> Optional[str]:
    """Synchronous WAF detection from headers dict (for httpx results)."""
    headers_lower = {k.lower(): v.lower() for k, v in headers.items()}

    for waf_name, signatures in WAF_SIGNATURES.items():
        for sig in signatures:
            sig_lower = sig.lower()
            for h_name, h_value in headers_lower.items():
                if sig_lower in h_name or sig_lower in h_value:
                    return waf_name
    return None
