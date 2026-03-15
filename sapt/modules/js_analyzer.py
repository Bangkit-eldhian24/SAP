"""
SAPT JS Analyzer — JavaScript extraction, deobfuscation, and secret/endpoint detection.
"""

from __future__ import annotations

import re
from typing import Any, Dict, List, Optional

import aiohttp

from sapt.core.logger import get_logger, log_finding
from sapt.models.models import JSFinding, SeverityLevel


# ── Patterns ─────────────────────────────────────────────────────────────────

API_ENDPOINT_PATTERNS = [
    r'["\'](/api/[a-zA-Z0-9_/\-{}]+)["\']',
    r'["\'](/v[0-9]+/[a-zA-Z0-9_/\-{}]+)["\']',
    r'fetch\(["\']([^"\']+)["\']',
    r'axios\.[a-z]+\(["\']([^"\']+)["\']',
    r'\.get\(["\']([^"\']+)["\']',
    r'\.post\(["\']([^"\']+)["\']',
    r'\.put\(["\']([^"\']+)["\']',
    r'\.delete\(["\']([^"\']+)["\']',
    r'XMLHttpRequest.*open\(["\'][A-Z]+["\'],\s*["\']([^"\']+)["\']',
    r'url:\s*["\']([^"\']+)["\']',
    r'endpoint:\s*["\']([^"\']+)["\']',
]

SECRET_PATTERNS = {
    "aws_access_key":       r'AKIA[0-9A-Z]{16}',
    "aws_secret_key":       r'["\']?[a-zA-Z0-9/+=]{40}["\']?',
    "google_api_key":       r'AIza[0-9A-Za-z\-_]{35}',
    "github_token":         r'gh[pousr]_[A-Za-z0-9_]{36,}',
    "slack_webhook":        r'https://hooks\.slack\.com/services/T[A-Z0-9]+/B[A-Z0-9]+/[a-zA-Z0-9]+',
    "jwt_token":            r'eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+',
    "private_key":          r'-----BEGIN (RSA |EC )?PRIVATE KEY-----',
    "stripe_key":           r'sk_live_[A-Za-z0-9]{24,}',
    "firebase_key":         r'["\']?[A-Za-z0-9]{39}["\']?',
    "generic_api_key":      r'["\']?api[_-]?key["\']?\s*[:=]\s*["\']([a-zA-Z0-9_\-]{20,})["\']',
    "generic_secret":       r'["\']?secret["\']?\s*[:=]\s*["\']([a-zA-Z0-9_\-]{20,})["\']',
    "password_in_code":     r'password\s*[:=]\s*["\']([^"\']{8,})["\']',
    "authorization_header": r'["\']Authorization["\']:\s*["\']Bearer\s+([^"\']+)["\']',
}

VULNERABLE_FUNCTION_PATTERNS = [
    (r'eval\(', "eval() — potential code injection", SeverityLevel.HIGH),
    (r'innerHTML\s*=', "innerHTML assignment — potential XSS", SeverityLevel.MEDIUM),
    (r'document\.write\(', "document.write() — potential XSS", SeverityLevel.MEDIUM),
    (r'\.html\(', "jQuery .html() — potential XSS", SeverityLevel.MEDIUM),
    (r'window\.location\s*=', "Direct location assignment — potential open redirect", SeverityLevel.LOW),
    (r'dangerouslySetInnerHTML', "React dangerouslySetInnerHTML — review required", SeverityLevel.MEDIUM),
    (r'postMessage\(', "postMessage — verify origin checking", SeverityLevel.LOW),
]


# ── Main Analysis Functions ──────────────────────────────────────────────────

async def fetch_js_content(js_url: str, session: Optional[aiohttp.ClientSession] = None) -> Optional[str]:
    """Fetch JavaScript content from URL."""
    logger = get_logger()
    close_session = False

    try:
        if session is None:
            session = aiohttp.ClientSession()
            close_session = True

        async with session.get(js_url, timeout=aiohttp.ClientTimeout(total=15)) as resp:
            if resp.status == 200:
                return await resp.text()
            return None
    except Exception as e:
        logger.debug(f"Failed to fetch JS from {js_url}: {e}")
        return None
    finally:
        if close_session and session:
            await session.close()


def extract_endpoints(js_content: str, js_url: str) -> List[JSFinding]:
    """Extract API endpoints from JavaScript code."""
    findings = []
    seen = set()

    for pattern in API_ENDPOINT_PATTERNS:
        for match in re.finditer(pattern, js_content):
            endpoint = match.group(1) if match.lastindex else match.group(0)
            if endpoint not in seen and len(endpoint) > 3:
                seen.add(endpoint)
                context_start = max(0, match.start() - 30)
                context_end = min(len(js_content), match.end() + 30)
                findings.append(JSFinding(
                    js_url=js_url,
                    finding_type="api_endpoint",
                    value=endpoint,
                    context=js_content[context_start:context_end],
                    severity=SeverityLevel.INFO,
                ))

    return findings


def extract_secrets(js_content: str, js_url: str) -> List[JSFinding]:
    """Extract potential secrets/tokens from JavaScript code."""
    findings = []

    for secret_type, pattern in SECRET_PATTERNS.items():
        for match in re.finditer(pattern, js_content):
            value = match.group(1) if match.lastindex else match.group(0)
            context_start = max(0, match.start() - 20)
            context_end = min(len(js_content), match.end() + 20)

            findings.append(JSFinding(
                js_url=js_url,
                finding_type="secret",
                value=f"{secret_type}: {value[:50]}...",
                context=js_content[context_start:context_end],
                severity=SeverityLevel.HIGH,
            ))
            log_finding(f"Secret found in JS: {secret_type}", "high")

    return findings


def find_vulnerable_functions(js_content: str, js_url: str) -> List[JSFinding]:
    """Find potentially vulnerable function calls in JavaScript."""
    findings = []

    for pattern, description, severity in VULNERABLE_FUNCTION_PATTERNS:
        for match in re.finditer(pattern, js_content):
            context_start = max(0, match.start() - 40)
            context_end = min(len(js_content), match.end() + 40)

            findings.append(JSFinding(
                js_url=js_url,
                finding_type="vulnerable_function",
                value=description,
                context=js_content[context_start:context_end],
                severity=severity,
            ))

    return findings


async def analyze_js(
    js_urls: List[str],
    extract_eps: bool = True,
    extract_secs: bool = True,
    find_vulns: bool = True,
) -> List[JSFinding]:
    """
    Full JS analysis pipeline.
    Fetches JS files and runs all configured analyzers.
    """
    logger = get_logger()
    all_findings: List[JSFinding] = []

    async with aiohttp.ClientSession() as session:
        for js_url in js_urls:
            content = await fetch_js_content(js_url, session)
            if not content:
                continue

            logger.debug(f"Analyzing JS: {js_url} ({len(content)} chars)")

            if extract_eps:
                all_findings.extend(extract_endpoints(content, js_url))
            if extract_secs:
                all_findings.extend(extract_secrets(content, js_url))
            if find_vulns:
                all_findings.extend(find_vulnerable_functions(content, js_url))

    logger.info(f"JS Analysis: {len(all_findings)} findings from {len(js_urls)} files")
    return all_findings
