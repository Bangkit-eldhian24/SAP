"""
SAPT Threat Model — Target Classification (Gap #1 fix).
Classifies targets by profile (ecommerce, fintech, etc.)
and prioritizes OWASP test categories accordingly.
"""

from __future__ import annotations

import re
from typing import Dict, List, Optional

from sapt.core.logger import get_logger
from sapt.models.models import TargetProfile, PRIORITY_MAP


# ── Common indicators for auto-detection ─────────────────────────────────────

PROFILE_INDICATORS: Dict[TargetProfile, List[str]] = {
    TargetProfile.ECOMMERCE: [
        "shop", "store", "cart", "checkout", "product", "order",
        "payment", "catalog", "merchant", "shopify", "woocommerce",
        "magento", "bigcommerce", "price", "buy",
    ],
    TargetProfile.FINTECH: [
        "bank", "finance", "pay", "wallet", "transfer", "loan",
        "credit", "debit", "invest", "trade", "crypto", "ledger",
        "fintech", "insurance", "mortgage",
    ],
    TargetProfile.API_ONLY: [
        "api.", "api-", "/api/", "graphql", "rest", "swagger",
        "openapi", "grpc", "webhook",
    ],
    TargetProfile.CMS: [
        "wordpress", "wp-", "joomla", "drupal", "ghost", "strapi",
        "contentful", "sanity", "blog", "cms", "typo3",
    ],
}


def detect_profile(
    target: str,
    tech_stack: Optional[List[str]] = None,
    headers: Optional[Dict[str, str]] = None,
) -> TargetProfile:
    """
    Auto-detect target profile from domain name, tech stack, and headers.
    Returns TargetProfile enum.
    """
    logger = get_logger()
    target_lower = target.lower()
    scores: Dict[TargetProfile, int] = {p: 0 for p in TargetProfile}

    # Check domain name indicators
    for profile, indicators in PROFILE_INDICATORS.items():
        for indicator in indicators:
            if indicator in target_lower:
                scores[profile] += 2

    # Check tech stack
    if tech_stack:
        tech_str = " ".join(tech_stack).lower()
        for profile, indicators in PROFILE_INDICATORS.items():
            for indicator in indicators:
                if indicator in tech_str:
                    scores[profile] += 1

    # Get highest scoring profile
    best_profile = max(scores, key=scores.get)
    if scores[best_profile] == 0:
        best_profile = TargetProfile.GENERIC_WEB

    logger.debug(
        f"Target profile detected: {best_profile.value} "
        f"(scores: {dict(scores)})"
    )
    return best_profile


def get_priority_tests(profile: TargetProfile) -> List[str]:
    """Get prioritized OWASP test categories for a target profile."""
    return PRIORITY_MAP.get(profile, PRIORITY_MAP[TargetProfile.GENERIC_WEB])


def get_test_recommendations(profile: TargetProfile) -> Dict[str, str]:
    """Get specific test recommendations based on target profile."""
    recommendations = {
        TargetProfile.ECOMMERCE: {
            "A04": "Test price manipulation, coupon abuse, cart race conditions",
            "A01": "Test IDOR on orders, user profiles, payment details",
            "A02": "Test payment token reuse, session fixation on checkout",
            "A07": "Test authentication bypass on admin panels",
            "A03": "Test SQLi on search, filter, and product parameters",
        },
        TargetProfile.FINTECH: {
            "A04": "Test transaction manipulation, balance race conditions",
            "A01": "Test IDOR on accounts, transactions, beneficiaries",
            "A07": "Test MFA bypass, JWT manipulation, session management",
            "A02": "Test encryption of sensitive financial data in transit",
            "A03": "Test injection on transaction parameters",
        },
        TargetProfile.API_ONLY: {
            "A01": "Test broken object-level authorization (BOLA)",
            "A07": "Test API key abuse, rate limiting, auth header manipulation",
            "A10": "Test SSRF via webhook URLs, redirect parameters",
            "A03": "Test injection via JSON/XML parameters",
            "A02": "Test sensitive data exposure in API responses",
        },
        TargetProfile.CMS: {
            "A06": "Check known CVEs for CMS version and plugins",
            "A03": "Test stored XSS via content fields, comments",
            "A01": "Test admin role escalation, user enumeration",
            "A05": "Test default credentials, exposed admin panels",
            "A07": "Test auth bypass on login, password reset flows",
        },
        TargetProfile.GENERIC_WEB: {
            "A01": "Test IDOR and access control on all endpoints",
            "A03": "Test XSS, SQLi, and command injection",
            "A07": "Test authentication and session management",
            "A02": "Test for sensitive data exposure",
            "A10": "Test SSRF on URL parameters, redirects",
        },
    }
    return recommendations.get(profile, recommendations[TargetProfile.GENERIC_WEB])
