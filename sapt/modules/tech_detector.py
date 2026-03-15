"""
SAPT Tech Detector — Framework/technology detection with CVE lookup.
Uses httpx tech-detect results + NVD API for CVE correlation.
"""

from __future__ import annotations

import re
from typing import Any, Dict, List, Optional

import requests

from sapt.core.logger import get_logger, log_finding
from sapt.models.models import TechDetection


# ── NVD API ──────────────────────────────────────────────────────────────────

NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"


def lookup_cves(
    tech_name: str,
    version: Optional[str] = None,
    api_key: Optional[str] = None,
    max_results: int = 10,
) -> List[str]:
    """
    Query NVD API for CVEs matching a technology + version.
    Returns list of CVE IDs.
    """
    logger = get_logger()
    keyword = tech_name
    if version:
        keyword += f" {version}"

    params = {
        "keywordSearch": keyword,
        "resultsPerPage": max_results,
    }
    headers = {}
    if api_key:
        headers["apiKey"] = api_key

    try:
        resp = requests.get(NVD_API_URL, params=params, headers=headers, timeout=15)
        if resp.status_code == 200:
            data = resp.json()
            cves = []
            for vuln in data.get("vulnerabilities", []):
                cve_id = vuln.get("cve", {}).get("id", "")
                if cve_id:
                    cves.append(cve_id)
            if cves:
                logger.debug(f"Found {len(cves)} CVEs for {keyword}")
            return cves
        else:
            logger.debug(f"NVD API returned {resp.status_code} for {keyword}")
            return []
    except Exception as e:
        logger.debug(f"NVD API query failed for {keyword}: {e}")
        return []


# ── Tech Detection ───────────────────────────────────────────────────────────

def parse_httpx_tech(httpx_data: List[Dict]) -> List[TechDetection]:
    """
    Parse httpx JSON output and extract tech stack detections.
    Returns list of TechDetection models.
    """
    detections: Dict[str, TechDetection] = {}

    for host_data in httpx_data:
        techs = host_data.get("tech", [])
        if not techs:
            continue

        for tech_str in techs:
            # httpx returns tech names like "React" or "jQuery:3.5.1"
            name, version = _parse_tech_string(tech_str)

            if name not in detections:
                detections[name] = TechDetection(
                    name=name,
                    version=version,
                    confidence=0.8,
                )
            elif version and not detections[name].version:
                detections[name].version = version

    return list(detections.values())


def enrich_with_cves(
    detections: List[TechDetection],
    api_key: Optional[str] = None,
) -> List[TechDetection]:
    """Enrich tech detections with CVE lookups from NVD."""
    logger = get_logger()

    for tech in detections:
        cves = lookup_cves(tech.name, tech.version, api_key)
        tech.cve_ids = cves

        if cves:
            log_finding(
                f"{tech.name} {tech.version or ''} — {len(cves)} CVEs found",
                "medium",
            )

    return detections


def _parse_tech_string(tech_str: str) -> tuple[str, Optional[str]]:
    """Parse 'TechName:version' or 'TechName' string."""
    if ":" in tech_str:
        parts = tech_str.split(":", 1)
        return parts[0].strip(), parts[1].strip() or None
    return tech_str.strip(), None


# ── Header Analysis ──────────────────────────────────────────────────────────

HEADER_TECH_MAP = {
    "x-powered-by": {
        "express":  "Express.js",
        "php":      "PHP",
        "asp.net":  "ASP.NET",
        "django":   "Django",
        "flask":    "Flask",
    },
    "server": {
        "nginx":    "Nginx",
        "apache":   "Apache",
        "iis":      "Microsoft IIS",
        "caddy":    "Caddy",
        "gunicorn": "Gunicorn",
    },
}


def detect_from_headers(headers: Dict[str, str]) -> List[TechDetection]:
    """Detect technologies from HTTP response headers."""
    detections = []

    for header_name, tech_map in HEADER_TECH_MAP.items():
        header_value = headers.get(header_name, "").lower()
        if not header_value:
            continue

        for keyword, tech_name in tech_map.items():
            if keyword in header_value:
                # Try to extract version
                version = None
                version_match = re.search(
                    rf"{keyword}[/ ]?([\d.]+)", header_value
                )
                if version_match:
                    version = version_match.group(1)

                detections.append(TechDetection(
                    name=tech_name,
                    version=version,
                    confidence=0.9,
                ))

    return detections
