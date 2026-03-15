"""
SAPT Evidence Collection — HTTP capture and screenshot utilities.
"""

from __future__ import annotations

import json
from datetime import datetime
from typing import Any, Dict, Optional

from sapt.models.models import Evidence


def capture_http_evidence(
    method: str,
    url: str,
    status_code: int,
    request_headers: Optional[Dict[str, str]] = None,
    response_headers: Optional[Dict[str, str]] = None,
    response_body: Optional[str] = None,
    payload: Optional[str] = None,
) -> Evidence:
    """Capture a full HTTP request/response as evidence."""
    parts = [
        f"{method} {url}",
        f"Status: {status_code}",
    ]

    if payload:
        parts.append(f"Payload: {payload}")

    if request_headers:
        parts.append(f"Request Headers: {json.dumps(request_headers, indent=2)}")

    if response_headers:
        parts.append(f"Response Headers: {json.dumps(response_headers, indent=2)}")

    if response_body:
        body_preview = response_body[:500]
        parts.append(f"Response Body:\n{body_preview}")

    return Evidence(
        type="http_request",
        data="\n\n".join(parts),
        description=f"{method} {url} → {status_code}",
    )


def generate_curl_command(
    method: str,
    url: str,
    headers: Optional[Dict[str, str]] = None,
    data: Optional[str] = None,
) -> Evidence:
    """Generate a curl command as evidence."""
    parts = [f"curl -X {method}"]

    if headers:
        for k, v in headers.items():
            parts.append(f"-H '{k}: {v}'")

    if data:
        parts.append(f"-d '{data}'")

    parts.append(f"'{url}'")

    return Evidence(
        type="curl_cmd",
        data=" \\\n  ".join(parts),
        description=f"curl command for {method} {url}",
    )
