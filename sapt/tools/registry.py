"""
SAPT Tool Registry — Central registry of all available tool wrappers.
Provides check_all_tools() for the `sapt check` command.
"""

from __future__ import annotations

from typing import Any, Dict, Type

from sapt.tools.base import BaseTool

# ── Import all tools ─────────────────────────────────────────────────────────

from sapt.tools.recon.subfinder import SubfinderTool
from sapt.tools.recon.httpx_tool import HttpxTool
from sapt.tools.recon.katana import KatanaTool
from sapt.tools.recon.dnsx import DnsxTool

from sapt.tools.scan.nuclei import NucleiTool
from sapt.tools.scan.naabu import NaabuTool
from sapt.tools.scan.ffuf import FfufTool
from sapt.tools.scan.arjun import ArjunTool

from sapt.tools.exploit.sqlmap import SqlmapTool


# ── Tool Registry ────────────────────────────────────────────────────────────

TOOL_REGISTRY: Dict[str, Type[BaseTool]] = {
    # Recon tools
    "subfinder": SubfinderTool,
    "httpx":     HttpxTool,
    "katana":    KatanaTool,
    "dnsx":      DnsxTool,
    # Scan tools
    "nuclei":    NucleiTool,
    "naabu":     NaabuTool,
    "ffuf":      FfufTool,
    "arjun":     ArjunTool,
    # Exploit tools
    "sqlmap":    SqlmapTool,
}

# ── Tool metadata for extended info ──────────────────────────────────────────

TOOL_METADATA: Dict[str, Dict[str, Any]] = {
    "subfinder": {"category": "recon",   "critical": True,  "desc": "Subdomain enumeration"},
    "httpx":     {"category": "recon",   "critical": True,  "desc": "HTTP probing & tech detection"},
    "katana":    {"category": "recon",   "critical": False, "desc": "Web crawler / spider"},
    "dnsx":      {"category": "recon",   "critical": False, "desc": "DNS resolution & brute-force"},
    "nuclei":    {"category": "scan",    "critical": True,  "desc": "Template-based vuln scanner"},
    "naabu":     {"category": "scan",    "critical": False, "desc": "Port scanner"},
    "ffuf":      {"category": "scan",    "critical": False, "desc": "Web fuzzer"},
    "arjun":     {"category": "scan",    "critical": False, "desc": "HTTP parameter discovery"},
    "sqlmap":    {"category": "exploit", "critical": False, "desc": "SQL injection testing"},
}


def check_all_tools() -> Dict[str, Dict[str, Any]]:
    """
    Run availability check for all registered tools.
    Returns dict of {tool_name: {status, path, version, install_cmd, category, critical, desc}}.
    """
    results = {}
    for name, tool_class in TOOL_REGISTRY.items():
        info = tool_class.check_availability()
        meta = TOOL_METADATA.get(name, {})
        results[name] = {**info, **meta}
    return results


def get_tool(name: str) -> Type[BaseTool]:
    """Get tool class by name. Raises KeyError if not registered."""
    if name not in TOOL_REGISTRY:
        raise KeyError(f"Tool '{name}' not found in registry. Available: {list(TOOL_REGISTRY.keys())}")
    return TOOL_REGISTRY[name]
