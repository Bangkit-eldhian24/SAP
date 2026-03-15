"""
SAPT Config — YAML config loader, validator, and default generator.
Loads sapt.yaml, merges with CLI overrides, validates required fields.
"""

from __future__ import annotations

import copy
from pathlib import Path
from typing import Any, Dict, Optional

import yaml

from sapt.core.exceptions import ConfigError
from sapt.core.logger import get_logger

# ── Default Configuration ────────────────────────────────────────────────────

DEFAULT_CONFIG: Dict[str, Any] = {
    "version": "1.0",
    "target": {
        "domain": "",
        "scope_file": None,
        "exclude_file": None,
        "profile": "generic_web",
    },
    "mode": {
        "default": "bb",
        "time_limit": 180,
    },
    "tools": {
        "subfinder": None,
        "httpx": None,
        "nuclei": None,
        "naabu": None,
        "ffuf": None,
        "katana": None,
        "dnsx": None,
        "arjun": None,
        "sqlmap": None,
    },
    "recon": {
        "subdomain": {
            "enabled": True,
            "tools": ["subfinder", "assetfinder"],
            "dns_brute": False,
            "wordlist": None,
        },
        "http_probe": {
            "enabled": True,
            "timeout": 10,
            "threads": 50,
            "follow_redirects": True,
        },
        "tech_detection": {
            "enabled": True,
            "cve_lookup": True,
            "nvd_api_key": None,
        },
        "js_analysis": {
            "enabled": True,
            "deobfuscate": True,
            "extract_endpoints": True,
            "extract_secrets": True,
        },
    },
    "scanning": {
        "nuclei": {
            "enabled": True,
            "severity": ["critical", "high", "medium"],
            "rate_limit": 150,
            "templates": None,
            "custom_templates": None,
        },
        "owasp": {
            "enabled": ["A01", "A02", "A03", "A05", "A06", "A07", "A10"],
        },
        "api_testing": {
            "enabled": True,
            "graphql": True,
            "rest": True,
            "websocket": False,
        },
        "fuzzing": {
            "enabled": True,
            "wordlist": None,
        },
    },
    "exploitation": {
        "verify_findings": True,
        "poc_generation": True,
        "safe_mode": True,
        "impact_assessment": True,
    },
    "reporting": {
        "formats": ["html", "json"],
        "executive_summary": True,
        "compliance_mapping": [],
        "cvss_scoring": True,
    },
    "notify": {
        "telegram": {
            "enabled": False,
            "bot_token": "",
            "chat_id": "",
            "notify_on": ["phase_complete", "critical_finding"],
        },
        "slack": {
            "enabled": False,
            "webhook_url": "",
        },
    },
    "output": {
        "base_dir": "./output",
        "keep_raw": True,
        "compress_old": False,
    },
    "logging": {
        "level": "info",
        "file": None,
        "save_to_file": True,
    },
}


# ── Deep Merge Helper ────────────────────────────────────────────────────────

def _deep_merge(base: Dict, override: Dict) -> Dict:
    """Deep merge override into base. Override values win."""
    result = copy.deepcopy(base)
    for key, value in override.items():
        if (
            key in result
            and isinstance(result[key], dict)
            and isinstance(value, dict)
        ):
            result[key] = _deep_merge(result[key], value)
        else:
            result[key] = copy.deepcopy(value)
    return result


# ── Config Class ─────────────────────────────────────────────────────────────

class SAPTConfig:
    """SAPT configuration manager."""

    def __init__(self, config_data: Optional[Dict[str, Any]] = None):
        self._data = _deep_merge(DEFAULT_CONFIG, config_data or {})

    @classmethod
    def load(cls, config_path: str = "sapt.yaml") -> "SAPTConfig":
        """Load config from YAML file, merged with defaults."""
        path = Path(config_path)
        if not path.exists():
            get_logger().warning(
                f"Config file '{config_path}' not found, using defaults."
            )
            return cls()

        try:
            with open(path, "r", encoding="utf-8") as f:
                user_config = yaml.safe_load(f) or {}
        except yaml.YAMLError as e:
            raise ConfigError(f"Invalid YAML in '{config_path}': {e}")

        return cls(user_config)

    @classmethod
    def generate_default(cls, output_path: str = "sapt.yaml") -> Path:
        """Generate a default sapt.yaml config file."""
        path = Path(output_path)
        content = _build_default_yaml()
        path.write_text(content, encoding="utf-8")
        return path

    def get(self, key: str, default: Any = None) -> Any:
        """Get a config value by dot-notation key. E.g. 'recon.subdomain.enabled'."""
        keys = key.split(".")
        value = self._data
        for k in keys:
            if isinstance(value, dict):
                value = value.get(k)
            else:
                return default
            if value is None:
                return default
        return value

    def set(self, key: str, value: Any):
        """Set a config value by dot-notation key."""
        keys = key.split(".")
        data = self._data
        for k in keys[:-1]:
            if k not in data or not isinstance(data[k], dict):
                data[k] = {}
            data = data[k]
        data[keys[-1]] = value

    @property
    def data(self) -> Dict[str, Any]:
        """Raw config dict."""
        return self._data

    def validate(self) -> bool:
        """Validate configuration. Raises ConfigError on problems."""
        mode = self.get("mode.default", "bb")
        valid_modes = ["bb", "stealth", "mass"]
        if mode not in valid_modes:
            raise ConfigError(
                f"Invalid mode '{mode}'. Must be one of: {valid_modes}"
            )

        profile = self.get("target.profile", "generic_web")
        valid_profiles = [
            "ecommerce", "fintech", "api_only", "cms", "generic_web"
        ]
        if profile not in valid_profiles:
            raise ConfigError(
                f"Invalid target profile '{profile}'. "
                f"Must be one of: {valid_profiles}"
            )

        time_limit = self.get("mode.time_limit", 180)
        if not isinstance(time_limit, (int, float)) or time_limit < 0:
            raise ConfigError(
                f"Invalid time_limit '{time_limit}'. Must be >= 0."
            )

        return True

    def to_yaml(self) -> str:
        """Serialize config to YAML string."""
        return yaml.dump(
            self._data, default_flow_style=False, sort_keys=False,
            allow_unicode=True,
        )


def _build_default_yaml() -> str:
    """Build the default sapt.yaml with comments."""
    return """\
# ═══════════════════════════════════════════════════════════════════════════
# SAPT — Semi-Automated Pentest Tool Configuration
# ═══════════════════════════════════════════════════════════════════════════
version: "1.0"

target:
  domain: ""                            # Override with --target flag
  scope_file: null                      # Path to scope.txt
  exclude_file: null                    # Path to exclude.txt
  profile: "generic_web"                # ecommerce | fintech | api_only | cms | generic_web

mode:
  default: "bb"                         # bb | stealth | mass
  time_limit: 180                       # minutes, 0 = unlimited

tools:
  # Auto-detected from PATH — override here if needed
  subfinder: null
  httpx: null
  nuclei: null
  naabu: null
  ffuf: null
  katana: null
  dnsx: null
  arjun: null
  sqlmap: null

recon:
  subdomain:
    enabled: true
    tools: ["subfinder", "assetfinder"]
    dns_brute: false
    wordlist: null                      # uses built-in if null
  http_probe:
    enabled: true
    timeout: 10
    threads: 50
    follow_redirects: true
  tech_detection:
    enabled: true
    cve_lookup: true
    nvd_api_key: null                   # optional, increases rate limit
  js_analysis:
    enabled: true
    deobfuscate: true
    extract_endpoints: true
    extract_secrets: true

scanning:
  nuclei:
    enabled: true
    severity: ["critical", "high", "medium"]
    rate_limit: 150
    templates: null                     # null = default nuclei-templates
    custom_templates: null
  owasp:
    enabled: ["A01", "A02", "A03", "A05", "A06", "A07", "A10"]
  api_testing:
    enabled: true
    graphql: true
    rest: true
    websocket: false
  fuzzing:
    enabled: true
    wordlist: null                      # null = built-in SecLists subset

exploitation:
  verify_findings: true
  poc_generation: true
  safe_mode: true                       # skip destructive tests
  impact_assessment: true

reporting:
  formats: ["html", "json"]
  executive_summary: true
  compliance_mapping: []                # ["pci-dss", "owasp", "nist"]
  cvss_scoring: true

notify:
  telegram:
    enabled: false
    bot_token: ""
    chat_id: ""
    notify_on: ["phase_complete", "critical_finding"]
  slack:
    enabled: false
    webhook_url: ""

output:
  base_dir: "./output"
  keep_raw: true
  compress_old: false

logging:
  level: "info"                         # debug | info | warning | error
  file: null                            # null = stdout only
  save_to_file: true
"""
