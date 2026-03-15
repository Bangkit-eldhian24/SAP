"""
SAPT Data Models — v1.0
All Pydantic models for type-safe data flow between phases.
Includes TargetProfile for threat modeling (Gap #1 fix).
"""

from __future__ import annotations

from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field


# ─────────────────────────────────────────────────────────────────────────────
# ENUMS
# ─────────────────────────────────────────────────────────────────────────────

class TestingMode(str, Enum):
    BB      = "bb"
    STEALTH = "stealth"
    MASS    = "mass"


class SeverityLevel(str, Enum):
    CRITICAL = "critical"
    HIGH     = "high"
    MEDIUM   = "medium"
    LOW      = "low"
    INFO     = "info"


class VulnerabilityType(str, Enum):
    IDOR               = "idor"
    SQLI               = "sqli"
    NOSQLI             = "nosqli"
    XSS                = "xss"
    SSRF               = "ssrf"
    XXE                = "xxe"
    SSTI               = "ssti"
    RCE                = "rce"
    AUTH_BYPASS         = "auth_bypass"
    JWT_BYPASS          = "jwt_bypass"
    PRIVILEGE_ESC       = "privilege_escalation"
    BUSINESS_LOGIC      = "business_logic"
    MISCONFIG           = "misconfiguration"
    SENSITIVE_EXPOSURE  = "sensitive_exposure"
    KNOWN_CVE           = "known_cve"
    CUSTOM              = "custom"


class PhaseStatus(str, Enum):
    PENDING   = "pending"
    RUNNING   = "running"
    COMPLETED = "completed"
    FAILED    = "failed"
    SKIPPED   = "skipped"


class ToolStatus(str, Enum):
    AVAILABLE   = "available"
    NOT_FOUND   = "not_found"
    VERSION_LOW = "version_low"
    ERROR       = "error"


class TargetProfile(str, Enum):
    """Target classification for threat modeling (Gap #1 fix)."""
    ECOMMERCE   = "ecommerce"
    FINTECH     = "fintech"
    API_ONLY    = "api_only"
    CMS         = "cms"
    GENERIC_WEB = "generic_web"


# ── Threat Model Priority Map ────────────────────────────────────────────────

PRIORITY_MAP: Dict[TargetProfile, List[str]] = {
    TargetProfile.ECOMMERCE:   ["A04", "A01", "A02", "A07", "A03"],
    TargetProfile.FINTECH:     ["A04", "A01", "A07", "A02", "A03"],
    TargetProfile.API_ONLY:    ["A01", "A07", "A10", "A03", "A02"],
    TargetProfile.CMS:         ["A06", "A03", "A01", "A05", "A07"],
    TargetProfile.GENERIC_WEB: ["A01", "A03", "A07", "A02", "A10"],
}


# ─────────────────────────────────────────────────────────────────────────────
# TOOL AVAILABILITY
# ─────────────────────────────────────────────────────────────────────────────

class ToolInfo(BaseModel):
    name: str
    status: ToolStatus
    path: Optional[str] = None
    version: Optional[str] = None
    install_cmd: Optional[str] = None
    required_for: List[str] = Field(default_factory=list)


class ToolCheckResult(BaseModel):
    checked_at: datetime = Field(default_factory=datetime.now)
    tools: List[ToolInfo] = Field(default_factory=list)
    core_ready: bool = False
    full_ready: bool = False
    missing_critical: List[str] = Field(default_factory=list)
    missing_optional: List[str] = Field(default_factory=list)

    def summary(self) -> str:
        available = [t for t in self.tools if t.status == ToolStatus.AVAILABLE]
        return f"{len(available)}/{len(self.tools)} tools available"


# ─────────────────────────────────────────────────────────────────────────────
# RECON PHASE (Phase 1)
# ─────────────────────────────────────────────────────────────────────────────

class TechDetection(BaseModel):
    name: str
    version: Optional[str] = None
    confidence: float = 0.0
    cve_ids: List[str] = Field(default_factory=list)
    nuclei_templates: List[str] = Field(default_factory=list)


class JSFinding(BaseModel):
    js_url: str
    finding_type: str           # "api_endpoint" | "secret" | "vulnerable_function"
    value: str
    context: Optional[str] = None
    severity: SeverityLevel = SeverityLevel.INFO


class LiveHost(BaseModel):
    url: str
    ip: Optional[str] = None
    status_code: int = 0
    title: Optional[str] = None
    tech_stack: List[TechDetection] = Field(default_factory=list)
    open_ports: List[int] = Field(default_factory=list)
    cve_candidates: List[str] = Field(default_factory=list)
    js_findings: List[JSFinding] = Field(default_factory=list)
    headers: Dict[str, str] = Field(default_factory=dict)
    waf_detected: Optional[str] = None


class ReconResults(BaseModel):
    target: str
    started_at: datetime = Field(default_factory=datetime.now)
    completed_at: Optional[datetime] = None
    status: PhaseStatus = PhaseStatus.PENDING
    subdomains: List[str] = Field(default_factory=list)
    live_hosts: List[LiveHost] = Field(default_factory=list)
    total_subdomains: int = 0
    total_live: int = 0

    def get_urls(self) -> List[str]:
        return [h.url for h in self.live_hosts]

    def get_cve_candidates(self) -> Dict[str, List[str]]:
        return {
            h.url: h.cve_candidates
            for h in self.live_hosts
            if h.cve_candidates
        }


# ─────────────────────────────────────────────────────────────────────────────
# SCAN PHASE (Phase 2)
# ─────────────────────────────────────────────────────────────────────────────

class Evidence(BaseModel):
    type: str                   # "http_request" | "screenshot" | "curl_cmd"
    data: str
    description: Optional[str] = None


class Finding(BaseModel):
    id: str
    target_url: str
    vuln_type: VulnerabilityType
    severity: SeverityLevel
    title: str
    description: str
    owasp_category: Optional[str] = None
    cve_id: Optional[str] = None
    cvss_score: Optional[float] = None
    evidence: List[Evidence] = Field(default_factory=list)
    reproduction_steps: List[str] = Field(default_factory=list)
    tool_source: str = ""
    verified: bool = False
    false_positive: bool = False
    found_at: datetime = Field(default_factory=datetime.now)


class ScanResults(BaseModel):
    target: str
    started_at: datetime = Field(default_factory=datetime.now)
    completed_at: Optional[datetime] = None
    status: PhaseStatus = PhaseStatus.PENDING
    findings: List[Finding] = Field(default_factory=list)
    nuclei_findings: List[Dict[str, Any]] = Field(default_factory=list)
    total_findings: int = 0

    def by_severity(self, severity: SeverityLevel) -> List[Finding]:
        return [f for f in self.findings if f.severity == severity]

    def critical_count(self) -> int:
        return len(self.by_severity(SeverityLevel.CRITICAL))

    def unverified(self) -> List[Finding]:
        return [
            f for f in self.findings
            if not f.verified and not f.false_positive
        ]


# ─────────────────────────────────────────────────────────────────────────────
# EXPLOITATION PHASE (Phase 3)
# ─────────────────────────────────────────────────────────────────────────────

class POC(BaseModel):
    finding_id: str
    language: str               # "python" | "bash" | "curl"
    code: str
    description: str
    file_path: Optional[str] = None


class ExploitResult(BaseModel):
    finding_id: str
    verified: bool = False
    exploitable: bool = False
    impact: Optional[str] = None
    data_accessed: Optional[str] = None
    poc_scripts: List[POC] = Field(default_factory=list)
    screenshots: List[str] = Field(default_factory=list)
    http_evidence: List[str] = Field(default_factory=list)


class ImpactAssessment(BaseModel):
    financial_impact: Optional[str] = None
    data_at_risk: Optional[str] = None
    affected_users: Optional[str] = None
    compliance_violations: List[str] = Field(default_factory=list)
    overall_risk: SeverityLevel = SeverityLevel.INFO


class ExploitationResults(BaseModel):
    target: str
    started_at: datetime = Field(default_factory=datetime.now)
    completed_at: Optional[datetime] = None
    status: PhaseStatus = PhaseStatus.PENDING
    exploit_results: List[ExploitResult] = Field(default_factory=list)
    impact: Optional[ImpactAssessment] = None
    confirmed_vulnerabilities: int = 0
    false_positives_removed: int = 0


# ─────────────────────────────────────────────────────────────────────────────
# REPORT (Phase 4)
# ─────────────────────────────────────────────────────────────────────────────

class SAPTReport(BaseModel):
    target: str
    generated_at: datetime = Field(default_factory=datetime.now)
    mode: TestingMode = TestingMode.BB
    duration_minutes: float = 0.0
    recon_summary: Dict[str, Any] = Field(default_factory=dict)
    scan_summary: Dict[str, Any] = Field(default_factory=dict)
    findings: List[Finding] = Field(default_factory=list)
    exploit_results: List[ExploitResult] = Field(default_factory=list)
    impact: Optional[ImpactAssessment] = None
    critical_count: int = 0
    high_count: int = 0
    medium_count: int = 0
    low_count: int = 0
    info_count: int = 0
    compliance_references: List[str] = Field(default_factory=list)
    report_paths: Dict[str, str] = Field(default_factory=dict)


# ─────────────────────────────────────────────────────────────────────────────
# SAPT STATE — persisted to SQLite across phases
# ─────────────────────────────────────────────────────────────────────────────

class SAPTState(BaseModel):
    """
    Central state object. Saved as JSON in SQLite.
    Each phase reads/writes to this — enables resume on crash.
    """
    target: str
    mode: TestingMode = TestingMode.BB
    config_path: str = "sapt.yaml"
    started_at: datetime = Field(default_factory=datetime.now)
    last_updated: datetime = Field(default_factory=datetime.now)

    phase_recon:   PhaseStatus = PhaseStatus.PENDING
    phase_scan:    PhaseStatus = PhaseStatus.PENDING
    phase_exploit: PhaseStatus = PhaseStatus.PENDING
    phase_report:  PhaseStatus = PhaseStatus.PENDING

    recon_results:        Optional[ReconResults] = None
    scan_results:         Optional[ScanResults] = None
    exploitation_results: Optional[ExploitationResults] = None

    tool_check: Optional[ToolCheckResult] = None
    output_dir: str = "./output"

    def can_resume(self) -> bool:
        return any([
            self.phase_recon == PhaseStatus.COMPLETED,
            self.phase_scan  == PhaseStatus.COMPLETED,
        ])

    def next_phase(self) -> Optional[str]:
        if self.phase_recon != PhaseStatus.COMPLETED:
            return "recon"
        if self.phase_scan != PhaseStatus.COMPLETED:
            return "scan"
        if self.phase_exploit != PhaseStatus.COMPLETED:
            return "exploit"
        if self.phase_report != PhaseStatus.COMPLETED:
            return "report"
        return None
