"""
SAPT Phase 2: Scan — Vulnerability scanning phase implementation.
Runs Nuclei scanning, OWASP-specific tests, and custom scanning modules.
"""

from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path
from typing import List, Optional

from sapt.core.config import SAPTConfig
from sapt.core.logger import get_logger, log_phase, log_success, log_tool
from sapt.models.models import (
    Finding, PhaseStatus, ScanResults, SeverityLevel, VulnerabilityType,
)


class ScanPhase:
    """Phase 2: Vulnerability Scanning."""

    def __init__(
        self, config: SAPTConfig, target: str,
        hosts_file: Optional[str] = None,
    ):
        self.config = config
        self.target = target
        self.hosts_file = hosts_file
        self.logger = get_logger()
        base_dir = config.get("output.base_dir", "./output")
        self.output_dir = Path(base_dir) / target / "scan"
        self.output_dir.mkdir(parents=True, exist_ok=True)

    async def run(self) -> ScanResults:
        """Run all configured scan modules."""
        results = ScanResults(target=self.target, started_at=datetime.now())
        results.status = PhaseStatus.RUNNING

        try:
            # Determine target URLs
            target_urls = await self._get_target_urls()

            # ── Nuclei Scanning ───────────────────────────────────────────
            if self.config.get("scanning.nuclei.enabled", True):
                log_tool("Nuclei", "Running template-based scanning...")
                nuclei_findings = await self._run_nuclei(target_urls)
                results.nuclei_findings = nuclei_findings
                log_success(f"Nuclei found {len(nuclei_findings)} results")

            # ── OWASP Testing ─────────────────────────────────────────────
            owasp_categories = self.config.get("scanning.owasp.enabled", [])
            if owasp_categories:
                log_tool("OWASP", f"Testing categories: {', '.join(owasp_categories)}")
                owasp_findings = await self._run_owasp_tests(target_urls, owasp_categories)
                results.findings.extend(owasp_findings)

            # ── API Testing ───────────────────────────────────────────────
            if self.config.get("scanning.api_testing.enabled", True):
                log_tool("API", "Running API-specific tests...")
                api_findings = await self._run_api_tests(target_urls)
                results.findings.extend(api_findings)

            # ── Finalize ──────────────────────────────────────────────────
            results.total_findings = len(results.findings)
            results.status = PhaseStatus.COMPLETED
            results.completed_at = datetime.now()

            self._save_json("scan_results.json", results.model_dump(mode="json"))
            log_success(f"Scan complete: {results.total_findings} total findings")

        except Exception as e:
            results.status = PhaseStatus.FAILED
            self.logger.error(f"Scan phase failed: {e}")
            raise

        return results

    async def _get_target_urls(self) -> List[str]:
        """Get target URLs from hosts file or fallback to target domain."""
        if self.hosts_file:
            path = Path(self.hosts_file)
            if path.exists():
                return [
                    line.strip() for line in path.read_text().splitlines()
                    if line.strip()
                ]

        # Fallback: check recon output
        recon_file = Path(
            self.config.get("output.base_dir", "./output")
        ) / self.target / "recon" / "live_hosts.txt"

        if recon_file.exists():
            return [
                line.strip() for line in recon_file.read_text().splitlines()
                if line.strip()
            ]

        return [f"https://{self.target}", f"http://{self.target}"]

    async def _run_nuclei(self, target_urls: List[str]) -> List[dict]:
        """Run Nuclei scanner."""
        from sapt.tools.scan.nuclei import NucleiTool

        input_file = self.output_dir / "_temp_targets.txt"
        input_file.write_text("\n".join(target_urls), encoding="utf-8")

        tool = NucleiTool(self.config.data, self.output_dir)
        result = await tool.run(str(input_file), timeout=600)

        input_file.unlink(missing_ok=True)

        if result.success and result.parsed_data:
            self._save_json("nuclei_results.jsonl", result.parsed_data)
            return result.parsed_data
        return []

    async def _run_owasp_tests(
        self, target_urls: List[str], categories: List[str],
    ) -> List[Finding]:
        """Run OWASP-specific tests based on enabled categories."""
        findings: List[Finding] = []

        for category in categories:
            try:
                if category == "A01":
                    from sapt.modules.owasp.a01_idor import test_idor
                    findings.extend(await test_idor(target_urls))

                elif category == "A03":
                    from sapt.modules.owasp.a03_sqli import test_sqli
                    findings.extend(await test_sqli(target_urls))

                elif category == "A05":
                    from sapt.modules.owasp.a05_misconfig import test_misconfig
                    for url in target_urls[:5]:
                        findings.extend(await test_misconfig(url))

                elif category == "A07":
                    from sapt.modules.owasp.a07_auth import test_auth_bypass
                    for url in target_urls[:5]:
                        findings.extend(await test_auth_bypass(url))

                elif category == "A10":
                    from sapt.modules.owasp.a10_ssrf import test_ssrf
                    findings.extend(await test_ssrf(target_urls))

                elif category in ("A02", "A06", "A08"):
                    self.logger.info(f"  {category}: Covered by Nuclei templates")

                elif category == "A04":
                    self.logger.info(
                        f"  ⚠️  {category} Business Logic: SEMI-AUTOMATED — "
                        "Manual review required"
                    )

            except Exception as e:
                self.logger.warning(f"  {category} test failed: {e}")

        return findings

    async def _run_api_tests(self, target_urls: List[str]) -> List[Finding]:
        """Run API-specific tests."""
        findings: List[Finding] = []

        if self.config.get("scanning.api_testing.graphql", True):
            from sapt.api.graphql import test_graphql
            for url in target_urls[:5]:
                findings.extend(await test_graphql(url))

        if self.config.get("scanning.api_testing.rest", True):
            from sapt.api.rest import test_rest_api
            for url in target_urls[:5]:
                findings.extend(await test_rest_api(url))

        return findings

    def _save_json(self, filename: str, data):
        path = self.output_dir / filename
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(data, indent=2, default=str), encoding="utf-8")
