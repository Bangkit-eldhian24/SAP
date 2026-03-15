"""
SAPT Phase 1: Recon — Reconnaissance phase implementation.
Runs subdomain enumeration, HTTP probing, tech detection, JS analysis.
"""

from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path
from typing import Optional

from sapt.core.config import SAPTConfig
from sapt.core.logger import get_logger, log_phase, log_success, log_tool
from sapt.models.models import (
    LiveHost, PhaseStatus, ReconResults, TechDetection,
)


class ReconPhase:
    """Phase 1: Reconnaissance."""

    def __init__(self, config: SAPTConfig, target: str):
        self.config = config
        self.target = target
        self.logger = get_logger()
        base_dir = config.get("output.base_dir", "./output")
        self.output_dir = Path(base_dir) / target / "recon"
        self.output_dir.mkdir(parents=True, exist_ok=True)

    async def run(self) -> ReconResults:
        """Run all configured recon modules."""
        results = ReconResults(target=self.target, started_at=datetime.now())
        results.status = PhaseStatus.RUNNING

        try:
            # ── Subdomain Enumeration ─────────────────────────────────────
            if self.config.get("recon.subdomain.enabled", True):
                log_tool("Subfinder", "Running subdomain enumeration...")
                subdomains = await self._run_subdomain_enum()
                results.subdomains = subdomains
                results.total_subdomains = len(subdomains)
                self._save_file("subdomains.txt", "\n".join(subdomains))
                log_success(f"Found {len(subdomains)} subdomains")

            # ── HTTP Probing ──────────────────────────────────────────────
            if self.config.get("recon.http_probe.enabled", True):
                log_tool("Httpx", "Probing live hosts...")
                live_hosts = await self._run_http_probe(results.subdomains)
                results.live_hosts = live_hosts
                results.total_live = len(live_hosts)
                urls = [h.url for h in live_hosts]
                self._save_file("live_hosts.txt", "\n".join(urls))
                log_success(f"Found {len(live_hosts)} live hosts")

            # ── Tech Detection ────────────────────────────────────────────
            if self.config.get("recon.tech_detection.enabled", True):
                log_tool("TechDetector", "Detecting technology stack...")
                await self._run_tech_detection(results)
                log_success("Tech detection completed")

            # ── JS Analysis ───────────────────────────────────────────────
            if self.config.get("recon.js_analysis.enabled", True):
                log_tool("JSAnalyzer", "Analyzing JavaScript files...")
                await self._run_js_analysis(results)
                log_success("JS analysis completed")

            results.status = PhaseStatus.COMPLETED
            results.completed_at = datetime.now()

            # Save full results
            self._save_json("recon_results.json", results.model_dump(mode="json"))

        except Exception as e:
            results.status = PhaseStatus.FAILED
            self.logger.error(f"Recon phase failed: {e}")
            raise

        return results

    async def _run_subdomain_enum(self) -> list[str]:
        """Run subdomain enumeration with configured tools."""
        from sapt.tools.recon.subfinder import SubfinderTool

        tool = SubfinderTool(self.config.data, self.output_dir)
        result = await tool.run(self.target, timeout=120)

        if result.success and result.parsed_data:
            return result.parsed_data
        else:
            self.logger.warning(f"Subfinder: {result.error_message or 'No results'}")
            return [self.target]

    async def _run_http_probe(self, subdomains: list[str]) -> list[LiveHost]:
        """Probe subdomains for live HTTP hosts."""
        from sapt.tools.recon.httpx_tool import HttpxTool

        if not subdomains:
            return []

        # Write subdomains to temp file for httpx input
        input_file = self.output_dir / "_temp_hosts.txt"
        input_file.write_text("\n".join(subdomains), encoding="utf-8")

        tool = HttpxTool(self.config.data, self.output_dir)
        result = await tool.run(str(input_file), timeout=180)

        live_hosts = []
        if result.success and result.parsed_data:
            from sapt.modules.waf_detector import detect_waf_from_headers

            for host_data in result.parsed_data:
                host = LiveHost(
                    url=host_data.get("url", ""),
                    ip=host_data.get("host", host_data.get("a", [None])),
                    status_code=host_data.get("status_code", 0),
                    title=host_data.get("title", ""),
                    headers=host_data.get("header", {}),
                )

                # WAF detection from headers
                if host.headers:
                    waf = detect_waf_from_headers(host.headers)
                    if waf:
                        host.waf_detected = waf

                # Tech stack from httpx
                techs = host_data.get("tech", [])
                for tech_str in techs:
                    name = tech_str.split(":")[0] if ":" in tech_str else tech_str
                    version = tech_str.split(":")[1] if ":" in tech_str else None
                    host.tech_stack.append(TechDetection(
                        name=name, version=version, confidence=0.8,
                    ))

                live_hosts.append(host)

        # Cleanup temp file
        input_file.unlink(missing_ok=True)

        return live_hosts

    async def _run_tech_detection(self, results: ReconResults):
        """Enrich tech detections with CVE lookups."""
        from sapt.modules.tech_detector import enrich_with_cves

        api_key = self.config.get("recon.tech_detection.nvd_api_key")
        cve_lookup = self.config.get("recon.tech_detection.cve_lookup", True)

        if not cve_lookup:
            return

        for host in results.live_hosts:
            if host.tech_stack:
                host.tech_stack = enrich_with_cves(host.tech_stack, api_key)
                host.cve_candidates = []
                for tech in host.tech_stack:
                    host.cve_candidates.extend(tech.cve_ids)

        self._save_json("tech_stack.json", {
            h.url: [t.model_dump() for t in h.tech_stack]
            for h in results.live_hosts if h.tech_stack
        })

    async def _run_js_analysis(self, results: ReconResults):
        """Run JS analysis on live hosts."""
        from sapt.modules.js_analyzer import analyze_js

        js_urls = []
        for host in results.live_hosts:
            js_urls.append(f"{host.url}/main.js")
            js_urls.append(f"{host.url}/app.js")
            js_urls.append(f"{host.url}/bundle.js")

        if js_urls:
            js_findings = await analyze_js(
                js_urls,
                extract_eps=self.config.get("recon.js_analysis.extract_endpoints", True),
                extract_secs=self.config.get("recon.js_analysis.extract_secrets", True),
            )

            for host in results.live_hosts:
                host.js_findings = [f for f in js_findings if host.url in f.js_url]

            js_dir = self.output_dir / "js_analysis"
            js_dir.mkdir(exist_ok=True)
            self._save_json(
                "js_analysis/js_findings.json",
                [f.model_dump() for f in js_findings],
            )

    def _save_file(self, filename: str, content: str):
        """Save text content to output directory."""
        path = self.output_dir / filename
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")

    def _save_json(self, filename: str, data):
        """Save JSON data to output directory."""
        path = self.output_dir / filename
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(
            json.dumps(data, indent=2, default=str),
            encoding="utf-8",
        )
