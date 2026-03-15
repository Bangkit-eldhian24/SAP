"""
SAPT Phase 4: Report — Report generation phase.
Generates HTML, JSON, and Markdown reports from scan results.
"""

from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path
from typing import Optional

from sapt.core.config import SAPTConfig
from sapt.core.logger import get_logger, log_success, log_tool
from sapt.models.models import PhaseStatus, SAPTReport, SAPTState, SeverityLevel


class ReportPhase:
    """Phase 4: Report Generation."""

    def __init__(
        self, config: SAPTConfig, target: str,
        state_db: Optional[str] = None,
    ):
        self.config = config
        self.target = target
        self.state_db = state_db
        self.logger = get_logger()
        base_dir = config.get("output.base_dir", "./output")
        self.output_dir = Path(base_dir) / target / "reports"
        self.output_dir.mkdir(parents=True, exist_ok=True)

    async def run(self) -> SAPTReport:
        """Generate all configured reports."""
        state = await self._load_state()
        report = self._build_report(state)

        formats = self.config.get("reporting.formats", ["html", "json"])

        for fmt in formats:
            if fmt == "json":
                log_tool("Report", "Generating JSON report...")
                self._gen_json_report(report)
            elif fmt == "html":
                log_tool("Report", "Generating HTML report...")
                self._gen_html_report(report)
            elif fmt == "md":
                log_tool("Report", "Generating Markdown report...")
                self._gen_markdown_report(report)

        log_success(f"Reports generated at: {self.output_dir}")
        return report

    async def _load_state(self) -> Optional[SAPTState]:
        """Load state from database."""
        if self.state_db:
            from sapt.core.state import StateManager
            manager = StateManager(self.state_db)
            return await manager.load()

        # Try default path
        default_db = Path(
            self.config.get("output.base_dir", "./output")
        ) / self.target / "sapt_state.db"

        if default_db.exists():
            from sapt.core.state import StateManager
            manager = StateManager(default_db)
            return await manager.load()

        return None

    def _build_report(self, state: Optional[SAPTState]) -> SAPTReport:
        """Build report from state data."""
        report = SAPTReport(target=self.target)

        if state:
            report.mode = state.mode

            if state.recon_results:
                report.recon_summary = {
                    "subdomains": state.recon_results.total_subdomains,
                    "live_hosts": state.recon_results.total_live,
                }

            if state.scan_results:
                report.findings = state.scan_results.findings
                report.scan_summary = {
                    "total_findings": state.scan_results.total_findings,
                }

            if state.exploitation_results:
                report.exploit_results = state.exploitation_results.exploit_results
                report.impact = state.exploitation_results.impact

        # Count by severity
        for finding in report.findings:
            if finding.severity == SeverityLevel.CRITICAL:
                report.critical_count += 1
            elif finding.severity == SeverityLevel.HIGH:
                report.high_count += 1
            elif finding.severity == SeverityLevel.MEDIUM:
                report.medium_count += 1
            elif finding.severity == SeverityLevel.LOW:
                report.low_count += 1
            else:
                report.info_count += 1

        return report

    def _gen_json_report(self, report: SAPTReport):
        """Generate JSON report."""
        path = self.output_dir / "sapt_report.json"
        path.write_text(
            report.model_dump_json(indent=2),
            encoding="utf-8",
        )
        report.report_paths["json"] = str(path)

    def _gen_html_report(self, report: SAPTReport):
        """Generate HTML report."""
        html = self._render_html(report)
        path = self.output_dir / "sapt_report.html"
        path.write_text(html, encoding="utf-8")
        report.report_paths["html"] = str(path)

    def _gen_markdown_report(self, report: SAPTReport):
        """Generate Markdown report."""
        md = self._render_markdown(report)
        path = self.output_dir / "sapt_report.md"
        path.write_text(md, encoding="utf-8")
        report.report_paths["md"] = str(path)

    def _render_html(self, report: SAPTReport) -> str:
        """Render HTML report."""
        findings_html = ""
        for f in report.findings:
            sev_color = {
                "critical": "#dc3545",
                "high": "#fd7e14",
                "medium": "#ffc107",
                "low": "#17a2b8",
                "info": "#6c757d",
            }.get(f.severity.value, "#6c757d")

            findings_html += f"""
            <div class="finding">
                <div class="finding-header">
                    <span class="severity" style="background:{sev_color}">{f.severity.value.upper()}</span>
                    <strong>{f.title}</strong>
                </div>
                <p>{f.description}</p>
                <p><strong>URL:</strong> {f.target_url}</p>
                <p><strong>OWASP:</strong> {f.owasp_category or 'N/A'}</p>
                <p><strong>Type:</strong> {f.vuln_type.value}</p>
            </div>
            """

        return f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>SAPT Report — {report.target}</title>
    <style>
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        body {{ font-family: 'Segoe UI', system-ui, sans-serif; background: #0a0a1a; color: #e0e0e0; padding: 2rem; }}
        .container {{ max-width: 1200px; margin: 0 auto; }}
        h1 {{ color: #00d4ff; font-size: 2rem; margin-bottom: 0.5rem; }}
        h2 {{ color: #7c8aff; margin: 2rem 0 1rem; border-bottom: 1px solid #333; padding-bottom: 0.5rem; }}
        .meta {{ color: #888; margin-bottom: 2rem; }}
        .stats {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(150px, 1fr)); gap: 1rem; margin: 1.5rem 0; }}
        .stat {{ background: #1a1a2e; border-radius: 8px; padding: 1.2rem; text-align: center; border: 1px solid #333; }}
        .stat .number {{ font-size: 2rem; font-weight: bold; }}
        .stat .label {{ color: #888; font-size: 0.85rem; margin-top: 0.3rem; }}
        .finding {{ background: #1a1a2e; border-radius: 8px; padding: 1.2rem; margin: 0.8rem 0; border-left: 4px solid #333; }}
        .finding-header {{ display: flex; align-items: center; gap: 0.8rem; margin-bottom: 0.5rem; }}
        .severity {{ color: #fff; padding: 0.2rem 0.6rem; border-radius: 4px; font-size: 0.75rem; font-weight: bold; text-transform: uppercase; }}
        .finding p {{ margin: 0.3rem 0; font-size: 0.9rem; }}
    </style>
</head>
<body>
    <div class="container">
        <h1>🔒 SAPT Security Report</h1>
        <p class="meta">Target: {report.target} | Mode: {report.mode.value} | Generated: {report.generated_at.strftime('%Y-%m-%d %H:%M')}</p>
        
        <div class="stats">
            <div class="stat"><div class="number" style="color:#dc3545">{report.critical_count}</div><div class="label">Critical</div></div>
            <div class="stat"><div class="number" style="color:#fd7e14">{report.high_count}</div><div class="label">High</div></div>
            <div class="stat"><div class="number" style="color:#ffc107">{report.medium_count}</div><div class="label">Medium</div></div>
            <div class="stat"><div class="number" style="color:#17a2b8">{report.low_count}</div><div class="label">Low</div></div>
            <div class="stat"><div class="number" style="color:#6c757d">{report.info_count}</div><div class="label">Info</div></div>
        </div>
        
        <h2>Findings</h2>
        {findings_html if findings_html else '<p>No findings to display.</p>'}
    </div>
</body>
</html>"""

    def _render_markdown(self, report: SAPTReport) -> str:
        """Render Markdown report."""
        lines = [
            f"# SAPT Security Report — {report.target}",
            "",
            f"**Mode:** {report.mode.value}  ",
            f"**Generated:** {report.generated_at.strftime('%Y-%m-%d %H:%M')}  ",
            "",
            "## Summary",
            "",
            f"| Severity | Count |",
            f"|----------|-------|",
            f"| Critical | {report.critical_count} |",
            f"| High     | {report.high_count} |",
            f"| Medium   | {report.medium_count} |",
            f"| Low      | {report.low_count} |",
            f"| Info     | {report.info_count} |",
            "",
            "## Findings",
            "",
        ]

        for f in report.findings:
            lines.extend([
                f"### [{f.severity.value.upper()}] {f.title}",
                "",
                f"- **URL:** {f.target_url}",
                f"- **Type:** {f.vuln_type.value}",
                f"- **OWASP:** {f.owasp_category or 'N/A'}",
                f"- **Description:** {f.description}",
                "",
            ])

        if not report.findings:
            lines.append("No findings to display.")

        return "\n".join(lines)
