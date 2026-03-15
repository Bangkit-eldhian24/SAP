"""Nuclei — Template-based vulnerability scanner tool wrapper."""

import json
from typing import Any, Dict, List

from sapt.tools.base import BaseTool, ToolResult


class NucleiTool(BaseTool):
    binary_name = "nuclei"
    install_cmd = "go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest"
    required_for = ["scan"]

    def build_command(self, target: str, **kwargs) -> List[str]:
        severity = ",".join(
            self.config.get("scanning", {})
            .get("nuclei", {})
            .get("severity", ["critical", "high"])
        )
        rate = str(
            self.config.get("scanning", {})
            .get("nuclei", {})
            .get("rate_limit", 150)
        )

        cmd = [
            self.binary_name,
            "-l", target,
            "-severity", severity,
            "-rate-limit", rate,
            "-jsonl",
            "-silent",
        ]

        # Custom templates
        templates = (
            self.config.get("scanning", {})
            .get("nuclei", {})
            .get("custom_templates")
        )
        if templates:
            cmd.extend(["-t", templates])

        return cmd

    def parse_output(self, result: ToolResult) -> List[Dict]:
        if not result.success:
            return []
        findings = []
        for line in result.stdout.splitlines():
            try:
                findings.append(json.loads(line))
            except json.JSONDecodeError:
                continue
        return findings
