"""Ffuf — Web fuzzer tool wrapper."""

import json
from typing import Any, Dict, List

from sapt.tools.base import BaseTool, ToolResult


class FfufTool(BaseTool):
    binary_name = "ffuf"
    install_cmd = "go install -v github.com/ffuf/ffuf/v2@latest"
    required_for = ["scan"]

    def build_command(self, target: str, **kwargs) -> List[str]:
        wordlist = kwargs.get(
            "wordlist",
            self.config.get("scanning", {}).get("fuzzing", {}).get("wordlist"),
        )

        cmd = [
            self.binary_name,
            "-u", f"{target}/FUZZ",
            "-json",
            "-mc", "200,301,302,401,403,500",
            "-ac",  # auto-calibrate
        ]

        if wordlist:
            cmd.extend(["-w", wordlist])

        rate = kwargs.get("rate")
        if rate:
            cmd.extend(["-rate", str(rate)])

        return cmd

    def parse_output(self, result: ToolResult) -> List[Dict]:
        if not result.success:
            return []
        findings = []
        for line in result.stdout.splitlines():
            try:
                data = json.loads(line)
                if "results" in data:
                    findings.extend(data["results"])
                else:
                    findings.append(data)
            except json.JSONDecodeError:
                continue
        return findings
