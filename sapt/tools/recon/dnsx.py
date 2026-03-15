"""Dnsx — DNS resolution and brute-force tool wrapper."""

from typing import Any, Dict, List

from sapt.tools.base import BaseTool, ToolResult


class DnsxTool(BaseTool):
    binary_name = "dnsx"
    install_cmd = "go install -v github.com/projectdiscovery/dnsx/cmd/dnsx@latest"
    required_for = ["recon"]

    def build_command(self, target: str, **kwargs) -> List[str]:
        cmd = [
            self.binary_name,
            "-l", target,
            "-silent",
            "-a",
            "-resp",
        ]

        wordlist = kwargs.get("wordlist")
        if wordlist:
            cmd.extend(["-w", wordlist])

        return cmd

    def parse_output(self, result: ToolResult) -> List[str]:
        if not result.success:
            return []
        return [
            line.strip()
            for line in result.stdout.splitlines()
            if line.strip()
        ]
