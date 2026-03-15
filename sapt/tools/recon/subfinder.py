"""Subfinder — Subdomain enumeration tool wrapper."""

from typing import Any, Dict, List

from sapt.tools.base import BaseTool, ToolResult


class SubfinderTool(BaseTool):
    binary_name = "subfinder"
    install_cmd = "go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest"
    required_for = ["recon"]

    def build_command(self, target: str, **kwargs) -> List[str]:
        cmd = [self.binary_name, "-d", target, "-silent", "-all"]

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
