"""Katana — Web crawler / spider tool wrapper."""

import json
from typing import Any, Dict, List

from sapt.tools.base import BaseTool, ToolResult


class KatanaTool(BaseTool):
    binary_name = "katana"
    install_cmd = "go install -v github.com/projectdiscovery/katana/cmd/katana@latest"
    required_for = ["recon"]

    def build_command(self, target: str, **kwargs) -> List[str]:
        cmd = [
            self.binary_name,
            "-u", target,
            "-silent",
            "-json",
            "-js-crawl",
            "-known-files", "all",
        ]

        depth = kwargs.get("depth", 3)
        cmd.extend(["-depth", str(depth)])

        return cmd

    def parse_output(self, result: ToolResult) -> List[Dict]:
        if not result.success:
            return []
        endpoints = []
        for line in result.stdout.splitlines():
            try:
                endpoints.append(json.loads(line))
            except json.JSONDecodeError:
                continue
        return endpoints
