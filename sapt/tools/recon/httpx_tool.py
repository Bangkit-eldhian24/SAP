"""Httpx — HTTP probing and tech detection tool wrapper."""

import json
from typing import Any, Dict, List

from sapt.tools.base import BaseTool, ToolResult


class HttpxTool(BaseTool):
    binary_name = "httpx"
    install_cmd = "go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest"
    required_for = ["recon"]

    def build_command(self, target: str, **kwargs) -> List[str]:
        threads = (
            self.config.get("recon", {})
            .get("http_probe", {})
            .get("threads", 50)
        )
        timeout = (
            self.config.get("recon", {})
            .get("http_probe", {})
            .get("timeout", 10)
        )

        cmd = [
            self.binary_name,
            "-l", target,
            "-silent",
            "-json",
            "-title",
            "-tech-detect",
            "-status-code",
            "-threads", str(threads),
            "-timeout", str(timeout),
        ]

        follow_redirects = (
            self.config.get("recon", {})
            .get("http_probe", {})
            .get("follow_redirects", True)
        )
        if follow_redirects:
            cmd.append("-follow-redirects")

        return cmd

    def parse_output(self, result: ToolResult) -> List[Dict]:
        if not result.success:
            return []
        hosts = []
        for line in result.stdout.splitlines():
            try:
                hosts.append(json.loads(line))
            except json.JSONDecodeError:
                continue
        return hosts
