"""Naabu — Port scanner tool wrapper."""

from typing import Any, Dict, List

from sapt.tools.base import BaseTool, ToolResult


class NaabuTool(BaseTool):
    binary_name = "naabu"
    install_cmd = "go install -v github.com/projectdiscovery/naabu/v2/cmd/naabu@latest"
    required_for = ["scan"]

    def build_command(self, target: str, **kwargs) -> List[str]:
        cmd = [
            self.binary_name,
            "-host", target,
            "-silent",
            "-json",
        ]

        ports = kwargs.get("ports", "top-100")
        cmd.extend(["-top-ports", ports] if ports.startswith("top") else ["-p", ports])

        return cmd

    def parse_output(self, result: ToolResult) -> List[Dict]:
        import json
        if not result.success:
            return []
        ports = []
        for line in result.stdout.splitlines():
            try:
                ports.append(json.loads(line))
            except json.JSONDecodeError:
                continue
        return ports
