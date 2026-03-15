"""Arjun — HTTP parameter discovery tool wrapper."""

import json
from typing import Any, Dict, List

from sapt.tools.base import BaseTool, ToolResult


class ArjunTool(BaseTool):
    binary_name = "arjun"
    install_cmd = "pip install arjun"
    required_for = ["scan"]

    def build_command(self, target: str, **kwargs) -> List[str]:
        cmd = [
            self.binary_name,
            "-u", target,
            "-oJ", "-",  # JSON output to stdout
        ]

        method = kwargs.get("method", "GET")
        cmd.extend(["-m", method])

        return cmd

    def parse_output(self, result: ToolResult) -> List[Dict]:
        if not result.success:
            return []
        try:
            data = json.loads(result.stdout)
            return data if isinstance(data, list) else [data]
        except json.JSONDecodeError:
            return []
