"""
SAPT BaseTool — Abstract base class for all external tool wrappers.
Handles: execution, timeout, error recovery, output parsing, availability check.
"""

from __future__ import annotations

import asyncio
import shutil
import subprocess
import time
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional

from sapt.core.exceptions import ToolNotFoundError, ToolTimeoutError


# ── Result Dataclass ─────────────────────────────────────────────────────────

@dataclass
class ToolResult:
    """Result of running an external tool."""
    tool_name: str
    success: bool
    stdout: str = ""
    stderr: str = ""
    return_code: int = 0
    output_file: Optional[Path] = None
    parsed_data: Any = None
    error_message: Optional[str] = None
    duration_seconds: float = 0.0


# ── Base Tool ────────────────────────────────────────────────────────────────

class BaseTool(ABC):
    """
    Abstract base class for all SAPT tool wrappers.

    Subclasses must implement:
        - binary_name: str
        - install_cmd: str
        - build_command(): List[str]
        - parse_output(): Any

    Subclasses can override:
        - required_for: List[str] — which phases need this tool
        - min_version: Optional[str]
    """

    binary_name: str = ""
    install_cmd: str = ""
    required_for: List[str] = []
    min_version: Optional[str] = None

    def __init__(self, config: Dict[str, Any] = None, output_dir: Path = None):
        self.config = config or {}
        self.output_dir = output_dir or Path("./output")
        self._binary_path: Optional[str] = None

    # ── Availability ──────────────────────────────────────────────────────

    @classmethod
    def check_availability(cls) -> Dict[str, Any]:
        """Check if tool is available and return info dict."""
        path = shutil.which(cls.binary_name)
        if not path:
            return {
                "status": "not_found",
                "path": None,
                "version": None,
                "install_cmd": cls.install_cmd,
            }
        version = cls._get_version(path)
        return {
            "status": "available",
            "path": path,
            "version": version,
            "install_cmd": None,
        }

    @classmethod
    def _get_version(cls, binary_path: str) -> Optional[str]:
        """Try common version flags to get version string."""
        for flag in ["-version", "--version", "-V", "version"]:
            try:
                result = subprocess.run(
                    [binary_path, flag],
                    capture_output=True, text=True, timeout=5,
                )
                output = result.stdout or result.stderr
                if output:
                    first_line = output.strip().splitlines()[0]
                    return first_line[:80]
            except Exception:
                continue
        return None

    def _resolve_binary(self) -> str:
        """Resolve binary path, raise ToolNotFoundError if missing."""
        if self._binary_path:
            return self._binary_path

        # Check config override first
        tools_cfg = self.config.get("tools", {})
        if tools_cfg:
            override = tools_cfg.get(self.binary_name)
            if override and Path(override).exists():
                self._binary_path = override
                return self._binary_path

        # Fall back to PATH
        path = shutil.which(self.binary_name)
        if not path:
            raise ToolNotFoundError(self.binary_name, self.install_cmd)

        self._binary_path = path
        return self._binary_path

    # ── Abstract Methods ──────────────────────────────────────────────────

    @abstractmethod
    def build_command(self, target: str, **kwargs) -> List[str]:
        """Build the CLI command list for subprocess execution."""
        ...

    @abstractmethod
    def parse_output(self, result: ToolResult) -> Any:
        """Parse raw stdout/output file into structured data."""
        ...

    # ── Execution ─────────────────────────────────────────────────────────

    async def run(
        self,
        target: str,
        timeout: int = 300,
        **kwargs,
    ) -> ToolResult:
        """
        Run the tool asynchronously.
        Returns ToolResult — never raises on tool failure (returns success=False).
        """
        binary = self._resolve_binary()
        cmd = self.build_command(target, **kwargs)
        cmd[0] = binary

        start = time.monotonic()

        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )

            try:
                stdout_bytes, stderr_bytes = await asyncio.wait_for(
                    proc.communicate(), timeout=timeout,
                )
            except asyncio.TimeoutError:
                proc.kill()
                await proc.communicate()
                return ToolResult(
                    tool_name=self.binary_name,
                    success=False,
                    error_message=f"Timeout after {timeout}s",
                    duration_seconds=time.monotonic() - start,
                )

            duration = time.monotonic() - start
            stdout = stdout_bytes.decode(errors="replace")
            stderr = stderr_bytes.decode(errors="replace")
            success = proc.returncode == 0

            result = ToolResult(
                tool_name=self.binary_name,
                success=success,
                stdout=stdout,
                stderr=stderr,
                return_code=proc.returncode,
                duration_seconds=duration,
            )
            result.parsed_data = self.parse_output(result)
            return result

        except ToolNotFoundError as e:
            return ToolResult(
                tool_name=self.binary_name,
                success=False,
                error_message=str(e),
                duration_seconds=0,
            )
        except Exception as e:
            return ToolResult(
                tool_name=self.binary_name,
                success=False,
                error_message=f"Unexpected error: {e}",
                duration_seconds=time.monotonic() - start,
            )
