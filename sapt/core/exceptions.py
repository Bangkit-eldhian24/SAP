"""
SAPT Custom Exception Hierarchy.
All SAPT-specific exceptions inherit from SAPTError.
"""


class SAPTError(Exception):
    """Base exception for all SAPT errors."""

    def __init__(self, message: str = "", detail: str = ""):
        self.detail = detail
        super().__init__(message)


class ConfigError(SAPTError):
    """Raised when configuration is invalid or missing."""


class ToolNotFoundError(SAPTError):
    """Raised when an external tool binary is not found in PATH."""

    def __init__(self, tool_name: str, install_cmd: str = ""):
        self.tool_name = tool_name
        self.install_cmd = install_cmd
        msg = f"Tool '{tool_name}' not found."
        if install_cmd:
            msg += f" Install: {install_cmd}"
        super().__init__(msg)


class ToolTimeoutError(SAPTError):
    """Raised when an external tool exceeds its timeout."""

    def __init__(self, tool_name: str, timeout: int):
        self.tool_name = tool_name
        self.timeout = timeout
        super().__init__(f"Tool '{tool_name}' timed out after {timeout}s")


class ToolExecutionError(SAPTError):
    """Raised when an external tool returns an error."""

    def __init__(self, tool_name: str, return_code: int, stderr: str = ""):
        self.tool_name = tool_name
        self.return_code = return_code
        self.stderr = stderr
        super().__init__(
            f"Tool '{tool_name}' failed with code {return_code}: {stderr[:200]}"
        )


class PhaseError(SAPTError):
    """Raised when a pentest phase fails."""

    def __init__(self, phase_name: str, message: str = ""):
        self.phase_name = phase_name
        super().__init__(f"Phase '{phase_name}' failed: {message}")


class StateError(SAPTError):
    """Raised when state save/load fails or state is corrupted."""


class ReportError(SAPTError):
    """Raised when report generation fails."""


class NotificationError(SAPTError):
    """Raised when notification delivery fails (Telegram/Slack)."""
