"""
SAPT Logger — Rich-based colored logging with level controls.
Supports --verbose, --debug, --quiet, --no-color flags.
"""

from __future__ import annotations

import logging
import sys
from typing import Optional

from rich.console import Console
from rich.logging import RichHandler
from rich.theme import Theme

# ── SAPT Theme ───────────────────────────────────────────────────────────────

SAPT_THEME = Theme({
    "info":     "cyan",
    "warning":  "yellow",
    "error":    "bold red",
    "critical": "bold white on red",
    "success":  "bold green",
    "phase":    "bold magenta",
    "tool":     "bold blue",
    "target":   "bold cyan",
    "finding":  "bold yellow",
    "dim":      "dim",
})

# ── Singleton Console ────────────────────────────────────────────────────────

_console: Optional[Console] = None


def get_console(no_color: bool = False) -> Console:
    """Get or create the global Rich console."""
    global _console
    if _console is None:
        _console = Console(
            theme=SAPT_THEME,
            no_color=no_color,
            stderr=True,
        )
    return _console


def reset_console():
    """Reset the global console (for testing)."""
    global _console
    _console = None


# ── Logger Setup ─────────────────────────────────────────────────────────────

_logger: Optional[logging.Logger] = None


def setup_logger(
    verbose: bool = False,
    debug: bool = False,
    quiet: bool = False,
    no_color: bool = False,
    log_file: Optional[str] = None,
) -> logging.Logger:
    """
    Configure and return the SAPT logger.

    Priority: debug > verbose > quiet > default (INFO)
    """
    global _logger

    if debug:
        level = logging.DEBUG
    elif verbose:
        level = logging.DEBUG
    elif quiet:
        level = logging.WARNING
    else:
        level = logging.INFO

    console = get_console(no_color=no_color)

    logger = logging.getLogger("sapt")
    logger.setLevel(level)
    logger.handlers.clear()

    # Rich console handler
    rich_handler = RichHandler(
        console=console,
        show_time=True,
        show_path=debug,
        markup=True,
        rich_tracebacks=True,
        tracebacks_show_locals=debug,
    )
    rich_handler.setLevel(level)
    logger.addHandler(rich_handler)

    # File handler (optional)
    if log_file:
        file_handler = logging.FileHandler(log_file, encoding="utf-8")
        file_handler.setLevel(logging.DEBUG)
        file_formatter = logging.Formatter(
            "%(asctime)s | %(levelname)-8s | %(name)s | %(message)s",
            datefmt="%Y-%m-%d %H:%M:%S",
        )
        file_handler.setFormatter(file_formatter)
        logger.addHandler(file_handler)

    _logger = logger
    return logger


def get_logger() -> logging.Logger:
    """Get the SAPT logger. Creates a default one if not yet set up."""
    global _logger
    if _logger is None:
        _logger = setup_logger()
    return _logger


# ── Convenience Functions ────────────────────────────────────────────────────

def log_phase(phase_name: str, status: str):
    """Log a phase status change with special formatting."""
    logger = get_logger()
    logger.info(f"[phase]▶ Phase: {phase_name}[/phase] — {status}")


def log_tool(tool_name: str, message: str):
    """Log a tool-related message."""
    logger = get_logger()
    logger.info(f"[tool]🔧 {tool_name}[/tool] — {message}")


def log_finding(title: str, severity: str):
    """Log a security finding."""
    logger = get_logger()
    severity_colors = {
        "critical": "[bold white on red]CRITICAL[/]",
        "high":     "[bold red]HIGH[/]",
        "medium":   "[yellow]MEDIUM[/]",
        "low":      "[blue]LOW[/]",
        "info":     "[dim]INFO[/]",
    }
    sev_display = severity_colors.get(severity.lower(), severity)
    logger.info(f"[finding]🎯 {title}[/finding] — {sev_display}")


def log_success(message: str):
    """Log a success message."""
    logger = get_logger()
    logger.info(f"[success]✅ {message}[/success]")


def log_error(message: str):
    """Log an error message."""
    logger = get_logger()
    logger.error(f"[error]❌ {message}[/error]")


def print_banner():
    """Print the SAPT ASCII banner."""
    console = get_console()
    banner = r"""
[bold cyan]
  ____    _    ____ _____
 / ___|  / \  |  _ \_   _|
 \___ \ / _ \ | |_) || |
  ___) / ___ \|  __/ | |
 |____/_/   \_\_|    |_|
[/bold cyan]
[dim]Semi-Automated Pentest Tool — v0.1.0[/dim]
"""
    console.print(banner)
