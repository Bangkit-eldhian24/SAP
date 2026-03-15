"""
SAPT Timer — Phase timer with auto-stop when --time limit is reached.
"""

from __future__ import annotations

import time
from typing import Optional

from sapt.core.logger import get_logger


class PhaseTimer:
    """Tracks time spent per phase and enforces global time limit."""

    def __init__(self, time_limit_minutes: int = 180):
        self.time_limit_seconds = time_limit_minutes * 60 if time_limit_minutes > 0 else float("inf")
        self.global_start: float = 0.0
        self._phase_start: float = 0.0
        self._phase_name: str = ""
        self._phase_times: dict[str, float] = {}

    def start_global(self):
        """Start the global timer."""
        self.global_start = time.monotonic()
        get_logger().debug(
            f"Global timer started (limit: {self.time_limit_seconds}s)"
        )

    def start_phase(self, phase_name: str):
        """Start timing a phase."""
        self._phase_name = phase_name
        self._phase_start = time.monotonic()

    def end_phase(self) -> float:
        """End timing the current phase. Returns duration in seconds."""
        if not self._phase_name:
            return 0.0
        duration = time.monotonic() - self._phase_start
        self._phase_times[self._phase_name] = duration
        get_logger().debug(
            f"Phase '{self._phase_name}' completed in {duration:.1f}s"
        )
        self._phase_name = ""
        self._phase_start = 0.0
        return duration

    def elapsed_global(self) -> float:
        """Seconds elapsed since global start."""
        if self.global_start == 0:
            return 0.0
        return time.monotonic() - self.global_start

    def remaining(self) -> float:
        """Seconds remaining before time limit."""
        return max(0.0, self.time_limit_seconds - self.elapsed_global())

    def is_expired(self) -> bool:
        """Check if global time limit has been exceeded."""
        if self.time_limit_seconds == float("inf"):
            return False
        return self.elapsed_global() >= self.time_limit_seconds

    def check_time(self) -> bool:
        """Check time and log warning if running low. Returns True if OK."""
        remaining = self.remaining()
        if remaining <= 0:
            get_logger().warning("⏰ Time limit reached! Stopping pipeline.")
            return False
        if remaining < 300:  # less than 5 minutes
            get_logger().warning(f"⏰ Less than {remaining:.0f}s remaining!")
        return True

    def summary(self) -> dict[str, float]:
        """Return summary of all phase timings."""
        return {
            "total_elapsed": self.elapsed_global(),
            "remaining": self.remaining(),
            **{f"phase_{k}": v for k, v in self._phase_times.items()},
        }
