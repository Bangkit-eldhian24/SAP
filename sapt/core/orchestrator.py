"""
SAPT Orchestrator — Pipeline runner that ties all phases together.
Phase 1 (Recon) → Phase 2 (Scan) → Phase 3 (Exploit) → Phase 4 (Report).
"""

from __future__ import annotations

from datetime import datetime
from pathlib import Path
from typing import Optional

from sapt.core.config import SAPTConfig
from sapt.core.exceptions import PhaseError
from sapt.core.logger import (
    get_console, get_logger, log_error, log_phase, log_success,
)
from sapt.core.state import StateManager
from sapt.core.timer import PhaseTimer
from sapt.models.models import (
    PhaseStatus, SAPTState, TestingMode,
)


class Orchestrator:
    """
    SAPT Pipeline Orchestrator.
    Manages the full pentest pipeline with state persistence,
    time management, and phase skip/resume logic.
    """

    def __init__(self, config: SAPTConfig, target: str):
        self.config = config
        self.target = target
        self.logger = get_logger()
        self.console = get_console()

        # Output directory
        base_dir = config.get("output.base_dir", "./output")
        self.output_dir = Path(base_dir) / target
        self.output_dir.mkdir(parents=True, exist_ok=True)

        # State manager
        self.state_manager = StateManager(self.output_dir / "sapt_state.db")

        # Timer
        time_limit = config.get("mode.time_limit", 180)
        self.timer = PhaseTimer(time_limit)

        # Mode
        mode_str = config.get("mode.default", "bb")
        self.mode = TestingMode(mode_str)

    async def run(
        self,
        skip_recon: bool = False,
        skip_scan: bool = False,
        skip_exploit: bool = False,
        resume: bool = False,
    ):
        """Run the full pentest pipeline."""
        # Initialize state
        await self.state_manager.init_db()

        state: Optional[SAPTState] = None
        if resume:
            state = await self.state_manager.load()
            if state and state.can_resume():
                self.logger.info("📋 Resuming from last checkpoint...")
            else:
                self.logger.warning("No valid checkpoint found. Starting fresh.")
                state = None

        if not state:
            state = SAPTState(
                target=self.target,
                mode=self.mode,
                config_path="sapt.yaml",
                output_dir=str(self.output_dir),
            )

        self.timer.start_global()

        try:
            # ── Phase 1: Recon ────────────────────────────────────────────
            if skip_recon or state.phase_recon == PhaseStatus.COMPLETED:
                log_phase("Recon", "SKIPPED")
                if not skip_recon:
                    state.phase_recon = PhaseStatus.SKIPPED
            else:
                await self._run_phase(state, "recon")

            if not self.timer.check_time():
                raise PhaseError("time_limit", "Global time limit reached")

            # ── Phase 2: Scan ─────────────────────────────────────────────
            if skip_scan or state.phase_scan == PhaseStatus.COMPLETED:
                log_phase("Scan", "SKIPPED")
                if not skip_scan:
                    state.phase_scan = PhaseStatus.SKIPPED
            else:
                await self._run_phase(state, "scan")

            if not self.timer.check_time():
                raise PhaseError("time_limit", "Global time limit reached")

            # ── Phase 3: Exploit ──────────────────────────────────────────
            if skip_exploit or state.phase_exploit == PhaseStatus.COMPLETED:
                log_phase("Exploit", "SKIPPED")
                if not skip_exploit:
                    state.phase_exploit = PhaseStatus.SKIPPED
            else:
                await self._run_phase(state, "exploit")

            if not self.timer.check_time():
                raise PhaseError("time_limit", "Global time limit reached")

            # ── Phase 4: Report ───────────────────────────────────────────
            await self._run_phase(state, "report")

            # ── Done ──────────────────────────────────────────────────────
            elapsed = self.timer.elapsed_global()
            log_success(
                f"Pipeline completed in {elapsed / 60:.1f} minutes. "
                f"Output: {self.output_dir}"
            )

        except PhaseError as e:
            log_error(f"Pipeline stopped: {e}")
            await self.state_manager.save(state)
            raise

        except Exception as e:
            log_error(f"Unexpected error: {e}")
            await self.state_manager.save(state)
            raise

    async def _run_phase(self, state: SAPTState, phase_name: str):
        """Run a single phase with timing and state management."""
        log_phase(phase_name.capitalize(), "STARTING")
        self.timer.start_phase(phase_name)

        # Update state
        setattr(state, f"phase_{phase_name}", PhaseStatus.RUNNING)
        await self.state_manager.save(state)

        try:
            if phase_name == "recon":
                from sapt.phases.recon import ReconPhase
                phase = ReconPhase(self.config, self.target)
                state.recon_results = await phase.run()

            elif phase_name == "scan":
                from sapt.phases.scan import ScanPhase
                phase = ScanPhase(self.config, self.target)
                state.scan_results = await phase.run()

            elif phase_name == "exploit":
                from sapt.phases.exploit import ExploitPhase
                phase = ExploitPhase(self.config, self.target)
                state.exploitation_results = await phase.run()

            elif phase_name == "report":
                from sapt.phases.report import ReportPhase
                phase = ReportPhase(self.config, self.target)
                await phase.run()

            # Mark completed
            setattr(state, f"phase_{phase_name}", PhaseStatus.COMPLETED)
            duration = self.timer.end_phase()
            log_phase(phase_name.capitalize(), f"COMPLETED in {duration:.1f}s")
            await self.state_manager.save(state)

        except Exception as e:
            setattr(state, f"phase_{phase_name}", PhaseStatus.FAILED)
            self.timer.end_phase()
            await self.state_manager.save(state)
            raise PhaseError(phase_name, str(e))
