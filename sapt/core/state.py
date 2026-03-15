"""
SAPT State — SQLite-backed persistence for SAPTState.
Enables resume on crash with --resume flag.
"""

from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path
from typing import Optional

import aiosqlite

from sapt.core.exceptions import StateError
from sapt.core.logger import get_logger
from sapt.models.models import SAPTState


class StateManager:
    """Manages SAPT state persistence in SQLite."""

    def __init__(self, db_path: str | Path):
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)

    async def init_db(self):
        """Create the state table if it doesn't exist."""
        async with aiosqlite.connect(str(self.db_path)) as db:
            await db.execute("""
                CREATE TABLE IF NOT EXISTS sapt_state (
                    id      INTEGER PRIMARY KEY DEFAULT 1,
                    target  TEXT NOT NULL,
                    data    TEXT NOT NULL,
                    updated TEXT NOT NULL
                )
            """)
            await db.commit()

    async def save(self, state: SAPTState):
        """Save state to SQLite. Upserts the single row."""
        try:
            state.last_updated = datetime.now()
            data_json = state.model_dump_json()

            async with aiosqlite.connect(str(self.db_path)) as db:
                await db.execute("""
                    INSERT INTO sapt_state (id, target, data, updated)
                    VALUES (1, ?, ?, ?)
                    ON CONFLICT(id) DO UPDATE SET
                        target = excluded.target,
                        data = excluded.data,
                        updated = excluded.updated
                """, (state.target, data_json, datetime.now().isoformat()))
                await db.commit()

            get_logger().debug(f"State saved to {self.db_path}")

        except Exception as e:
            raise StateError(f"Failed to save state: {e}")

    async def load(self) -> Optional[SAPTState]:
        """Load state from SQLite. Returns None if no state exists."""
        if not self.db_path.exists():
            return None

        try:
            async with aiosqlite.connect(str(self.db_path)) as db:
                cursor = await db.execute(
                    "SELECT data FROM sapt_state WHERE id = 1"
                )
                row = await cursor.fetchone()

            if not row:
                return None

            data = json.loads(row[0])
            return SAPTState(**data)

        except Exception as e:
            raise StateError(f"Failed to load state: {e}")

    async def exists(self) -> bool:
        """Check if a state file exists and has data."""
        if not self.db_path.exists():
            return False

        try:
            async with aiosqlite.connect(str(self.db_path)) as db:
                cursor = await db.execute(
                    "SELECT COUNT(*) FROM sapt_state WHERE id = 1"
                )
                row = await cursor.fetchone()
                return row[0] > 0 if row else False
        except Exception:
            return False

    async def clear(self):
        """Clear the state database."""
        try:
            async with aiosqlite.connect(str(self.db_path)) as db:
                await db.execute("DELETE FROM sapt_state")
                await db.commit()
        except Exception as e:
            raise StateError(f"Failed to clear state: {e}")
