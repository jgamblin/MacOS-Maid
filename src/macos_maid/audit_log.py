"""Action logger for MacOS Maid.

Logs every destructive action to ~/.maid/last_run.json so users
can review what happened after a run.
"""

from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Any


class AuditLog:
    """Records actions taken during a maid run."""

    def __init__(self) -> None:
        self._start_time = time.time()
        self.actions: list[dict[str, Any]] = []
        self.errors: list[dict[str, str]] = []
        self.modules_run: list[str] = []

    def record_module(self, module_name: str) -> None:
        """Record that a module was run."""
        if module_name not in self.modules_run:
            self.modules_run.append(module_name)

    def add_action(
        self,
        module: str,
        action: str,
        detail: str,
        bytes_reclaimed: int = 0,
    ) -> None:
        """Log a single action taken by a module."""
        entry: dict[str, Any] = {
            "module": module,
            "action": action,
            "detail": detail,
        }
        if bytes_reclaimed > 0:
            entry["bytes"] = bytes_reclaimed
        self.actions.append(entry)

    def add_error(self, module: str, error: str) -> None:
        """Log an error encountered during a run."""
        self.errors.append({"module": module, "error": error})

    @property
    def total_bytes_reclaimed(self) -> int:
        return sum(a.get("bytes", 0) for a in self.actions)

    def to_dict(self) -> dict[str, Any]:
        """Serialize the log to a dictionary."""
        from datetime import datetime, timezone

        return {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "duration_seconds": round(time.time() - self._start_time, 1),
            "modules_run": self.modules_run,
            "actions": self.actions,
            "total_bytes_reclaimed": self.total_bytes_reclaimed,
            "errors": self.errors,
        }

    def save(self, log_dir: Path) -> None:
        """Save the log to log_dir/last_run.json."""
        log_dir.mkdir(parents=True, exist_ok=True)
        log_file = log_dir / "last_run.json"
        log_file.write_text(json.dumps(self.to_dict(), indent=2))
