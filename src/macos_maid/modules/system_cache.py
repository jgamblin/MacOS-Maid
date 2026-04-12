# src/macos_maid/modules/system_cache.py
"""System cache and log cleanup module.

SAFETY: This module NEVER touches /private/var/folders — the original script did
this and it was dangerous. We only clean safe, user-facing cache and log directories.
"""

from __future__ import annotations

import shutil
from pathlib import Path

from macos_maid.modules.base import AuditResult, CleanResult, Module, ScanResult
from macos_maid.reporter import format_bytes
from macos_maid.utils import dir_size


class SystemCacheModule(Module):
    """Clean system caches and diagnostic logs safely.

    This module cleans:
    - User Library caches (~/Library/Caches)
    - System diagnostic reports (/Library/Logs/DiagnosticReports)
    - User diagnostic reports (~/Library/Logs/DiagnosticReports)

    SAFETY: We NEVER touch /private/var/folders which contains system-critical
    temporary files. The original macos-maid script cleaned this directory and
    it was extremely dangerous.
    """

    name = "system_cache"
    category = "both"
    requires_sudo = True  # System logs need sudo

    # Safe directories to clean
    SAFE_CACHE_DIRS = [
        Path.home() / "Library" / "Caches",
    ]

    SAFE_LOG_DIRS = [
        Path("/Library/Logs/DiagnosticReports"),
        Path.home() / "Library" / "Logs" / "DiagnosticReports",
    ]

    def scan(self) -> ScanResult:
        """Preview what this module would clean (dry-run)."""
        items = []
        total_bytes = 0

        # Scan cache directories
        for cache_dir in self.SAFE_CACHE_DIRS:
            if cache_dir.exists():
                size = dir_size(cache_dir)
                if size > 0:
                    items.append(f"{cache_dir}: {format_bytes(size)}")
                    total_bytes += size

        # Scan log directories
        for log_dir in self.SAFE_LOG_DIRS:
            if log_dir.exists():
                size = dir_size(log_dir)
                if size > 0:
                    items.append(f"{log_dir}: {format_bytes(size)}")
                    total_bytes += size

        return ScanResult(
            items=items,
            bytes_reclaimable=total_bytes,
            requires_sudo=True,
        )

    def clean(self) -> CleanResult:
        """Execute cleanup operations."""
        items_cleaned = []
        bytes_reclaimed = 0
        errors = []

        # Clean cache directories (remove contents, keep directory)
        for cache_dir in self.SAFE_CACHE_DIRS:
            if not cache_dir.exists():
                continue

            try:
                size_before = dir_size(cache_dir)

                # Remove contents but keep the directory itself
                for item in cache_dir.iterdir():
                    try:
                        if item.is_symlink():
                            continue  # skip symlinks for safety
                        elif item.is_file():
                            item.unlink()
                        elif item.is_dir():
                            shutil.rmtree(item)
                    except Exception as e:
                        errors.append(f"Failed to remove {item}: {e}")

                size_after = dir_size(cache_dir)
                reclaimed = size_before - size_after

                if reclaimed > 0:
                    items_cleaned.append(f"{cache_dir}: {format_bytes(reclaimed)}")
                    bytes_reclaimed += reclaimed

            except Exception as e:
                errors.append(f"Failed to clean {cache_dir}: {e}")

        # Clean log directories (delete log files)
        for log_dir in self.SAFE_LOG_DIRS:
            if not log_dir.exists():
                continue

            try:
                size_before = dir_size(log_dir)

                # Delete log files in the directory
                for item in log_dir.iterdir():
                    try:
                        if item.is_file():
                            item.unlink()
                    except Exception as e:
                        errors.append(f"Failed to remove {item}: {e}")

                size_after = dir_size(log_dir)
                reclaimed = size_before - size_after

                if reclaimed > 0:
                    items_cleaned.append(f"{log_dir}: {format_bytes(reclaimed)}")
                    bytes_reclaimed += reclaimed

            except Exception as e:
                errors.append(f"Failed to clean {log_dir}: {e}")

        return CleanResult(
            items_cleaned=items_cleaned,
            bytes_reclaimed=bytes_reclaimed,
            errors=errors,
        )

    def audit(self) -> AuditResult:
        """Run security checks (no security checks for this module)."""
        return AuditResult.empty()
