"""Trash cleanup module for MacOS Maid."""

from __future__ import annotations

import os
import subprocess

from macos_maid.modules.base import AuditResult, CleanResult, Module, ScanResult
from macos_maid.reporter import format_bytes


class TrashModule(Module):
    """Module to report trash size and empty trash."""

    name = "trash"
    category = "dev"
    requires_sudo = False

    def _get_trash_size(self) -> int:
        """Get trash size in bytes via du -sk ~/.Trash."""
        try:
            trash_path = os.path.expanduser("~/.Trash")
            result = subprocess.run(
                ["du", "-sk", trash_path],
                capture_output=True,
                text=True,
                check=True,
            )
            # du -sk returns size in KB as first field
            size_kb = int(result.stdout.split()[0])
            return size_kb * 1024  # Convert to bytes
        except (subprocess.CalledProcessError, ValueError, IndexError, FileNotFoundError):
            return 0

    def _empty_trash(self) -> None:
        """Empty trash via AppleScript."""
        applescript = 'tell application "Finder" to empty trash'
        subprocess.run(
            ["osascript", "-e", applescript],
            capture_output=True,
            text=True,
            check=True,
        )

    def scan(self) -> ScanResult:
        """Report trash size without modifying it."""
        size_bytes = self._get_trash_size()

        if size_bytes == 0:
            items = ["Trash is empty"]
        else:
            items = [f"Trash contains {format_bytes(size_bytes)}"]

        return ScanResult(
            items=items,
            bytes_reclaimable=size_bytes,
            requires_sudo=False,
        )

    def clean(self) -> CleanResult:
        """Empty the trash."""
        size_bytes = self._get_trash_size()

        if size_bytes == 0:
            return CleanResult.empty()

        try:
            self._empty_trash()
            return CleanResult(
                items_cleaned=[f"Emptied trash ({format_bytes(size_bytes)})"],
                bytes_reclaimed=size_bytes,
                errors=[],
            )
        except Exception as e:
            return CleanResult(
                items_cleaned=[],
                bytes_reclaimed=0,
                errors=[f"Failed to empty trash: {e}"],
            )

    def audit(self) -> AuditResult:
        """Trash module has no security checks."""
        return AuditResult.empty()
