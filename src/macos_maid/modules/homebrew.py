"""Homebrew cleanup module for MacOS Maid."""

from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

from macos_maid.modules.base import AuditResult, CleanResult, Module, ScanResult
from macos_maid.reporter import format_bytes


class HomebrewModule(Module):
    """Clean up Homebrew packages and cache.

    - Updates outdated packages
    - Cleans up old versions and cache
    - Reports cache size and outdated package count
    """

    name = "homebrew"
    category = "dev"
    requires_sudo = False

    def __init__(
        self,
        update: bool = False,
        upgrade: bool = False,
        cleanup: bool = True,
    ) -> None:
        """Initialize Homebrew module.

        Args:
            update: Run brew update (default: False, installs new software)
            upgrade: Run brew upgrade (default: False, installs new software)
            cleanup: Run brew cleanup (default: True)
        """
        self.update = update
        self.upgrade = upgrade
        self.cleanup = cleanup

    def _is_brew_installed(self) -> bool:
        """Check if brew is installed on the system."""
        return shutil.which("brew") is not None

    def _run_brew(self, *args: str) -> str:
        """Run a brew command and return its output."""
        result = subprocess.run(
            ["brew", *args],
            capture_output=True,
            text=True,
            check=True,
            timeout=120,
        )
        return result.stdout.strip()

    def _get_outdated_count(self) -> int:
        """Get the number of outdated packages."""
        try:
            output = self._run_brew("outdated", "--quiet")
            if not output:
                return 0
            return len(output.strip().split("\n"))
        except subprocess.CalledProcessError:
            return 0

    def _get_cache_size(self) -> int:
        """Get the size of the Homebrew cache in bytes."""
        try:
            cache_path = self._run_brew("--cache")
            cache_dir = Path(cache_path)

            if not cache_dir.exists():
                return 0

            # Use du to get size in kilobytes, then convert to bytes
            result = subprocess.run(
                ["du", "-sk", str(cache_dir)],
                capture_output=True,
                text=True,
                check=True,
            )
            size_kb = int(result.stdout.split()[0])
            return size_kb * 1024
        except (subprocess.CalledProcessError, ValueError, IndexError):
            return 0

    def scan(self) -> ScanResult:
        """Preview what this module would do (dry-run)."""
        if not self._is_brew_installed():
            return ScanResult.empty()

        items = []
        outdated_count = self._get_outdated_count()
        cache_size = self._get_cache_size()

        if outdated_count > 0:
            items.append(f"{outdated_count} outdated packages")

        if cache_size > 0:
            items.append(f"{format_bytes(cache_size)} cache")

        return ScanResult(
            items=items,
            bytes_reclaimable=cache_size,
            requires_sudo=False,
        )

    def clean(self) -> CleanResult:
        """Execute cleanup operations."""
        if not self._is_brew_installed():
            return CleanResult.empty()

        items_cleaned = []
        errors = []

        # Run brew update if enabled
        if self.update:
            try:
                self._run_brew("update")
                items_cleaned.append("brew update")
            except subprocess.CalledProcessError as e:
                errors.append(f"brew update failed: {e}")

        # Run brew upgrade if enabled
        if self.upgrade:
            try:
                self._run_brew("upgrade")
                items_cleaned.append("brew upgrade")
            except subprocess.CalledProcessError as e:
                errors.append(f"brew upgrade failed: {e}")

        # Run brew cleanup if enabled — measure before/after
        bytes_reclaimed = 0
        if self.cleanup:
            try:
                cache_before = self._get_cache_size()
                self._run_brew("cleanup", "--prune=all")
                cache_after = self._get_cache_size()
                bytes_reclaimed = max(0, cache_before - cache_after)
                items_cleaned.append(f"brew cleanup ({format_bytes(bytes_reclaimed)} reclaimed)")
            except subprocess.CalledProcessError as e:
                errors.append(f"brew cleanup failed: {e}")

        return CleanResult(
            items_cleaned=items_cleaned,
            bytes_reclaimed=bytes_reclaimed,
            errors=errors,
        )

    def audit(self) -> AuditResult:
        """Run security checks (read-only, never modifies anything)."""
        return AuditResult.empty()
