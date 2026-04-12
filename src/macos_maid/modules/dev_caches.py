"""Developer cache cleanup module for MacOS Maid.

Safely removes and recreates regenerable development tool caches.
SAFETY: Uses strict allowlist of ONLY cache directories - never touches
node_modules, .venv, target/, build/, or any project directories.
"""

from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

from macos_maid.modules.base import AuditResult, CleanResult, Module, ScanResult
from macos_maid.reporter import format_bytes


class DevCachesModule(Module):
    """Clean development tool caches (pip, npm, cargo, gradle, CocoaPods, Xcode)."""

    name = "dev_caches"
    category = "dev"
    requires_sudo = False

    # SAFETY: Strict allowlist of ONLY regenerable cache directories
    CACHE_PATHS = {
        "pip": Path.home() / "Library" / "Caches" / "pip",
        "npm": Path.home() / ".npm" / "_cacache",
        "cargo": Path.home() / ".cargo" / "registry" / "cache",  # NOT registry/src
        "gradle": Path.home() / ".gradle" / "caches",
        "cocoapods": Path.home() / "Library" / "Caches" / "CocoaPods",
        "xcode_derived": Path.home() / "Library" / "Developer" / "Xcode" / "DerivedData",
    }

    def _dir_size(self, path: Path) -> int:
        """Get directory size in bytes using du -sk.

        Args:
            path: Directory path to measure

        Returns:
            Size in bytes, or 0 if directory doesn't exist or error occurs
        """
        try:
            result = subprocess.run(
                ["du", "-sk", str(path)],
                capture_output=True,
                text=True,
                check=False,
                timeout=30,
            )

            if result.returncode != 0:
                return 0

            # Parse output: "1024\t/path/to/dir\n"
            output = result.stdout.strip()
            if not output:
                return 0

            size_kb = int(output.split("\t")[0])
            return size_kb * 1024  # Convert KB to bytes

        except (ValueError, IndexError, OSError):
            return 0

    def scan(self) -> ScanResult:
        """Preview what caches exist and their sizes."""
        items = []
        total_bytes = 0

        for cache_name, cache_path in self.CACHE_PATHS.items():
            size = self._dir_size(cache_path)
            if size > 0:
                items.append(f"{cache_name}: {format_bytes(size)}")
                total_bytes += size

        return ScanResult(
            items=items,
            bytes_reclaimable=total_bytes,
            requires_sudo=False,
        )

    def clean(self) -> CleanResult:
        """Remove and recreate cache directories."""
        items_cleaned = []
        errors = []
        total_bytes = 0

        for cache_name, cache_path in self.CACHE_PATHS.items():
            # Get size before removal
            size = self._dir_size(cache_path)

            if not cache_path.exists():
                continue

            # SAFETY: Never follow symlinks
            if cache_path.is_symlink():
                errors.append(f"Skipping symlink: {cache_path}")
                continue

            try:
                # Remove the cache directory
                shutil.rmtree(cache_path)

                # Recreate empty directory
                cache_path.mkdir(parents=True, exist_ok=True)

                items_cleaned.append(f"{cache_name}: {format_bytes(size)}")
                total_bytes += size

            except (OSError, PermissionError) as e:
                errors.append(f"{cache_name}: {e}")

        return CleanResult(
            items_cleaned=items_cleaned,
            bytes_reclaimed=total_bytes,
            errors=errors,
        )

    def audit(self) -> AuditResult:
        """No security checks for dev caches."""
        return AuditResult.empty()
