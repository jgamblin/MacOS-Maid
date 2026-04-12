"""Privacy and security audit module for MacOS Maid."""

from __future__ import annotations

import os
import sqlite3
import subprocess
from datetime import datetime, timedelta
from pathlib import Path

from macos_maid.modules.base import (
    AuditResult,
    CleanResult,
    Finding,
    Module,
    ScanResult,
    worst_severity,
)

# TCC service name mappings to human-readable names
TCC_SERVICE_NAMES = {
    "kTCCServiceScreenCapture": "Screen Capture",
    "kTCCServiceSystemPolicyAllFiles": "Full Disk Access",
    "kTCCServiceAccessibility": "Accessibility",
    "kTCCServiceCamera": "Camera",
    "kTCCServiceMicrophone": "Microphone",
    "kTCCServiceListenEvent": "Input Monitoring",
    "kTCCServicePostEvent": "Input Monitoring",
    "kTCCServiceSystemPolicyDesktopFolder": "Desktop Folder Access",
    "kTCCServiceSystemPolicyDocumentsFolder": "Documents Folder Access",
    "kTCCServiceSystemPolicyDownloadsFolder": "Downloads Folder Access",
    "kTCCServiceSystemPolicyNetworkVolumes": "Network Volumes Access",
    "kTCCServiceSystemPolicyRemovableVolumes": "Removable Volumes Access",
}


class PrivacyModule(Module):
    """Module for privacy audits and cleanup.

    SAFETY: Never deletes Downloads by default - report only.
    If move-to-trash enabled, moves to Trash (recoverable).
    TCC audit reads user-level DB only, never requests FDA.
    """

    name = "privacy"
    category = "security"
    requires_sudo = True

    def __init__(
        self,
        clear_recent: bool = True,
        downloads_move_to_trash: bool = False,
        downloads_older_than: int = 90,
    ):
        """Initialize Privacy module.

        Args:
            clear_recent: Clear recent items (default: True)
            downloads_move_to_trash: Move old downloads to trash (default: False, report only)
            downloads_older_than: Age threshold in days for old downloads (default: 90)
        """
        self.clear_recent = clear_recent
        self.downloads_move_to_trash = downloads_move_to_trash
        self.downloads_older_than = downloads_older_than

    def _get_tcc_permissions(self) -> dict[str, list[str]]:
        """Read TCC permissions from user-level database.

        Reads ~/Library/Application Support/com.apple.TCC/TCC.db in read-only mode.
        Never requests Full Disk Access.

        Returns:
            Dict mapping service name to list of app names with granted access
        """
        tcc_db_path = os.path.expanduser("~/Library/Application Support/com.apple.TCC/TCC.db")

        if not os.path.exists(tcc_db_path):
            return {}

        permissions: dict[str, list[str]] = {}

        try:
            # Open database in read-only mode
            conn = sqlite3.connect(f"file:{tcc_db_path}?mode=ro", uri=True)
            cursor = conn.cursor()

            # Query for granted permissions (auth_value = 2)
            cursor.execute(
                """
                SELECT service, client
                FROM access
                WHERE auth_value = 2
                ORDER BY service, client
                """
            )

            for service, client in cursor.fetchall():
                if service not in permissions:
                    permissions[service] = []
                permissions[service].append(client)

            conn.close()

        except (sqlite3.Error, OSError):
            # If we can't read the TCC database, return empty dict
            # This can happen if the database is locked or inaccessible
            return {}

        return permissions

    def _clear_recent_items(self) -> None:
        """Clear recent items by resetting the SFL2 recent items database.

        Works on macOS Ventura (13+) and later. Falls back to legacy plist
        approach for older macOS versions.
        """
        # Modern approach: clear the SFL2 database used by macOS 13+
        sfl2_paths = [
            Path.home()
            / "Library/Application Support/com.apple.sharedfilelist"
            / "com.apple.LSSharedFileList.RecentDocuments.sfl2",
            Path.home()
            / "Library/Application Support/com.apple.sharedfilelist"
            / "com.apple.LSSharedFileList.RecentApplications.sfl2",
            Path.home()
            / "Library/Application Support/com.apple.sharedfilelist"
            / "com.apple.LSSharedFileList.RecentServers.sfl2",
        ]

        cleared = False
        for sfl2 in sfl2_paths:
            if sfl2.exists():
                try:
                    sfl2.unlink()
                    cleared = True
                except OSError:
                    pass

        if cleared:
            return

        # Legacy fallback: use defaults for older macOS
        subprocess.run(
            [
                "defaults",
                "delete",
                "com.apple.recentitems",
            ],
            capture_output=True,
            text=True,
            check=False,
            timeout=10,
        )

    def _get_old_downloads(self) -> list[tuple[Path, int]]:
        """Get old files from Downloads folder.

        Returns:
            List of (file_path, size_bytes) tuples for files older than threshold
        """
        downloads_dir = Path.home() / "Downloads"

        if not downloads_dir.exists():
            return []

        old_files = []
        threshold_time = datetime.now() - timedelta(days=self.downloads_older_than)

        try:
            for item in downloads_dir.iterdir():
                if item.is_file():
                    mtime = datetime.fromtimestamp(item.stat().st_mtime)
                    if mtime < threshold_time:
                        size = item.stat().st_size
                        old_files.append((item, size))
        except (PermissionError, OSError):
            # If we can't read Downloads, return empty list
            return []

        return old_files

    def scan(self) -> ScanResult:
        """Preview what this module would do."""
        items = []

        if self.clear_recent:
            items.append("Clear recent items")

        return ScanResult(
            items=items,
            bytes_reclaimable=0,
            requires_sudo=True,
        )

    def clean(self) -> CleanResult:
        """Execute privacy cleanup operations.

        SAFETY: Never deletes Downloads by default.
        Only clears recent items if configured.
        """
        cleaned = []
        errors = []

        if self.clear_recent:
            try:
                self._clear_recent_items()
                cleaned.append("Cleared recent items")
            except Exception as e:
                errors.append(f"Failed to clear recent items: {e}")

        # SAFETY: Never delete Downloads by default
        # Even if downloads_move_to_trash is enabled, we only report in audit()
        # This ensures no accidental data loss

        return CleanResult(
            items_cleaned=cleaned,
            bytes_reclaimed=0,
            errors=errors,
        )

    def audit(self) -> AuditResult:
        """Run privacy and security audits (read-only, never modifies anything)."""
        findings = []

        # Audit TCC permissions
        tcc_permissions = self._get_tcc_permissions()

        if tcc_permissions:
            # Report on sensitive permissions
            sensitive_services = [
                "kTCCServiceScreenCapture",
                "kTCCServiceSystemPolicyAllFiles",
                "kTCCServiceAccessibility",
                "kTCCServiceCamera",
                "kTCCServiceMicrophone",
            ]

            for service in sensitive_services:
                if service in tcc_permissions:
                    apps = tcc_permissions[service]
                    human_name = TCC_SERVICE_NAMES.get(service, service)
                    app_list = ", ".join(apps[:5])
                    if len(apps) > 5:
                        app_list += f" and {len(apps) - 5} more"

                    findings.append(
                        Finding(
                            severity="info",
                            title=f"{human_name} Permission",
                            detail=f"{len(apps)} app(s) have {human_name} access: {app_list}",
                            remediation=(
                                f"Review {human_name} permissions in"
                                " System Preferences > Security & Privacy > Privacy"
                            ),
                        )
                    )

        # Report on old Downloads files (REPORT ONLY, never delete)
        old_downloads = self._get_old_downloads()
        if old_downloads:
            total_size = sum(size for _, size in old_downloads)
            size_mb = total_size / (1024 * 1024)

            findings.append(
                Finding(
                    severity="info",
                    title="Old Downloads Files",
                    detail=(
                        f"Found {len(old_downloads)} file(s) in Downloads"
                        f" older than {self.downloads_older_than} days"
                        f" ({size_mb:.1f} MB)"
                    ),
                    remediation="Review and manually clean up old files in ~/Downloads",
                )
            )

        # Determine overall status
        if not findings:
            findings.append(
                Finding(
                    severity="pass",
                    title="Privacy Audit",
                    detail="No privacy concerns detected",
                    remediation=None,
                )
            )

        status = worst_severity(findings)

        return AuditResult(status=status, findings=findings)
