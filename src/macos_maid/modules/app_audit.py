"""Application audit module for MacOS Maid.

Read-only audit-only module that checks for unsigned applications:
- Scans /Applications for .app bundles
- Checks code signing status
- Identifies App Store vs. third-party apps
- Detects elevated permissions
- Provides tiered warnings based on risk level
"""

from __future__ import annotations

import subprocess
from pathlib import Path
from typing import Any

from macos_maid.modules.base import (
    AuditResult,
    CleanResult,
    Finding,
    Module,
    ScanResult,
)


class AppAuditModule(Module):
    """Audit application security (read-only, never modifies anything)."""

    name = "app_audit"
    category = "security"
    requires_sudo = False

    def scan(self) -> ScanResult:
        """Preview what this module would do (audit-only, returns empty)."""
        return ScanResult.empty()

    def clean(self) -> CleanResult:
        """Execute cleanup operations (audit-only, returns empty)."""
        return CleanResult.empty()

    def audit(self) -> AuditResult:
        """Run security checks for installed applications."""
        apps = self._get_applications()

        if not apps:
            return AuditResult.empty()

        # Classify apps
        signed_count = 0
        unsigned_sandboxed = []
        unsigned_privileged = []

        for app in apps:
            classification = self._classify_app(
                signed=app["signed"],
                from_app_store=app["from_app_store"],
                has_elevated_perms=app["has_elevated_perms"],
            )

            if classification == "ok":
                signed_count += 1
            elif classification == "info":
                unsigned_sandboxed.append(app["path"])
            elif classification == "warn":
                unsigned_privileged.append(app["path"])

        # Build findings
        findings = []

        # Add summary if all apps are signed
        if signed_count == len(apps):
            findings.append(
                Finding(
                    severity="pass",
                    title="Application Security",
                    detail=f"All {signed_count} applications are signed or from the App Store",
                    remediation=None,
                )
            )

        # Add info findings for unsigned sandboxed apps
        if unsigned_sandboxed:
            for app_path in unsigned_sandboxed:
                app_name = Path(app_path).name
                findings.append(
                    Finding(
                        severity="info",
                        title="Unsigned Application",
                        detail=f"{app_name} is unsigned but appears to be sandboxed",
                        remediation=(
                            "Consider verifying the source and reinstalling"
                            " from official channels if available"
                        ),
                    )
                )

        # Add warning findings for unsigned privileged apps
        if unsigned_privileged:
            for app_path in unsigned_privileged:
                app_name = Path(app_path).name
                findings.append(
                    Finding(
                        severity="warn",
                        title="Unsigned Application with Elevated Permissions",
                        detail=f"{app_name} is unsigned and may have elevated permissions",
                        remediation=(
                            f"Review {app_name} carefully."
                            " Consider removing or replacing with a signed version."
                        ),
                    )
                )

        # Determine worst status
        status = "pass"
        if unsigned_sandboxed:
            status = "info"
        if unsigned_privileged:
            status = "warn"

        return AuditResult(status=status, findings=findings)

    def _classify_app(self, signed: bool, from_app_store: bool, has_elevated_perms: bool) -> str:
        """Classify an application's security risk level.

        Args:
            signed: Whether the app is code-signed
            from_app_store: Whether the app is from the Mac App Store
            has_elevated_perms: Whether the app has elevated permissions

        Returns:
            "ok" for signed or App Store apps
            "warn" for unsigned apps with elevated permissions
            "info" for unsigned sandboxed apps
        """
        if signed or from_app_store:
            return "ok"

        if has_elevated_perms:
            return "warn"

        return "info"

    def _check_codesign(self, app_path: str) -> bool:
        """Check if an application is code-signed.

        Args:
            app_path: Path to the .app bundle

        Returns:
            True if the app is signed, False otherwise
        """
        try:
            result = subprocess.run(
                ["codesign", "-v", app_path],
                capture_output=True,
                text=True,
                timeout=5,
            )
            # codesign -v returns 0 for valid signatures
            return result.returncode == 0
        except Exception:
            return False

    def _check_app_store(self, app_path: str) -> bool:
        """Check if an application is from the Mac App Store.

        Args:
            app_path: Path to the .app bundle

        Returns:
            True if the app is from the App Store, False otherwise
        """
        try:
            result = subprocess.run(
                ["codesign", "-d", "--verbose=2", app_path],
                capture_output=True,
                text=True,
                timeout=5,
            )
            # Check stderr for App Store signature
            output = result.stderr.lower()
            return "apple mac os application signing" in output
        except Exception:
            return False

    def _check_elevated_perms(self, app_path: str) -> bool:
        """Check if an application has elevated permissions.

        This is a heuristic check looking for indicators of elevated permissions:
        - Presence of helper tools
        - SMJobBless frameworks
        - Privileged helper tools in Contents/Library/LaunchServices

        Args:
            app_path: Path to the .app bundle

        Returns:
            True if the app appears to have elevated permissions, False otherwise
        """
        try:
            # Check for common indicators of elevated permissions
            helper_paths = [
                Path(app_path) / "Contents" / "Library" / "LaunchServices",
                Path(app_path) / "Contents" / "Library" / "LoginItems",
            ]

            for helper_path in helper_paths:
                if helper_path.exists() and any(helper_path.iterdir()):
                    return True

            # Check for privileged helper tools in Info.plist
            info_plist = Path(app_path) / "Contents" / "Info.plist"
            if info_plist.exists():
                result = subprocess.run(
                    ["defaults", "read", str(info_plist), "SMPrivilegedExecutables"],
                    capture_output=True,
                    text=True,
                    timeout=5,
                )
                if result.returncode == 0:
                    return True

            return False
        except Exception:
            return False

    def _get_applications(self) -> list[dict[str, Any]]:
        """Scan /Applications for .app bundles and check their signing status.

        Returns:
            List of dicts with keys: path, signed, from_app_store, has_elevated_perms
        """
        apps: list[dict[str, Any]] = []
        applications_dir = Path("/Applications")

        if not applications_dir.exists():
            return apps

        try:
            for entry in applications_dir.iterdir():
                if entry.is_dir() and entry.suffix == ".app":
                    app_path = str(entry)
                    apps.append(
                        {
                            "path": app_path,
                            "signed": self._check_codesign(app_path),
                            "from_app_store": self._check_app_store(app_path),
                            "has_elevated_perms": self._check_elevated_perms(app_path),
                        }
                    )
        except Exception:
            # Return whatever we collected so far
            pass

        return apps
