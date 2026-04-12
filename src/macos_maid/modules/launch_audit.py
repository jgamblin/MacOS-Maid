"""Launch daemon and agent audit module for MacOS Maid."""

from __future__ import annotations

from pathlib import Path

from macos_maid.modules.base import AuditResult, Finding, Module


class LaunchAuditModule(Module):
    """Module for auditing launch daemons and agents.

    Read-only audit module that flags non-Apple launch daemons and agents.
    Never removes or disables them.
    """

    name = "launch_audit"
    category = "security"
    requires_sudo = False

    LAUNCH_DIRS = [
        Path("/Library/LaunchDaemons"),
        Path("/Library/LaunchAgents"),
        Path.home() / "Library" / "LaunchAgents",
    ]

    def _is_apple_daemon(self, label: str) -> bool:
        """Check if a daemon/agent label belongs to Apple.

        Args:
            label: The daemon/agent label (typically from plist filename)

        Returns:
            True if the label starts with "com.apple."
        """
        return label.startswith("com.apple.")

    def _list_launch_items(self) -> list[dict[str, str]]:
        """Scan LAUNCH_DIRS for .plist files.

        Returns:
            List of dictionaries with 'label' (stem) and 'path' (str)
        """
        items = []
        for launch_dir in self.LAUNCH_DIRS:
            if not launch_dir.exists():
                continue

            for plist_file in launch_dir.glob("*.plist"):
                items.append(
                    {
                        "label": plist_file.stem,
                        "path": str(plist_file),
                    }
                )

        return items

    def audit(self) -> AuditResult:
        """Audit launch daemons and agents.

        Lists non-Apple items as "info" findings.
        If no non-Apple items are found, reports "pass".
        """
        launch_items = self._list_launch_items()
        findings = []

        # Filter for non-Apple items
        non_apple_items = [
            item for item in launch_items if not self._is_apple_daemon(item["label"])
        ]

        if not non_apple_items:
            findings.append(
                Finding(
                    severity="pass",
                    title="Launch Daemons and Agents",
                    detail="No non-Apple launch daemons or agents found",
                    remediation=None,
                )
            )
            return AuditResult(status="pass", findings=findings)

        # Report each non-Apple item as an info finding
        for item in non_apple_items:
            findings.append(
                Finding(
                    severity="info",
                    title="Non-Apple Launch Item",
                    detail=f"{item['label']} at {item['path']}",
                    remediation="Review and verify this launch item is expected",
                )
            )

        return AuditResult(status="info", findings=findings)
